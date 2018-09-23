/*
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <zhpe.h>

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

struct mem_wire_msg1 {
	uint32_t		rx_ring_size;
};

struct mem_wire_msg2 {
	uint64_t		key;
};

void zhpe_tx_free(struct zhpe_tx *ztx)
{
	if (!ztx)
		return;
	zhpe_mr_put(ztx->zmr);
	zhpeq_free(ztx->zq);
	free(ztx->pentries);
	free(ztx->zentries);
	free(ztx);
}

static int do_tx_setup(struct zhpe_ep_attr *ep_attr, struct zhpe_tx **ztx_out)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_tx		*ztx = NULL;
	uint32_t		qlen;
	uint32_t		i;
	size_t			req;
	struct fid_mr		*mr;

	*ztx_out = NULL;
	ztx = calloc(1, sizeof(*ztx));
	if (!ztx)
		goto done;
	qlen = roundup_power_of_two(ep_attr->ep->tx_attr.size) * 2;
	ztx->mask = qlen - 1;
	ztx->use_count = 1;

	/* Allocate memory */
	req = sizeof(*ztx->pentries) * qlen;
	ret = -posix_memalign((void **)&ztx->pentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->pentries = NULL;
		goto done;
	}
	memset(ztx->pentries, 0, req);
	/* user free list: ufree.index = 0 */
	ztx->ufree.count = qlen / 2;
	for (i = 0; i < qlen / 2  - 1; i++)
		ztx->pentries[i].pe_root.status = i + 1;
	ztx->pentries[i].pe_root.status = ZHPE_BAD_INDEX;
	/* provider free list */
	ztx->pfree.index = ++i;
	ztx->pfree.count = qlen / 2;
	for (; i < qlen - 1; i++)
		ztx->pentries[i].pe_root.status = i + 1;
	ztx->pentries[i].pe_root.status = ZHPE_BAD_INDEX;

	req = ZHPE_RING_ENTRY_LEN * qlen;
	ret = -posix_memalign((void **)&ztx->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->zentries = NULL;
		goto done;
	}

	/* Allocate queue from bridge. */
	ret = zhpeq_alloc(ep_attr->domain->zdom, qlen, qlen,
			  0, 0, 0, &ztx->zq);
	if (ret < 0)  {
		ZHPE_LOG_ERROR("zhpeq_alloc() error %d\n", ret);
		goto done;
	}
	memset(ztx->zentries, 0, req);

	/* Register zentries memory. */
	ret = zhpe_mr_reg_int_uncached(ep_attr->domain, ztx->zentries, req,
				       FI_WRITE, 0, &mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	ztx->zmr = container_of(mr, struct zhpe_mr, mr_fid);
	ret = zhpeq_lcl_key_access(ztx->zmr->kdata, ztx->zentries,
				   0, 0, &ztx->lz_zentries);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_lcl_key_access() error %d\n", ret);
		goto done;
	}

 done:
	if (ret < 0) {
		zhpe_tx_put(ztx);
		ztx = NULL;
	}
	*ztx_out = ztx;

	return ret;
}

static inline void *scoreboard_alloc(struct zhpe_rx_common *rx_cmn)
{
	const size_t		size = sizeof(*rx_cmn->scoreboard);
	const uint32_t		bits = size * CHAR_BIT;

	rx_cmn->scoreboard = calloc((rx_cmn->mask + bits) / bits, size);

	return rx_cmn->scoreboard;
}

static int zhpe_tx_handle_conn_pull(struct zhpe_pe_root *pe_root,
				    struct zhpeq_cq_entry *zq_cqe)
{
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_rx_peer_visible *peer = (void *)&zq_cqe->z.result;

	if (zq_cqe->z.status == ZHPEQ_CQ_STATUS_SUCCESS)
		atomic_store_lazy_uint32(&conn->rx_remote.shadow,
					 ntohl(peer->completed));
	else
		ZHPE_LOG_ERROR("status : %d\n",  zq_cqe->z.status);
	__sync_fetch_and_sub(&conn->rx_remote.pull_busy, 1);

	return 0;
}

static void do_rx_free(struct zhpe_conn *conn)
{
	zhpe_rkey_put(conn->rx_remote.cmn.rkey);
	conn->rx_remote.cmn.rkey = NULL;
	zhpe_mr_put(conn->rx_local.cmn.zmr);
	conn->rx_local.cmn.zmr = NULL;
	free(conn->rx_local.zentries);
	conn->rx_local.zentries = NULL;
	free(conn->rx_local.cmn.scoreboard);
	conn->rx_local.cmn.scoreboard = NULL;
	free(conn->rx_remote.cmn.scoreboard);
	conn->rx_remote.cmn.scoreboard = NULL;
}

static int do_rx_setup(struct zhpe_conn *conn, int conn_fd, int action)
{
	int			ret;
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;
	struct zhpe_ep		*ep = conn->ep_attr->ep;
	struct zhpe_rx_local	*rx_ringl = &conn->rx_local;
	struct zhpe_rx_remote	*rx_ringr = &conn->rx_remote;
	char			blob[ZHPEQ_KEY_BLOB_MAX];
	struct zhpe_msg_hdr	ohdr = { .op_type = 0 };
	struct mem_wire_msg1	mem_msg1;
	struct mem_wire_msg2	mem_msg2;
	size_t			blob_len;
	uint32_t		qlenl;
	uint32_t		qlenr;
	struct fid_mr		*mr;
	size_t			off;
	size_t			req;

	memset(rx_ringl, 0, sizeof(*rx_ringl));
	memset(rx_ringr, 0, sizeof(*rx_ringr));
	rx_ringr->pull_pe_root.handler = zhpe_tx_handle_conn_pull;
	rx_ringr->pull_pe_root.conn = conn;

	/* rx ring will be the same as the tx size. */
	qlenr = roundup_power_of_two(ep->tx_attr.size) * 2;
	mem_msg1.rx_ring_size = htonl(qlenr);
	if (likely(action != ZHPE_CONN_ACTION_SELF)) {
		ret = zhpe_send_blob(conn_fd, &mem_msg1, sizeof(mem_msg1));
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, &mem_msg1,
					   sizeof(mem_msg1));
		if (ret < 0)
			goto done;
	}
	qlenl = ntohl(mem_msg1.rx_ring_size);

	rx_ringl->cmn.mask = qlenl - 1;
	rx_ringr->cmn.mask = qlenr - 1;

	ret = -FI_ENOMEM;

	/* Allocate local rx ring memory. */
	if (!scoreboard_alloc(&rx_ringl->cmn))
		goto done;

	/* +1 for peer visible cache line. */
	req = ZHPE_RING_ENTRY_LEN * (qlenl + 1);
	ret = -posix_memalign((void **)&rx_ringl->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		rx_ringl->zentries = NULL;
		goto done;
	}
	memset(rx_ringl->zentries, 0, req);

	/* Allocate remote scoreboard. */
	if (!scoreboard_alloc(&rx_ringr->cmn))
		goto done;

	/* Register zentries memory. */
	ret = zhpe_mr_reg_int_uncached(ep_attr->domain, rx_ringl->zentries, req,
				       FI_REMOTE_READ | FI_REMOTE_WRITE,
				       ZHPEQ_MR_KEY_ZERO_OFF, &mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	rx_ringl->cmn.zmr = container_of(mr, struct zhpe_mr, mr_fid);

	/* Exchange key information. */
	blob_len = sizeof(blob);
	ret = zhpeq_zmmu_export(zhpeq_dom(conn->ztx->zq),
				rx_ringl->cmn.zmr->kdata, blob, &blob_len);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_zmmu_export() error %d\n", ret);
		goto done;
	}

	mem_msg2.key = htobe64(fi_mr_key(mr));
	if (likely(action != ZHPE_CONN_ACTION_SELF)) {
		ret = zhpe_send_blob(conn_fd, &mem_msg2, sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_send_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, &mem_msg2,
					   sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_recv_fixed_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
	}

	ret = zhpe_conn_rkey_import(conn, ohdr, be64toh(mem_msg2.key),
				    blob, blob_len, &rx_ringr->cmn.rkey);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_zmmu_alloc() error %d\n", ret);
		goto done;
	}
	ret = zhpeq_rem_key_access(rx_ringr->cmn.rkey->kdata, 0, 0, 0,
				   &rx_ringr->rz_zentries);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_rem_key_access() error %d\n", ret);
		goto done;
	}
	/* Set up pushed locations. */
	off = ZHPE_RING_ENTRY_LEN * qlenl;
	rx_ringl->peer_visible = (void *)(rx_ringl->zentries + off);
	off = ZHPE_RING_ENTRY_LEN * qlenr;
	rx_ringr->rz_peer_visible = rx_ringr->rz_zentries + off;
 done:
	if (ret < 0)
		do_rx_free(conn);

	return ret;
}

int zhpe_compare_zkeys(void *vk1, void *vk2)
{
	struct zhpe_key		*k1 = (void *)vk1;
	struct zhpe_key		*k2 = (void *)vk2;

	if (k1->key < k2->key)
		return -1;
	else if (k1->key > k2->key)
		return 1;

	return memcmp(&k1->internal, &k2->internal, sizeof(k1->internal));
}

int zhpe_conn_z_setup(struct zhpe_conn *conn, int conn_fd, int action)
{
	int			ret = 0;
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;

	mutex_acquire(&ep_attr->cmap.mutex);
	if (!ep_attr->ztx)
		ret = do_tx_setup(ep_attr, &ep_attr->ztx);
	if (ret >= 0) {
		conn->ztx = ep_attr->ztx;
		(void)__sync_fetch_and_add(&ep_attr->ztx->use_count, 1);
	}
	mutex_release(&ep_attr->cmap.mutex);
	if (ret < 0)
		goto done;
	/* Init remote mr tree. */
	dlist_init(&conn->rkey_deferred_list);
	conn->rkey_seq = 0;
	conn->kexp_seq = 0;
	ret = -FI_ENOMEM;
	conn->rkey_tree = rbtNew(zhpe_compare_zkeys);
	if (!conn->rkey_tree)
		goto done;
	conn->kexp_tree = rbtNew(zhpe_compare_zkeys);
	if (!conn->kexp_tree)
		goto done;
	fastlock_init(&conn->mr_lock);
	mutex_init(&conn->mutex, NULL);
	cond_init(&conn->cond, NULL);
	/* Get address index. */
	ret = zhpeq_backend_open(conn->ztx->zq,
				 (action != ZHPE_CONN_ACTION_SELF ?
				  conn_fd : -1));
	if (ret < 0) {
		ZHPE_LOG_ERROR("%s,%u:zhpeq_backend_open() error %d\n",
			       __FUNCTION__, __LINE__, ret);
		goto done;
	}
	conn->zq_index = ret;
	/* FIXME: ENQA */
	conn->hdr_off = 0;

	/* Exchange information and setup rx rings */
	ret = do_rx_setup(conn, conn_fd, action);
	if (ret < 0)
		goto done;
	/* FIXME: Rethink for multiple contexts. */
	conn->tx_ctx = ep_attr->tx_ctx;
	conn->rx_ctx = ep_attr->rx_ctx;
	mutex_acquire(&ep_attr->cmap.mutex);
	conn->state = ZHPE_CONN_STATE_READY;
	cond_broadcast(&ep_attr->cmap.cond);
	mutex_release(&ep_attr->cmap.mutex);
	ret = 0;

 done:

	return ret;
}

void zhpe_conn_z_free(struct zhpe_conn *conn)
{
	void			*keyp;
	RbtIterator		*rbt;
	struct zhpe_rkey_data	*rkey;
	struct zhpe_kexp_data	*kexp;

	if (conn->rkey_tree) {
		/* Is lock initialized? */
		if (conn->kexp_tree) {
			fastlock_acquire(&conn->mr_lock);
			while (!dlist_empty(&conn->rkey_deferred_list)) {
				dlist_pop_front(&conn->rkey_deferred_list,
						struct zhpe_rkey_data, rkey,
						lentry);
				free(rkey);
			}
			while ((rbt = rbtBegin(conn->rkey_tree)))  {
				rbtKeyValue(conn->rkey_tree, rbt, &keyp,
					    (void **)&rkey);
				rbtErase(conn->rkey_tree, rbt);
				fastlock_release(&conn->mr_lock);
				zhpe_rkey_put(rkey);
			}
			while ((rbt = rbtBegin(conn->kexp_tree)))  {
				rbtKeyValue(conn->kexp_tree, rbt, &keyp,
					    (void **)&kexp);
				rbtErase(conn->kexp_tree, rbt);
				fastlock_release(&conn->mr_lock);
				/* FIXME: Think about driver disconnect. */
				zhpe_kexp_put(kexp);
			}
			fastlock_release(&conn->mr_lock);
			fastlock_destroy(&conn->mr_lock);
			rbtDelete(conn->kexp_tree);
		}
		rbtDelete(conn->rkey_tree);
		conn->rkey_tree = NULL;
	}
	do_rx_free(conn);
	if (conn->zq_index != FI_ADDR_NOTAVAIL)
		zhpeq_backend_close(conn->ztx->zq, conn->zq_index);
	zhpe_tx_put(conn->ztx);
}

int __zhpe_conn_pull(struct zhpe_conn *conn)
{
	int			ret = 0;
	struct zhpe_rx_remote	*rx_ringr = &conn->rx_remote;
	uint32_t		zindex;

	ret = zhpeq_reserve(conn->ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;
	ret = zhpeq_geti(conn->ztx->zq, zindex, false,
			 sizeof(struct zhpe_rx_peer_visible),
			 rx_ringr->rz_peer_visible,
			 &rx_ringr->pull_pe_root);
	if (ret < 0)
		goto done;
	ret = zhpeq_commit(conn->ztx->zq, zindex, 1);

 done:
	if (ret < 0)
		ZHPE_LOG_ERROR("pull failed:error %d\n", ret);

	return ret;
}

int zhpe_tx_free_res(struct zhpe_conn *conn, int64_t tindex,
		     int64_t zindex, int64_t rindex, uint8_t pe_flags)
{
	int			ret = 0;
	struct zhpe_tx		*ztx = conn->ztx;
	struct zhpe_msg_hdr	zhdr;
	uint64_t		rzaddr;

	if (!conn)
		goto done;

	/* We assume ordered allocation: zq then rx ring; tx_buf can
	 * be freed without problems. index < 0 indicates item was
	 * not allocated.
	 */
	if (tindex >= 0)
		zhpe_tx_release(ztx, tindex, pe_flags);

	if (zindex < 0)
		goto done;

	/* If no rx_ring space, send NOP to bridge. */
	if (rindex < 0) {
		ret = zhpeq_nop(ztx->zq, zindex, false,
				ZHPE_CONTEXT_IGNORE_PTR);
		if (ret < 0)
			goto done;
		goto commit;
	}

	/* Send NOP to receive ring. */
	memset(&zhdr, 0, sizeof(zhdr));
	zhdr.op_type = ZHPE_OP_NOP;
	rzaddr = conn->rx_remote.rz_zentries + zhpe_ring_off(conn, rindex);
	ret = zhpeq_puti(ztx->zq, zindex, false, &zhdr, sizeof(zhdr), rzaddr,
			 ZHPE_CONTEXT_IGNORE_PTR);
	if (ret < 0)
		goto done;

commit:
	ret = zhpeq_commit(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
 done:

	return ret;
}

#define	CHUNK_SIZE_OFF		offsetof(struct zhpe_slab_free_entry, size)
#define	CHUNK_DATA_OFF		offsetof(struct zhpe_slab_free_entry, lentry)
#define CHUNK_SIZE_SIZE		(CHUNK_DATA_OFF - CHUNK_SIZE_OFF)
#define CHUNK_SIZE_MIN \
	(sizeof(struct zhpe_slab_free_entry) - CHUNK_DATA_OFF)
#define CHUNK_SIZE_PINUSE	((uintptr_t)1)
#define CHUNK_SIZE_MASK		(~(sizeof(uintptr_t) - 1))

static inline void *ptr_to_chunk(void *ptr)
{
	return ((char *)ptr - CHUNK_DATA_OFF);
}

static inline size_t chunk_size(size_t csize)
{
	return (csize & CHUNK_SIZE_MASK) + CHUNK_SIZE_SIZE;
}

static inline void *_next_chunk(struct zhpe_slab_free_entry *chunk)
{
	return ((char *)chunk + chunk_size(chunk->size));
}

static inline void *_prev_chunk(struct zhpe_slab_free_entry *chunk)
{
	return ((char *)chunk - chunk_size(chunk->prev_size));
}

static inline void *prev_chunk(struct zhpe_slab_free_entry *chunk)
{
	if (chunk->size & CHUNK_SIZE_PINUSE)
		return NULL;
	return _prev_chunk(chunk);
}

#if 0

#define CHUNK_SIZE_SEEN		((uintptr_t)4)

static uint64_t			slab_check_path;
static void			*slab_check_ptr[4];
struct zhpe_slab_free_entry	slab_check_chunk[4];

static void slab_check_save_path(uint shift)
{
	if (!shift)
		slab_check_path = 0;
	else
		slab_check_path |= (1 << shift);
}

static void slab_check_save(struct zhpe_slab_free_entry *chunk, uint idx)
{
	if (idx >= ARRAY_SIZE(slab_check_ptr) ||
	    idx >= ARRAY_SIZE(slab_check_chunk))
		abort();
	if (!idx) {
		memset(slab_check_ptr, 0, sizeof(slab_check_ptr));
		memset(slab_check_chunk, 0, sizeof(slab_check_chunk));
	} else if (idx == 3) {
		/* nextnext */
		if (!(slab_check_chunk[2].size & CHUNK_SIZE_MASK))
			return;
	}
	slab_check_ptr[idx] = chunk;
	if (chunk)
		slab_check_chunk[idx] = *chunk;
}

static void slab_check(struct zhpe_slab *slab)
{
	struct zhpe_slab_free_entry *prev;
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;
	struct zhpe_slab_free_entry *free;
	size_t			free_count;

	/* Clear seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				free, lentry)
		free->size &= ~CHUNK_SIZE_SEEN;

	free_count = 0;
	prev = NULL;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		/* All free chunks should have had their SEEN bit cleared. */
		next = _next_chunk(chunk);
		if (!(next->size & CHUNK_SIZE_PINUSE)) {
			if (chunk->size & CHUNK_SIZE_SEEN)
				abort();
			chunk->size |= CHUNK_SIZE_SEEN;
			free_count++;
			if (_prev_chunk(next) != chunk)
				abort();
		}
		/* Current chunk and previous agree? */
		if (prev) {
			if (!(chunk->size & CHUNK_SIZE_PINUSE) &&
			    _prev_chunk(chunk) != prev)
				abort();
		}
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK)) {
			/* End marker in write place? */
			if (next != (void *)((char *)slab->mem + slab->size -
					     CHUNK_DATA_OFF))
				abort();
			break;
		}
		/* Shuffle. */
		prev = chunk;
		chunk = next;
	}

	/* Check seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				free, lentry) {
		if (!free_count)
			abort();
		if (!(free->size & CHUNK_SIZE_SEEN))
			abort();
		free->size &= ~CHUNK_SIZE_SEEN;
	}
}

static void slab_check_freed(struct zhpe_slab *slab,
			     struct zhpe_slab_free_entry *freed)
{
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;

	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		if (chunk == freed)
			break;
		next = _next_chunk(chunk);
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK))
			abort();
		chunk = next;
	}
}

#else

static inline void slab_check_save_path(uint shift)
{
}

static inline void slab_check_save(struct zhpe_slab_free_entry *chunk,
				   uint idx)
{
}

static inline void slab_check(struct zhpe_slab *slab)
{
}

static void slab_check_freed(struct zhpe_slab *slab,
			     struct zhpe_slab_free_entry *freed)
{
}

#endif

int zhpe_slab_init(struct zhpe_slab *slab, size_t size,
		   struct zhpe_domain *domain)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_slab_free_entry *chunk;
	struct fid_mr		*mr;

	/* Align to pointer size boundary; assumed to be power of 2
	 * and greater than 2; so bit 0 will always be zero.
	 */
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	slab->size = size;
	dlist_init(&slab->free_list);
	slab->mem = malloc(size);
	if (!slab->mem)
		goto done;
	fastlock_init(&slab->lock);
	ret = 0;
	if (size < CHUNK_SIZE_MIN + 2 * CHUNK_SIZE_SIZE)
		goto done;
	size -= 2 * CHUNK_SIZE_SIZE;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	chunk->size = (size | CHUNK_SIZE_PINUSE);
	dlist_insert_tail(&chunk->lentry, &slab->free_list);
	chunk = _next_chunk(chunk);
	chunk->size = 0;

	ret = zhpe_mr_reg_int_uncached(domain, slab->mem, slab->size,
				       FI_READ | FI_WRITE, 0, &mr);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpe_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	slab->zmr = container_of(mr, struct zhpe_mr, mr_fid);
 done:
	return ret;
}

void zhpe_slab_destroy(struct zhpe_slab *slab)
{
	if (slab->mem) {
		slab_check(slab);
		zhpe_mr_put(slab->zmr);
		slab->zmr = NULL;
		free(slab->mem);
		slab->mem = NULL;
		fastlock_destroy(&slab->lock);
	}
}

int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size,
		    struct zhpe_iov *iov)
{
	int			ret = -ENOMEM;
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;

	iov->iov_len = size;
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	if (size < CHUNK_SIZE_MIN)
		size = CHUNK_SIZE_MIN;
	/* Just first fit because it is fast and entries are transient.
	 * Every free entry should have the PINUSE bit set because,
	 * otherwise, it would be merged with another block.
	 */
	fastlock_acquire(&slab->lock);
	dlist_foreach_container(&slab->free_list, struct zhpe_slab_free_entry,
				chunk, lentry) {
		if (chunk->size >= size)
			goto found;
	}
	fastlock_release(&slab->lock);
	goto done;
 found:
	/* Do we have space to divide the chunk?
	 * We need space for the pointers (CHUNK_SIZE_MIN) +
	 * space for prev_size (CHUNK_SIZE_OFF).
	 */
	if (chunk->size - size <= CHUNK_SIZE_MIN + CHUNK_SIZE_SIZE + 1) {
		/* No. */
		dlist_remove(&chunk->lentry);
		iov->iov_base = ((char *)chunk + CHUNK_DATA_OFF);
	} else {
		chunk->size -= size + CHUNK_SIZE_SIZE;
		next = _next_chunk(chunk);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size = size;
		iov->iov_base = ((char *)next + CHUNK_DATA_OFF);
		chunk = next;
	}
	next = _next_chunk(chunk);
	next->size |= CHUNK_SIZE_PINUSE;
	slab_check(slab);
	fastlock_release(&slab->lock);
	iov->iov_desc = slab->zmr;
	(void)zhpeq_lcl_key_access(slab->zmr->kdata, iov->iov_base, size,
				   0, &iov->iov_zaddr);
	ret = 0;
 done:
	return ret;
}

void zhpe_slab_free(struct zhpe_slab *slab, void *ptr)
{
	struct zhpe_slab_free_entry *chunk;
	struct zhpe_slab_free_entry *next;
	struct zhpe_slab_free_entry *nextnext;
	struct zhpe_slab_free_entry *prev;

	if (!ptr)
		return;
	chunk = ptr_to_chunk(ptr);
	fastlock_acquire(&slab->lock);
	slab_check(slab);
	slab_check_freed(slab, chunk);
	slab_check_save_path(0);
	slab_check_save(chunk, 0);
	prev = prev_chunk(chunk);
	slab_check_save(prev, 1);
	/* Combine with prev or create new free entry? */
	if (prev) {
		slab_check_save_path(1);
		prev->size += chunk_size(chunk->size);
		chunk = prev;
	} else {
		slab_check_save_path(2);
		dlist_insert_head(&chunk->lentry, &slab->free_list);
	}
	next = _next_chunk(chunk);
	slab_check_save(next, 2);
	nextnext = _next_chunk(next);
	slab_check_save(nextnext, 3);
	/* next is end of slab or in use? */
	if (!(next->size & CHUNK_SIZE_MASK) ||
	    (nextnext->size & CHUNK_SIZE_PINUSE)) {
		/* Yes: Update prev flag and size. */
		slab_check_save_path(3);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size &= ~CHUNK_SIZE_PINUSE;
		goto done;
	}
	/* No: combine chunk with next. */
	slab_check_save_path(3);
	chunk->size += chunk_size(next->size);
	nextnext->prev_size = (chunk->size & CHUNK_SIZE_MASK);
	dlist_remove(&next->lentry);
 done:
	fastlock_release(&slab->lock);
}

int zhpe_iov_op_get(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
	return zhpeq_get(zq, zindex, fence, lza, len, rza, context);
}

int zhpe_iov_op_get_imm(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len, uint64_t rza,
			  void *context)
{
	if (len > ZHPEQ_IMM_MAX)
		abort();

	return zhpeq_geti(zq, zindex, fence, len, rza, context);
}

int zhpe_iov_op_put(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
	int			ret;

	if (len <= ZHPEQ_IMM_MAX)
		ret = zhpeq_puti(zq, zindex, fence, lptr, len, rza, context);
	else
		ret = zhpeq_put(zq, zindex, fence, lza, len, rza, context);

	return ret;
}

int zhpe_iov_op(struct zhpe_pe_root *pe_root,
		struct zhpe_iov_state *lstate,
		struct zhpe_iov_state *rstate,
		size_t max_bytes, uint8_t max_ops,
		int (*op)(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len,
			  uint64_t rza, void *context),
		size_t *rem)
{
	int			ret = 0;
	int64_t			rc = 0;
	struct zhpeq		*zq = pe_root->conn->ztx->zq;
	struct zhpe_iov_state	save_lstate = *lstate;
	struct zhpe_iov_state	save_rstate = *rstate;
	uint32_t		zindex;
	size_t			ops;
	size_t			bytes;
	size_t			len;
	size_t			llen;
	size_t			rlen;
	uint64_t		lza;
	uint64_t		rza;
	void			*lptr;

	/* Note: caller should initialize pe_root->completions zero or some
	 * other appropirate value and set the ZHPE_PE_PROV flag, if
	 * required.
	 *
	 * We need to determine the number of ops before reserve them.
	 */
	ops = 0;
	bytes = 0;
	while (!zhpe_iov_state_empty(lstate) &&
	       !zhpe_iov_state_empty(rstate) &&
	       (!max_ops || ops < max_ops) &&
	       (!max_bytes || bytes < max_bytes)) {

		llen = zhpe_ziov_state_len(lstate);
		rlen = zhpe_ziov_state_len(rstate);
		len = llen;
		if (len > rlen)
			len = rlen;
		ops++;
		bytes += len;
		zhpe_ziov_state_adv(lstate, len);
		zhpe_ziov_state_adv(rstate, len);
	}

	max_ops = ops;
	if (!ops)
		goto done;
	if (!max_bytes || bytes < max_bytes)
		max_bytes = bytes;
	for (;;) {
		rc = zhpeq_reserve(zq, max_ops);
		if (rc >= 0)
			break;
		if (max_ops == 1 || rc != -FI_EAGAIN)
			goto done;
		max_ops = 1;
	}
	zindex = rc;

	pe_root->completions += max_ops;

	*lstate = save_lstate;
	*rstate = save_rstate;
	for (ops = 0; ops < max_ops; ops++) {
		llen = zhpe_ziov_state_len(lstate);
		lptr = zhpe_iov_state_ptr(lstate, ZHPE_IOV_ZIOV);
		lza = zhpe_ziov_state_zaddr(lstate);
		rlen = zhpe_ziov_state_len(rstate);
		rza = zhpe_ziov_state_zaddr(rstate);

		len = llen;
		if (len > rlen)
			len = rlen;
		if (len > max_bytes)
			len = max_bytes;
		max_bytes -= len;
		*rem -= len;
		rc = op(zq, zindex + ops, false, lptr, lza, len, rza, pe_root);
		if (rc < 0)
			break;
		zhpe_ziov_state_adv(lstate, len);
		zhpe_ziov_state_adv(rstate, len);
	}
	if (rc < 0) {
		ret = rc;
		for (; ops < max_ops; ops++)
			zhpeq_nop(zq, zindex + ops, false,
				  ZHPE_CONTEXT_IGNORE_PTR);
	}
	rc = zhpeq_commit(zq, zindex, max_ops);
 done:
	if (rc) {
		if (!ret)
			ret = rc;
	} else
		ret = ops;

	return ret;
}

int zhpe_put_imm_to_iov(struct zhpe_pe_root *pe_root, void *lbuf,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem)
{
	struct zhpe_iov		liov = {
		.iov_base = lbuf,
		.iov_len = llen,
	};
	struct zhpe_iov_state	lstate = { .viov = &liov, .cnt = 1 };

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_iov_op_put, rem);
}


int zhpe_iov_to_get_imm(struct zhpe_pe_root *pe_root,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem)
{
	struct zhpe_iov		liov = {
		.iov_len = llen,
	};
	struct zhpe_iov_state	lstate = { .viov = &liov, .cnt = 1 };

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_iov_op_get_imm, rem);
}

void zhpe_send_status(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
		      int32_t status, uint64_t rem)
{
	struct zhpe_msg_status	msg_status;

	msg_status.rem = htobe64(rem);
	msg_status.status = htonl(status);
	ohdr.op_type = ZHPE_OP_STATUS;

	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &msg_status, sizeof(msg_status));
}

void zhpe_send_key_revoke(struct zhpe_conn *conn,
			  const struct zhpe_key *zkey)
{
	struct zhpe_msg_hdr	ohdr = {
		.op_type	= ZHPE_OP_KEY_REVOKE,
	};
	struct zhpe_msg_key_request key_req;

	ohdr.seq = htons(__sync_fetch_and_add(&conn->kexp_seq, 1));
	key_req.zkeys[0].key = htobe64(zkey->key);
	key_req.zkeys[0].internal = zkey->internal;

	zhpe_prov_op(conn, ohdr, ZHPE_PE_RETRY,
		     &key_req, sizeof(key_req.zkeys[0]));
}

static inline struct zhpe_kexp_data *conn_kexp_get(struct zhpe_conn *conn,
						   const struct zhpe_key *zkey)
{
	struct zhpe_kexp_data	*ret;
	RbtIterator		*rbt;
	void			*keyp;

	rbt = rbtFind(conn->kexp_tree, (void *)zkey);
	if (!rbt)
		return NULL;
	rbtKeyValue(conn->kexp_tree, rbt, &keyp, (void **)&ret);
	__sync_fetch_and_add(&ret->use_count, 1);

	return ret;
}

static inline struct zhpe_rkey_data *conn_rkey_get(struct zhpe_conn *conn,
						   const struct zhpe_key *zkey)
{
	struct zhpe_rkey_data	*ret;
	RbtIterator		*rbt;
	void			*keyp;

	rbt = rbtFind(conn->rkey_tree, (void *)zkey);
	if (!rbt)
		return NULL;
	rbtKeyValue(conn->rkey_tree, rbt, &keyp, (void **)&ret);
	__sync_fetch_and_add(&ret->use_count, 1);

	return ret;
}

struct zhpe_rkey_data *zhpe_conn_rkey_get(struct zhpe_conn *conn,
					  const struct zhpe_key *zkey)
{
	struct zhpe_rkey_data	*ret;

	fastlock_acquire(&conn->mr_lock);
	ret = conn_rkey_get(conn, zkey);
	fastlock_release(&conn->mr_lock);

	return ret;
}

int zhpe_conn_key_export(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			 struct zhpe_mr *zmr)
{
	int			ret;
	size_t			blob_len;
	struct zhpe_kexp_data	*new = NULL;
	uint8_t			pe_flags = 0;
	struct zhpe_domain	*domain = conn->ep_attr->domain;
	struct zhpe_kexp_data	*kexp;
	struct zhpe_msg_key_data msg_data;

	fastlock_acquire(&conn->mr_lock);
	for (;;) {
		kexp = conn_kexp_get(conn, &zmr->zkey);
		if (kexp) {
			if (new) {
				fastlock_release(&domain->lock);
				free(new);
			}
			break;
		}
		if  (!new) {
			fastlock_release(&conn->mr_lock);
			new = malloc(sizeof(*new));
			if (!new) {
				ret = -FI_ENOMEM;
				goto done;
			}
			dlist_init(&new->lentry);
			new->conn = conn;
			new->zkey = zmr->zkey;
			new->use_count = 3;
			fastlock_acquire(&domain->lock);
			if (zmr->flags & ZHPE_MR_FLAGS_FREEING) {
				fastlock_release(&domain->lock);
				free(new);
				ret = -FI_ENOKEY;
				goto done;
			}
			fastlock_acquire(&conn->mr_lock);
			continue;
		}
		rbtInsert(conn->kexp_tree, &new->zkey, new);
		dlist_insert_tail(&new->lentry, &zmr->kexp_list);
		kexp = new;
		fastlock_release(&domain->lock);
		break;
	}
	fastlock_release(&conn->mr_lock);

	msg_data.key = htobe64(zmr->mr_fid.key);
	blob_len = sizeof(msg_data.blob);
	ret = zhpeq_zmmu_export(zhpeq_dom(conn->ztx->zq),
				zmr->kdata, msg_data.blob, &blob_len);
	if (ret < 0)
		goto done;

	if (ohdr.op_type == ZHPE_OP_KEY_REQUEST) {
		ohdr.op_type = ZHPE_OP_KEY_RESPONSE;
		pe_flags |= ZHPE_PE_RETRY;
	} else
		ohdr.op_type = ZHPE_OP_KEY_EXPORT;
	ohdr.seq = htons(__sync_fetch_and_add(&conn->kexp_seq, 1));
	ret = zhpe_prov_op(conn, ohdr, pe_flags, &msg_data,
			   offsetof(struct zhpe_msg_key_data, blob) + blob_len);
 done:
	zhpe_kexp_put(kexp);

	return ret;
}

static bool process_rkey_revoke(struct zhpe_conn *conn,
			       const struct zhpe_key *zkey)
{
	bool			ret = false;
	struct zhpe_rkey_data	*old = NULL;
	RbtIterator		*rbt;
	void			*keyp;

	/* conn->mr_lock must be held; return true if unlocked */
	rbt = rbtFind(conn->rkey_tree, &zkey);
	if (rbt) {
		rbtKeyValue(conn->rkey_tree, rbt, &keyp, (void **)&old);
		rbtErase(conn->rkey_tree, rbt);
	}
	if (old) {
		fastlock_release(&conn->mr_lock);
		zhpe_rkey_put(old);
		ret = true;
	}

	return ret;
}

static bool process_rkey_import(struct zhpe_conn *conn,
				struct zhpe_rkey_data *new)
{
	bool			ret = false;
	struct zhpe_rkey_data	*old = NULL;
	RbtIterator		*rbt;
	void			*keyp;

	/* conn->mr_lock must be held; return true if unlocked */
	rbt = rbtFind(conn->rkey_tree, &new->zkey);
	if (rbt) {
		rbtKeyValue(conn->rkey_tree, rbt, &keyp, (void **)&old);
		rbtErase(conn->rkey_tree, rbt);
	}
	rbtInsert(conn->rkey_tree, &new->zkey, new);
	if (old) {
		fastlock_release(&conn->mr_lock);
		zhpe_rkey_put(old);
		ret = true;
	}
	if (new->ohdr.op_type == ZHPE_OP_KEY_RESPONSE) {
		if (!ret) {
			fastlock_release(&conn->mr_lock);
			ret = true;
		}
		zhpe_pe_complete_key_response(conn, new->ohdr, 0);
	}

	return ret;
}

static void process_rkey_deferred(struct zhpe_conn *conn, bool locked)
{
	struct zhpe_rkey_data	*new;
	struct dlist_entry      *dlist;
	bool			unlocked;

	if (!locked)
		fastlock_acquire(&conn->mr_lock);
	while (!dlist_empty(&conn->rkey_deferred_list)) {
		dlist = conn->rkey_deferred_list.next;
		new = container_of(dlist, struct zhpe_rkey_data, lentry);
		if (new->ohdr.seq != conn->rkey_seq)
			break;
		conn->rkey_seq++;
		dlist_remove(dlist);

		switch (new->ohdr.op_type) {

		case ZHPE_OP_KEY_REVOKE:
			unlocked = process_rkey_revoke(conn, &new->zkey);
			free(new);
			break;

		default:
			unlocked = process_rkey_import(conn, new);
			break;
		}
		if (unlocked)
			fastlock_acquire(&conn->mr_lock);
	}
	fastlock_release(&conn->mr_lock);
}

static void insert_rkey_deferred(struct zhpe_conn *conn,
				 struct zhpe_rkey_data *new)
{
	struct dlist_entry      *dlist;
	struct zhpe_rkey_data	*cur;

	/* conn->mr_lock must be held. */
	dlist_foreach(&conn->rkey_deferred_list, dlist) {
		cur = container_of(dlist, struct zhpe_rkey_data,  lentry);
		if (cur->ohdr.seq > new->ohdr.seq) {
			dlist_insert_before(&new->lentry, &cur->lentry);
			return;
		}
	}
	dlist_insert_tail(&new->lentry, &conn->rkey_deferred_list);
}

int zhpe_conn_rkey_import(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  uint64_t key, const void *blob, size_t blob_len,
			  struct zhpe_rkey_data **rkey_out)
{
	int			ret;
	struct zhpe_rkey_data	*new = NULL;
	struct zhpeq_key_data	*kdata = NULL;

	ret = zhpeq_zmmu_import(zhpeq_dom(conn->ztx->zq), conn->zq_index,
				blob, blob_len, false, &kdata);
	if (ret < 0)
		goto done;

	ohdr.seq = ntohs(ohdr.seq);
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	__sync_fetch_and_add(&conn->ztx->use_count, 1);
	new->ztx = conn->ztx;
	new->zkey.key = key;
	new->zkey.internal = !!(kdata->z.access & ZHPE_MR_KEY_INT);
	new->kdata = kdata;
	new->ohdr = ohdr;
	new->use_count = 1;
	if (rkey_out) {
		new->use_count++;
		*rkey_out = new;
	}

	fastlock_acquire(&conn->mr_lock);
	if (ohdr.seq != conn->rkey_seq && ohdr.op_type != ZHPE_OP_NONE) {
		insert_rkey_deferred(conn, new);
		fastlock_release(&conn->mr_lock);
		goto done;
	}
	if (ohdr.op_type != ZHPE_OP_NONE)
		conn->rkey_seq++;
	process_rkey_deferred(conn, !process_rkey_import(conn, new));
	/* conn->mr_lock was dropped. */
	ret = 0;

 done:
	if (ret < 0) {
		/* We're probably dead, but try. */
		if (rkey_out)
			*rkey_out = NULL;
		if (ohdr.op_type != ZHPE_OP_NONE) {
			if (ohdr.op_type == ZHPE_OP_KEY_RESPONSE)
				zhpe_pe_complete_key_response(conn, ohdr, ret);
			fastlock_acquire(&conn->mr_lock);
			if (ohdr.seq == conn->rkey_seq) {
				conn->rkey_seq++;
				process_rkey_deferred(conn, true);
			} else
				fastlock_release(&conn->mr_lock);
		}
	}

	return ret;
}

int zhpe_conn_rkey_revoke(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  const struct zhpe_key *zkey)
{
	int			ret = 0;
	struct zhpe_rkey_data	*new = NULL;

	ohdr.seq = ntohs(ohdr.seq);
	fastlock_acquire(&conn->mr_lock);
	if (ohdr.seq == conn->rkey_seq) {
		conn->rkey_seq++;
		if (process_rkey_revoke(conn, zkey))
			ret = -FI_ENOKEY;
		process_rkey_deferred(conn, !ret);
		/* conn->mr_lock was dropped. */
		goto done;
	}

	/* Deferred processing. */
	fastlock_release(&conn->mr_lock);
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	new->zkey = *zkey;
	new->ohdr = ohdr;
	fastlock_acquire(&conn->mr_lock);
	insert_rkey_deferred(conn, new);
	process_rkey_deferred(conn, true);
	/* conn->mr_lock was dropped. */

 done:
	return ret;
}

static int check_read(size_t req, ssize_t res)
{
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("read(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_LOG_ERROR("read(): read %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

static int check_write(size_t req, ssize_t res)
{
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("write(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_LOG_ERROR("write(): wrote %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

int zhpe_send_blob(int sock_fd, const void *blob, size_t blob_len)
{
	int			ret = -FI_EINVAL;
	uint32_t		wlen = blob_len;
	size_t			req;
	ssize_t			res;

	if (!blob) {
		blob_len = 0;
		wlen = UINT32_MAX;
	} else if (blob_len >= UINT32_MAX)
		goto done;
	wlen = htonl(wlen);
	req = sizeof(wlen);
	res = ofi_write_socket(sock_fd, &wlen, req);
	ret = check_write(req, res);
	if (ret < 0)
		goto done;
	if (!blob_len)
		goto done;
	req = blob_len;
	res = ofi_write_socket(sock_fd, blob, req);
	ret = check_write(req, res);
 done:

	return ret;
}

int zhpe_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len)
{
	int			ret;
	uint32_t		wlen;
	size_t			req;
	ssize_t			res;

	req = sizeof(wlen);
	res = ofi_read_socket(sock_fd, &wlen, req);
	ret = check_read(req, res);
	if (ret < 0)
		goto done;
	req = ntohl(wlen);
	if (req != blob_len) {
		ZHPE_LOG_ERROR("Expected %Lu bytes, saw %Lu\n",
			       (ullong)blob_len, (ullong)res);
		ret = -EINVAL;
		goto done;
	}
	res = ofi_read_socket(sock_fd, blob, req);
	ret = check_read(req, res);
 done:

	return ret;
}

#if ENABLE_DEBUG

static int zmr_print(void *keyp, void *datap)
{
	struct zhpe_mr		*zmr = datap;

	printf("zmr  %p key 0x%Lx/%d use_count %d\n",
	       zmr, (ullong)zmr->zkey.key, zmr->zkey.internal, zmr->use_count);

	return 0;
}

static int rkey_print(void *keyp, void *datap)
{
	struct zhpe_rkey_data	*rkey = datap;

	printf("rkey %p key 0x%Lx/%d use_count %d\n",
	       rkey, (ullong)rkey->zkey.key, rkey->zkey.internal,
	       rkey->use_count);

	return 0;
}

static int kexp_print(void *keyp, void *datap)
{
	struct zhpe_kexp_data	*kexp = datap;

	printf("kexp %p key 0x%Lx/%d use_count %d\n",
	       kexp, (ullong)kexp->zkey.key, kexp->zkey.internal,
	       kexp->use_count);

	return 0;
}

static int tree_work(RbtHandle *tree, int (*work)(void *keyp, void *data))
{
	int			ret = 0;
	RbtIterator		*rbt;
	void			*keyp;
	void			*datap;

	rbt = rbtBegin(tree);
	if (!rbt)
		return 0;
	do {
		rbtKeyValue(tree, rbt, &keyp, &datap);
		ret = work(keyp, datap);
		if (ret)
			break;
	} while ((rbt = rbtNext(tree, rbt)));

	return ret;
}

void zhpe_zmr_dump(struct zhpe_domain *domain)
{
	tree_work(domain->mr_tree, zmr_print);
}

void zhpe_rkey_dump(struct zhpe_conn *conn)
{
	tree_work(conn->rkey_tree, rkey_print);
}

void zhpe_kexp_dump(struct zhpe_conn *conn)
{
	tree_work(conn->kexp_tree, kexp_print);
}

int gdb_hook_noabort;

void gdb_hook(void)
{
	if (!gdb_hook_noabort)
		abort();
}

#endif
