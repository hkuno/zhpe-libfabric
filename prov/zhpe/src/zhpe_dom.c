/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_DOMAIN, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_DOMAIN, __VA_ARGS__)

const struct fi_domain_attr zhpe_domain_attr = {
	.name = NULL,
	.threading		= FI_THREAD_COMPLETION,
	.control_progress	= FI_PROGRESS_MANUAL,
	.data_progress		= FI_PROGRESS_MANUAL,
	.resource_mgmt		= FI_RM_ENABLED,
	.mr_mode		= FI_MR_ALLOCATED,
	.mr_key_size		= ZHPE_KEY_SIZE,
	.cq_data_size		= ZHPE_CQ_DATA_SIZE,
	.cq_cnt			= ZHPE_EP_MAX_CQ_CNT,
	.ep_cnt			= ZHPE_EP_MAX_EP_CNT,
	.tx_ctx_cnt		= ZHPE_EP_MAX_TX_CNT,
	.rx_ctx_cnt		= ZHPE_EP_MAX_RX_CNT,
	.max_ep_tx_ctx		= ZHPE_EP_MAX_TX_CNT,
	.max_ep_rx_ctx		= ZHPE_EP_MAX_RX_CNT,
	.max_ep_stx_ctx		= 0,
	.max_ep_srx_ctx		= 0,
	.cntr_cnt		= ZHPE_EP_MAX_CNTR_CNT,
	.mr_iov_limit		= ZHPE_EP_MAX_IOV_LIMIT,
	.max_err_data		= ZHPE_MAX_ERR_CQ_EQ_DATA_SZ,
	.mr_cnt			= ZHPE_DOMAIN_MR_CNT,
	.caps			= ZHPE_DOMAIN_CAP,
	.mode			= ZHPE_DOMAIN_MODE,
};

int zhpe_verify_domain_attr(uint32_t api_version, const struct fi_info *info)
{
	const struct fi_domain_attr *attr = info->domain_attr;
	int			rc;

	if (!attr)
		return 0;

	switch (attr->threading) {
	case FI_THREAD_UNSPEC:
	case FI_THREAD_SAFE:
	case FI_THREAD_FID:
	case FI_THREAD_DOMAIN:
	case FI_THREAD_COMPLETION:
	case FI_THREAD_ENDPOINT:
		break;
	default:
		ZHPE_LOG_DBG("Invalid threading model!\n");
		return -FI_ENODATA;
	}

	switch (attr->control_progress) {
	case FI_PROGRESS_UNSPEC:
	case FI_PROGRESS_AUTO:
	case FI_PROGRESS_MANUAL:
		break;

	default:
		ZHPE_LOG_DBG("Control progress mode not supported!\n");
		return -FI_ENODATA;
	}

	switch (attr->data_progress) {
	case FI_PROGRESS_UNSPEC:
	case FI_PROGRESS_AUTO:
	case FI_PROGRESS_MANUAL:
		break;

	default:
		ZHPE_LOG_DBG("Data progress mode not supported!\n");
		return -FI_ENODATA;
	}

	switch (attr->resource_mgmt) {
	case FI_RM_UNSPEC:
	case FI_RM_DISABLED:
	case FI_RM_ENABLED:
		break;

	default:
		ZHPE_LOG_DBG("Resource mgmt not supported!\n");
		return -FI_ENODATA;
	}

	switch (attr->av_type) {
	case FI_AV_UNSPEC:
	case FI_AV_MAP:
	case FI_AV_TABLE:
		break;

	default:
		ZHPE_LOG_DBG("AV type not supported!\n");
		return -FI_ENODATA;
	}

	rc = ofi_check_mr_mode(&zhpe_prov, api_version,
			       zhpe_domain_attr.mr_mode | FI_MR_BASIC, info);
	if (rc < 0)
		return rc;

	if (attr->mr_key_size > zhpe_domain_attr.mr_key_size)
		return -FI_ENODATA;

	if (attr->cq_data_size > zhpe_domain_attr.cq_data_size)
		return -FI_ENODATA;

	if (attr->cq_cnt > zhpe_domain_attr.cq_cnt)
		return -FI_ENODATA;

	if (attr->ep_cnt > zhpe_domain_attr.ep_cnt)
		return -FI_ENODATA;

	if (attr->max_ep_tx_ctx > zhpe_domain_attr.max_ep_tx_ctx)
		return -FI_ENODATA;

	if (attr->max_ep_rx_ctx > zhpe_domain_attr.max_ep_rx_ctx)
		return -FI_ENODATA;

	if (attr->cntr_cnt > zhpe_domain_attr.cntr_cnt)
		return -FI_ENODATA;

	if (attr->mr_iov_limit > zhpe_domain_attr.mr_iov_limit)
		return -FI_ENODATA;

	if (attr->max_err_data > zhpe_domain_attr.max_err_data)
		return -FI_ENODATA;

	if (attr->mr_cnt > zhpe_domain_attr.mr_cnt)
		return -FI_ENODATA;

	return 0;
}

static int zhpe_dom_close(struct fid *fid)
{
	struct zhpe_domain *dom;

	dom = container_of(fid, struct zhpe_domain, dom_fid.fid);
	if (dom->cache_inited) {
		fastlock_acquire(&dom->cache_lock);
		while (ofi_mr_cache_flush(&dom->cache));
		fastlock_release(&dom->cache_lock);
	}
	if (atm_load_rlx(&dom->ref))
		return -FI_EBUSY;

	zhpe_pe_finalize(dom->pe);
	fastlock_destroy(&dom->lock);
	zhpe_mr_cache_destroy(dom);
	rbtDelete(dom->mr_tree);
	zhpeq_domain_free(dom->zdom);
	zhpe_dom_remove_from_list(dom);
	free(dom);

	return 0;
}

int zhpe_zmr_put_uncached(struct zhpe_mr *zmr)
{
	struct zhpe_domain	*domain;
	struct zhpe_kexp_data	*kexp;
	RbtIterator		*rbt;
	int32_t			old;
	struct zhpe_mr_ops	*zmr_ops;

	old = atm_dec(&zmr->use_count);
	assert(old > 0);
	if (old > 1)
		return 0;

	domain = zmr->domain;

	fastlock_acquire(&domain->lock);
	rbt = zhpe_zkey_rbtFind(domain->mr_tree, &zmr->zkey);
	assert(rbt);
	if (rbt)
		rbtErase(domain->mr_tree, rbt);
	fastlock_release(&domain->lock);
	while (!dlist_empty(&zmr->kexp_list)) {
		dlist_pop_front(&zmr->kexp_list, struct zhpe_kexp_data,
				kexp, lentry);
		/* FIXME:race with conn going away? */
		mutex_lock(&kexp->conn->tx_ctx->mutex);
		rbt = zhpe_zkey_rbtFind(kexp->conn->kexp_tree, &zmr->zkey);
		if (rbt)
			rbtErase(kexp->conn->kexp_tree, rbt);
		mutex_unlock(&kexp->conn->tx_ctx->mutex);
		zhpe_send_key_revoke(kexp->conn, &zmr->zkey);
		free(kexp);
	}
	atm_dec(&domain->ref);
	if (zmr->kdata)
		zhpeq_mr_free(zmr->domain->zdom, zmr->kdata);
	zmr_ops = container_of(zmr->mr_fid.fid.ops, struct zhpe_mr_ops,
			       fi_ops);
	zmr_ops->freeme(zmr);

	return 0;
}

int zhpe_mr_close(struct fid *fid)
{
	return zhpe_mr_put(container_of(fid, struct zhpe_mr, mr_fid.fid));
}

static struct zhpe_mr_ops zmr_ops_uncached = {
	.fi_ops = {
		.size		= sizeof(struct fi_ops),
		.close		= zhpe_mr_close,
		.bind		= fi_no_bind,
		.control	= fi_no_control,
		.ops_open	= fi_no_ops_open,
	},
	.freeme			= zhpeu_free_ptr,
	.put			= zhpe_zmr_put_uncached,
};

struct zhpe_mr *zhpe_mr_find(struct zhpe_domain *domain,
			     const struct zhpe_key *zkey)
{
	struct zhpe_mr		*ret = NULL;
	RbtIterator		*rbt;

	fastlock_acquire(&domain->lock);
	rbt = zhpe_zkey_rbtFind(domain->mr_tree, zkey);
	if (rbt) {
		ret = zhpe_rbtKeyValue(domain->mr_tree, rbt);
		zhpe_mr_get(ret);
	}
	fastlock_release(&domain->lock);

	return ret;
}

int zhpe_zmr_reg(struct zhpe_domain *domain, const void *buf,
		 size_t len, uint32_t qaccess, uint64_t key,
		 struct zhpe_mr *zmr, struct zhpe_mr_ops *ops)
{
	int			ret = 0;
	RbtIterator		*rbt;

	dlist_init(&zmr->kexp_list);
	zmr->mr_fid.fid.fclass = FI_CLASS_MR;
	zmr->mr_fid.fid.ops = &ops->fi_ops;
	zmr->mr_fid.mem_desc = zmr;
	zmr->mr_fid.key = key;
	zmr->domain = domain;
	zmr->flags = 0;
	zmr->use_count = 1;
	zmr->zkey.key = key;
	zmr->zkey.internal = !!(qaccess & ZHPE_MR_KEY_INT);

	ret = zhpeq_mr_reg(domain->zdom, buf, len, qaccess, &zmr->kdata);
	ZHPE_LOG_DBG("dom %p buf %p len 0x%lx qa 0x%x key 0x%lx/%d ret %d\n",
		     domain, buf, len, qaccess, key, zmr->zkey.internal, ret);
	if (ret < 0)
		goto done;

	fastlock_acquire(&domain->lock);
	rbt = zhpe_zkey_rbtFind(domain->mr_tree, &zmr->zkey);
	if (rbt)
		ret = -FI_ENOKEY;
	else
		zhpe_zmr_rbtInsert(domain->mr_tree, zmr);
	fastlock_release(&domain->lock);
	atm_inc(&domain->ref);
	if (OFI_UNLIKELY(ret < 0)) {
		zhpeq_mr_free(domain->zdom, zmr->kdata);
		zmr->kdata = NULL;
		goto done;
	}

 done:
	return ret;
}

int zhpe_mr_reg_int_uncached(struct zhpe_domain *domain, const void *buf,
			     size_t len, uint64_t access, uint32_t qaccess,
			     struct fid_mr **mr)
{
	int			ret;
	struct zhpe_mr		*zmr;

	zmr = malloc(sizeof(*zmr));
	if (!zmr)
		return -FI_ENOMEM;

	qaccess |= ZHPE_MR_KEY_INT | zhpe_convert_access(access);

	ret = zhpe_zmr_reg(domain, buf, len, qaccess,
			   atm_inc(&domain->mr_zhpe_key),
			   zmr, &zmr_ops_uncached);
	if (ret >= 0)
		*mr = &zmr->mr_fid;
	else {
		*mr = NULL;
		free(zmr);
	}

	return ret;
}

int zhpe_mr_reg_int_iov(struct zhpe_domain *domain,
			struct zhpe_iov_state *lstate)
{
	int			ret = 0;
	struct zhpe_iov		*liov = lstate->viov;
	uint8_t			missing = lstate->missing;
 	int			i;
	struct fid_mr		*mr;
	struct zhpe_mr		*zmr;

        for (i = ffs(missing) - 1; i >= 0;
	     (missing &= ~(1U << i), i = ffs(missing) - 1)) {
		zmr = liov[i].iov_desc;
		assert(!zmr);
		ret = domain->reg_int(domain, liov[i].iov_base, liov[i].iov_len,
				      ZHPE_MR_ACCESS_ALL, 0, &mr);
		if (ret < 0)
			break;
		liov[i].iov_len |= ZHPE_ZIOV_LEN_KEY_INT;
		zmr = container_of(mr, struct zhpe_mr, mr_fid);
		liov[i].iov_desc = zmr;
		ret = zhpeq_lcl_key_access(zmr->kdata, liov[i].iov_base, 0, 0,
					   &liov[i].iov_zaddr);
		if (ret < 0)
			break;
	}

	return ret;
}

static int zhpe_regattr(struct fid *fid, const struct fi_mr_attr *attr,
			uint64_t flags, struct fid_mr **mr)
{
	int			ret = -FI_EINVAL;
	uint32_t		qaccess = 0;
	struct zhpe_domain	*domain;
	uint64_t		key;
	struct zhpe_mr		*zmr;
	struct fi_eq_entry	eq_entry;

	if (!fid || fid->fclass != FI_CLASS_DOMAIN ||
	    !attr || !attr->mr_iov || attr->iov_count != 1 ||
	    (attr->access & ~(FI_SEND | FI_RECV | FI_READ | FI_WRITE |
			      FI_REMOTE_READ | FI_REMOTE_WRITE)) ||
	    flags || !mr)
		goto done;

	zmr = malloc(sizeof(*zmr));
	if (!zmr) {
		ret = -FI_ENOMEM;
		goto done;
	}

	domain = container_of(fid, struct zhpe_domain, dom_fid.fid);

	key = attr->requested_key;
	if (domain->attr.mr_mode & FI_MR_PROV_KEY)
		key = atm_inc(&domain->mr_user_key);
	if (!(domain->attr.mr_mode & FI_MR_VIRT_ADDR))
		qaccess |= ZHPEQ_MR_KEY_ZERO_OFF;
	qaccess |= zhpe_convert_access(attr->access);

	ret = zhpe_zmr_reg(domain, attr->mr_iov[0].iov_base,
			   attr->mr_iov[0].iov_len, qaccess, key,
			   zmr, &zmr_ops_uncached);
	if (ret >= 0)
		*mr = &zmr->mr_fid;
	else {
		*mr = NULL;
		free(zmr);
		goto done;
	}
	if (domain->mr_eq) {
		zmr->mr_fid.fid.context = attr->context;
		eq_entry.context = attr->context;
		eq_entry.fid = &domain->dom_fid.fid;
		ret = zhpe_eq_report_event(domain->mr_eq, FI_MR_COMPLETE,
					   &eq_entry, sizeof(eq_entry), 0);
		if (ret < 0) {
			zhpe_mr_put(zmr);
			*mr = NULL;
		}
	}
 done:
	return ret;
}

static int zhpe_regv(struct fid *fid, const struct iovec *iov,
		size_t count, uint64_t access,
		uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr, void *context)
{
	struct fi_mr_attr	attr = {
		attr.mr_iov	= iov,
		attr.iov_count	= count,
		attr.access	= access,
		attr.offset	= offset,
		attr.requested_key = requested_key,
		attr.context	= context,
	};

	return zhpe_regattr(fid, &attr, flags, mr);
}

static int zhpe_reg(struct fid *fid, const void *buf, size_t len,
		    uint64_t access, uint64_t offset, uint64_t requested_key,
		    uint64_t flags, struct fid_mr **mr, void *context)
{
	struct iovec		iov = {
		iov.iov_base	= (void *)buf,
		iov.iov_len	= len,
	};

	return zhpe_regv(fid, &iov, 1, access,  offset, requested_key,
			 flags, mr, context);
}

static int zhpe_dom_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct zhpe_domain *dom;
	struct zhpe_eq *eq;

	dom = container_of(fid, struct zhpe_domain, dom_fid.fid);
	eq = container_of(bfid, struct zhpe_eq, eq.fid);

	if (dom->eq)
		return -FI_EINVAL;

	dom->eq = eq;
	if (flags & FI_REG_MR)
		dom->mr_eq = eq;

	return 0;
}

static int zhpe_dom_ctrl(struct fid *fid, int command, void *arg)
{
	struct zhpe_domain *dom;

	dom = container_of(fid, struct zhpe_domain, dom_fid.fid);

	switch (command) {
	/* FIXME: Revisit deferred work. */
	case FI_QUEUE_WORK:
#if 0
		return zhpe_queue_work(dom, arg);
#else
		(void)dom;
#endif
	default:
		return -FI_ENOSYS;
	}
}

static int zhpe_endpoint(struct fid_domain *domain, struct fi_info *info,
			 struct fid_ep **ep, void *context)
{
	switch (info->ep_attr->type) {
	case FI_EP_RDM:
		return zhpe_rdm_ep(domain, info, ep, context);
	case FI_EP_MSG:
		return zhpe_msg_ep(domain, info, ep, context);
	default:
		return -FI_ENOPROTOOPT;
	}
}

static int zhpe_scalable_ep(struct fid_domain *domain, struct fi_info *info,
		     struct fid_ep **sep, void *context)
{
	/* FIXME: Scalable EP */
	return -FI_ENOSYS;
#if 0
	switch (info->ep_attr->type) {
	case FI_EP_RDM:
		return zhpe_rdm_sep(domain, info, sep, context);
	case FI_EP_MSG:
		return zhpe_msg_sep(domain, info, sep, context);
	default:
		return -FI_ENOPROTOOPT;
	}
#endif
}

static struct fi_ops zhpe_dom_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_dom_close,
	.bind = zhpe_dom_bind,
	.control = zhpe_dom_ctrl,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_domain zhpe_dom_ops = {
	.size = sizeof(struct fi_ops_domain),
	.av_open = zhpe_av_open,
	.cq_open = zhpe_cq_open,
	.endpoint = zhpe_endpoint,
	.scalable_ep = zhpe_scalable_ep,
	.cntr_open = zhpe_cntr_open,
	.poll_open = zhpe_poll_open,
	.stx_ctx = fi_no_stx_context,
	.srx_ctx = fi_no_srx_context,
	.query_atomic = zhpe_query_atomic,
};

static struct fi_ops_mr zhpe_dom_mr_ops = {
	.size = sizeof(struct fi_ops_mr),
	.reg = zhpe_reg,
	.regv = zhpe_regv,
	.regattr = zhpe_regattr,
};

int zhpe_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context)
{
	int			ret;
	struct zhpe_domain	*zhpe_domain;
	struct zhpe_fabric	*fab;

	fab = container_of(fabric, struct zhpe_fabric, fab_fid);
	if (info && info->domain_attr) {
		ret = zhpe_verify_domain_attr(fabric->api_version, info);
		if (ret < 0)
			goto err0;
	}

	zhpe_domain = calloc_cachealigned(1, sizeof(*zhpe_domain));
	if (!zhpe_domain) {
		ret = -FI_ENOMEM;
		goto err0;
	}

	fastlock_init(&zhpe_domain->lock);
	zhpe_domain->monitor_fd = -1;

	if (info)
		zhpe_domain->info = *info;
	else {
		ret = -FI_EINVAL;
		ZHPE_LOG_ERROR("invalid fi_info\n");
		goto err1;
	}

	zhpe_domain->dom_fid.fid.fclass = FI_CLASS_DOMAIN;
	zhpe_domain->dom_fid.fid.context = context;
	zhpe_domain->dom_fid.fid.ops = &zhpe_dom_fi_ops;
	zhpe_domain->dom_fid.ops = &zhpe_dom_ops;
	zhpe_domain->dom_fid.mr = &zhpe_dom_mr_ops;

	if (!info->domain_attr ||
	    info->domain_attr->data_progress == FI_PROGRESS_UNSPEC)
		zhpe_domain->progress_mode = zhpe_domain_attr.data_progress;
	else
		zhpe_domain->progress_mode = info->domain_attr->data_progress;

	zhpe_domain->fab = fab;
	*dom = &zhpe_domain->dom_fid;

	if (info->domain_attr)
		zhpe_domain->attr = *(info->domain_attr);
	else
		zhpe_domain->attr = zhpe_domain_attr;
	if (zhpe_domain->attr.mr_mode == FI_MR_BASIC) {
		zhpe_domain->attr.mr_mode = OFI_MR_BASIC_MAP;
		if (info->mode & FI_LOCAL_MR)
			zhpe_domain->attr.mr_mode |= FI_MR_LOCAL;
	}

	zhpe_domain->pe = zhpe_pe_init(zhpe_domain);
	if (!zhpe_domain->pe) {
		ret = -FI_ENOMEM;
		ZHPE_LOG_ERROR("Failed to init PE\n");
		goto err1;
	}

	zhpe_domain->mr_tree = rbtNew(zhpe_compare_zkeys);
	if (!zhpe_domain->mr_tree) {
		ret = -FI_ENOMEM;
		goto err2;
	}
	zhpe_domain->reg_int = zhpe_mr_reg_int_uncached;
	ret = zhpe_mr_cache_init(zhpe_domain);
	if (ret < 0)
		goto err3;
	ret = zhpeq_domain_alloc(&zhpe_domain->zdom);
	if (ret < 0)
		goto err4;

	zhpe_dom_add_to_list(zhpe_domain);

	return 0;
 err4:
	zhpe_mr_cache_destroy(zhpe_domain);
 err3:
	rbtDelete(zhpe_domain->mr_tree);
 err2:
	zhpe_pe_finalize(zhpe_domain->pe);
 err1:
	fastlock_destroy(&zhpe_domain->lock);
	free(zhpe_domain);
 err0:

       return ret;
}
