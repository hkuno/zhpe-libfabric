/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2018-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You m"ay choose to be licensed under the terms of the GNU
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

#ifdef HAVE_LINUX_UMMUNOTIFY_H

#include <sys/ioctl.h>

#include <linux/ummunotify.h>

#endif

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_DOMAIN, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_DOMAIN, __VA_ARGS__)

static inline struct zhpe_mr **entry_data(struct ofi_mr_entry *entry)
{
	return (void *)entry->data;
}

static void zhpe_zmr_get_cached(struct zhpe_mr *zmr)
{
	/* dom mr_lock held */
	assert(zmr->entry->use_cnt > 0);
	zmr->entry->use_cnt++;
}

static int zhpe_zmr_put_cached(struct zhpe_mr *zmr)
{
	int			ret = 0;

	if (!zmr)
		goto done;

	assert(zmr->entry);
	assert(atm_load_rlx(&zmr->use_count) == 1);

	ofi_mr_cache_delete(&zmr->zdom->cache, zmr->entry);
 done:

	return ret;
}

static struct zhpe_mr_ops zmr_ops_cached = {
	.fi_ops = {
		.size		= sizeof(struct fi_ops),
		.close		= zhpe_mr_close,
		.bind		= fi_no_bind,
		.control	= fi_no_control,
		.ops_open	= fi_no_ops_open,
	},
	.get			= zhpe_zmr_get_cached,
	.put			= zhpe_zmr_put_cached,
};

static int zhpe_mr_reg_int_cached(struct zhpe_domain *zdom, const void *buf,
				  size_t len, uint64_t access, uint32_t qaccess,
				  struct fid_mr **fid_mr)
{
	int			ret;
	struct iovec		iov = {
		.iov_base	= (void *)buf,
		.iov_len	= len,
	};
	struct fi_mr_attr	attr = {
		.mr_iov		= &iov,
		.iov_count	= 1,
		.access		= access,
	};
	struct ofi_mr_entry	*entry;
	struct  zhpe_mr		*zmr;

	assert(!qaccess);
	ret = ofi_mr_cache_search(&zdom->cache, &attr, &entry);
	if (OFI_LIKELY(ret >= 0)) {
		zmr = *entry_data(entry);
		*fid_mr = &zmr->mr_fid;
	} else
		*fid_mr = NULL;

	return ret;
}

static int zhpe_mr_cache_add_region(struct ofi_mr_cache *cache,
				    struct ofi_mr_entry *entry)
{
	int			ret;
	struct zhpe_domain	*zdom = udom2zdom(cache->domain);
	void			*buf = entry->info.iov.iov_base;
	size_t			len = entry->info.iov.iov_len;
	uint32_t		qaccess =
		(ZHPEQ_MR_GET | ZHPEQ_MR_PUT | ZHPEQ_MR_GET_REMOTE |
		 ZHPEQ_MR_PUT_REMOTE | ZHPEQ_MR_SEND | ZHPEQ_MR_RECV |
		 ZHPEQ_MR_KEY_ZERO_OFF | ZHPE_MR_KEY_INT);
	struct zhpe_mr		*zmr;

	zmr = malloc(sizeof(*zmr));
	if (!zmr) {
		ret = -FI_ENOMEM;
		goto done;
	}
	ret = zhpe_zmr_reg(zdom, buf, len, qaccess, atm_inc(&zdom->mr_zhpe_key),
			   zmr, &zmr_ops_cached);
	if (ret < 0) {
		free(zmr);
		goto done;
	}
	zmr->entry = entry;
	*entry_data(entry) = zmr;
 done:

	return ret;
}

static void zhpe_mr_cache_delete_region(struct ofi_mr_cache *cache,
					struct ofi_mr_entry *entry)
{
	struct zhpe_mr		*zmr = *entry_data(entry);
	void			*buf = entry->info.iov.iov_base;
	size_t			len = entry->info.iov.iov_len;
	int			rc;

	/* monitor lock is held */
	assert(atm_load_rlx(&zmr->use_count) == 1);
	zmr->entry = NULL;
	rc = zhpe_zmr_put_uncached(zmr);
	if (rc < 0)
		ZHPE_LOG_ERROR("Failed to unregister memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)buf, (uintptr_t)buf + len - 1,
			       rc, fi_strerror(-rc));
}

void zhpe_mr_cache_destroy(struct zhpe_domain *zdom)
{
	RbtIterator		rbt;
	struct zhpe_mr		*free_list = NULL;
	struct zhpe_mr		*zmr;
	struct ofi_mr_entry	*entry;

	if (zdom->cache_inited) {
		/*
		 * No other application threads should have a reference
		 * to the domain *except* the monitor. At the moment,
		 * because we don't clean up well there can be outstanding
		 * active entries in the cache. Find them and free
		 * them.
		 */
		fastlock_acquire(zdom->mr_lock);
		for (rbt  = rbtBegin(zdom->mr_tree); rbt;
		     rbt = rbtNext(zdom->mr_tree, rbt)) {
			zmr = zhpe_rbtKeyValue(zdom->mr_tree, rbt);
			entry = zmr->entry;
			if (entry && entry->use_cnt >= 1) {
				entry->use_cnt = 1;
				zmr->next = free_list;
				free_list = zmr;
			}
		}
		fastlock_release(zdom->mr_lock);
		/*
		 * The monitor lock will be destroyed and we need a valid
		 * lock for the code path, even if we don't care about
		 * exclusion, anymore.
		 */
		zdom->mr_lock = &zdom->util_domain.lock;
		while ((zmr = free_list)) {
			free_list = free_list->next;
			zhpe_mr_put(zmr);
		}
		ofi_mr_cache_cleanup(&zdom->cache);
		zdom->cache_inited = false;
	}
}

int zhpe_mr_cache_init(struct zhpe_domain *zdom)
{
	int			ret = 0;

	if (!zhpe_mr_cache_enable)
		goto done;

	zdom->cache.entry_data_size = sizeof(struct zhpe_mr *);
	zdom->cache.add_region = zhpe_mr_cache_add_region;
	zdom->cache.delete_region = zhpe_mr_cache_delete_region;
	ret = ofi_mr_cache_init(&zdom->util_domain, default_monitor,
				&zdom->cache);
	if (ret < 0)
		goto done;
	zdom->reg_int = zhpe_mr_reg_int_cached;
	zdom->cache_inited = true;

 done:

	return ret;
}
