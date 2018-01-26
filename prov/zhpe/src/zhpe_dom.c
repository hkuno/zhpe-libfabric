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
	.threading = FI_THREAD_SAFE,
	.control_progress = FI_PROGRESS_AUTO,
	.data_progress = FI_PROGRESS_AUTO,
	.resource_mgmt = FI_RM_ENABLED,
	.mr_mode = FI_MR_ALLOCATED | FI_MR_VIRT_ADDR,
	.mr_key_size = ZHPE_KEY_SIZE,
	.cq_data_size = ZHPE_CQ_DATA_SIZE,
	.cq_cnt = ZHPE_EP_MAX_CQ_CNT,
	.ep_cnt = ZHPE_EP_MAX_EP_CNT,
	.tx_ctx_cnt = ZHPE_EP_MAX_TX_CNT,
	.rx_ctx_cnt = ZHPE_EP_MAX_RX_CNT,
	.max_ep_tx_ctx = ZHPE_EP_MAX_TX_CNT,
	.max_ep_rx_ctx = ZHPE_EP_MAX_RX_CNT,
	.max_ep_stx_ctx = ZHPE_EP_MAX_EP_CNT,
	.max_ep_srx_ctx = ZHPE_EP_MAX_EP_CNT,
	.cntr_cnt = ZHPE_EP_MAX_CNTR_CNT,
	.mr_iov_limit = ZHPE_EP_MAX_IOV_LIMIT,
	.max_err_data = ZHPE_MAX_ERR_CQ_EQ_DATA_SZ,
	.mr_cnt = ZHPE_DOMAIN_MR_CNT,
};

static inline int user_mr_mode(uint32_t api_version,
			       const struct fi_info *info, uint32_t *user_mode)
{
	*user_mode = info->domain_attr->mr_mode;

	if (FI_VERSION_LT(api_version, FI_VERSION(1, 5))) {

		switch (*user_mode) {

		case FI_MR_UNSPEC:
		case FI_MR_BASIC:
			*user_mode = OFI_MR_BASIC_MAP;
			if (info->mode & FI_LOCAL_MR)
				*user_mode |= FI_MR_LOCAL;
			break;

		default:
			return -FI_ENODATA;
		}

		return 0;
	}
	if (*user_mode & (FI_MR_BASIC | FI_MR_SCALABLE)) {
		if (*user_mode == FI_MR_BASIC) {
			*user_mode = OFI_MR_BASIC_MAP;
			if (info->mode & FI_LOCAL_MR)
				*user_mode |= FI_MR_LOCAL;
		} else
			return -FI_ENODATA;
	}

	return 0;
}

/* FIXME: Temporary, imported from master post v1.5.1
 * I'm not sure I completely agree with this, but the goal is to reduce
 * the required capabilities if the user hasn't asked to support
 * remote RMA operations. Importing this allows me to work with the
 * latest fabtests.
 */
static inline void ofi_mr_mode_adjust(uint64_t info_caps, uint32_t *mr_mode)
{
	if (!(info_caps & (FI_RMA | FI_ATOMIC)) ||
	    !(info_caps & (FI_REMOTE_READ | FI_REMOTE_WRITE))) {
		*mr_mode &= ~(FI_MR_PROV_KEY | FI_MR_VIRT_ADDR);
		if (!(*mr_mode & FI_MR_LOCAL))
			*mr_mode &= ~FI_MR_ALLOCATED;
	}
}

int zhpe_verify_domain_attr(uint32_t version, const struct fi_info *info)
{
	const struct fi_domain_attr *attr = info->domain_attr;
	uint32_t		user32;
	uint32_t		prov32;

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

	prov32 = zhpe_domain_attr.mr_mode;
	ofi_mr_mode_adjust(info->caps, &prov32);
	if (user_mr_mode(version, info, &user32) < 0 ||
	    (user32 & prov32) != prov32) {
		FI_INFO(&zhpe_prov, FI_LOG_CORE,
			"Invalid memory registration mode\n");
		return -FI_ENODATA;
	}

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
	if (ofi_atomic_get32(&dom->ref))
		return -FI_EBUSY;

	zhpe_pe_finalize(dom->pe);
	fastlock_destroy(&dom->lock);
	ofi_mr_map_close(&dom->mr_map);
	zhpeq_domain_free(dom->zdom);
	zhpe_dom_remove_from_list(dom);
	free(dom);

	return 0;
}

int mr_close(struct fid *fid, bool revoke_oneshot)
{
	int			ret;
	struct zhpe_mr		*zmr;
	struct zhpe_domain	*domain;
	struct zhpe_conn_map	*map;
	struct zhpe_kexp_data	*kexp;
	RbtIterator		*rbt;

	zmr = container_of(fid, struct zhpe_mr, mr_fid.fid);
	domain = zmr->domain;

	fastlock_acquire(&domain->lock);
	zmr->flags |= ZHPE_MR_KEY_FREEING;
	while (!dlist_empty(&zmr->kexp_list)) {
	        kexp = container_of(zmr->kexp_list.next,
				   struct zhpe_kexp_data, lentry);
		dlist_remove(&kexp->lentry);
		dlist_init(&kexp->lentry);
		fastlock_release(&domain->lock);
		fastlock_acquire(&kexp->conn->mr_lock);
		rbt = rbtFind(kexp->conn->kexp_tree, &zmr->mr_fid.key);
		if (rbt)
			rbtErase(kexp->conn->kexp_tree, rbt);
		fastlock_release(&kexp->conn->mr_lock);
		if (kexp->exporting) {
			map = &kexp->conn->ep_attr->cmap;
			mutex_acquire(&map->mutex);
			while (kexp->exporting)
				cond_wait(&map->cond, &map->mutex);
			mutex_release(&map->mutex);
		}
		if (!(zmr->kdata->access & ZHPEQ_MR_KEY_ONESHOT) ||
		    revoke_oneshot)
			zhpe_send_key_revoke(kexp->conn, zmr->mr_fid.key);
		zhpe_kexp_put(kexp);
		fastlock_acquire(&domain->lock);
	}
	/* Free key last to prevent re-use race. */
	ret = ofi_mr_remove(&domain->mr_map, zmr->mr_fid.key);
	if (ret < 0)
		ZHPE_LOG_ERROR("MR Erase error %d \n", ret);
	fastlock_release(&domain->lock);
	ofi_atomic_dec32(&domain->ref);
	zhpe_mr_put(zmr);

	return 0;
}

int zhpe_mr_close(struct fid *fid)
{
	return mr_close(fid, true);
}

int zhpe_mr_close_oneshot(struct zhpe_iov *ziov, uint32_t count, bool revoke)
{
	int			ret = 0;
	int			rc;
	uint32_t		i;
	struct zhpe_mr		*zmr;

	for (i = 0; i < count; i++) {
		zmr = ziov[i].iov_desc;
		if (!zmr || !(zmr->kdata->access & ZHPEQ_MR_KEY_ONESHOT))
			continue;
		rc = mr_close(&zmr->mr_fid.fid, revoke);
		if (rc < 0 && ret >= 0)
			ret = rc;
	}

	return ret;
}

static struct fi_ops zhpe_mr_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_mr_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

struct zhpe_mr *zhpe_mr_get(struct zhpe_domain *domain, uint64_t key)
{
	struct zhpe_mr		*ret;

	fastlock_acquire(&domain->lock);
	ret = ofi_mr_get(&domain->mr_map, key);
	if (ret)
		__sync_fetch_and_add(&ret->use_count, 1);
	fastlock_release(&domain->lock);

	return ret;
}

static inline int zhpe_regattr_int(struct zhpe_domain *domain,
				   const struct fi_mr_attr *attr,
				   uint64_t flags, struct fid_mr **mr_out)
{
	int			ret = -FI_ENOMEM;
	struct zhpe_mr		*zmr = NULL;
	bool			locked = false;

	zmr = calloc(1, sizeof(*zmr));
	if (!zmr)
		goto done;
	dlist_init(&zmr->kexp_list);

	fastlock_acquire(&domain->lock);
	locked = true;

	zmr->mr_fid.fid.fclass = FI_CLASS_MR;
	zmr->mr_fid.fid.context = attr->context;
	zmr->mr_fid.fid.ops = &zhpe_mr_fi_ops;
	zmr->mr_fid.mem_desc = zmr;
	zmr->domain = domain;
	zmr->flags = flags;
	zmr->use_count = 1;

	ret = ofi_mr_insert(&domain->mr_map, attr, &zmr->mr_fid.key, zmr);
	if (ret < 0)
		goto done;

	fastlock_release(&domain->lock);
	locked = false;

	ofi_atomic_inc32(&domain->ref);

	ret = zhpeq_mr_reg(domain->zdom, attr->mr_iov[0].iov_base,
			   attr->mr_iov[0].iov_len,
			   zhpe_convert_access(attr->access),
			   attr->requested_key, &zmr->kdata);
	if (ret < 0)
		goto done;
	/* FIXME: Hack. */
	zmr->kdata->key = zmr->mr_fid.key;
	*mr_out = &zmr->mr_fid;
 done:
	if (ret < 0) {
		if (locked) {
			fastlock_release(&domain->lock);
			free(zmr);
		} else if (zmr)
			zhpe_mr_close(&zmr->mr_fid.fid);
	}

	return ret;
}

int zhpe_mr_reg_int(struct zhpe_domain *domain, const void *buf, size_t len,
		    uint64_t access, struct fid_mr **mr)
{
	struct iovec		iov = {
		.iov_base	= (void *)buf,
		.iov_len	= len,
	};
	struct fi_mr_attr	attr = {
		.mr_iov		= &iov,
		.iov_count	= 1,
		.access		= access,
	};

	attr.requested_key = ((uint64_t)UINT32_MAX + 1 +
			      __sync_fetch_and_add(&domain->mr_zhpe_key, 1));
	if (!zhpe_mr_key_int(attr.requested_key))
		return -FI_ENOKEY;

	return zhpe_regattr_int(domain, &attr, 0, mr);
}

int zhpe_mr_reg_int_oneshot(struct zhpe_domain *domain, struct zhpe_iov *ziov,
			    size_t len, uint64_t access)
{
	int			ret = 0;
	size_t			i;
	size_t			tlen;
	size_t			rlen = 0;
	struct fid_mr		*mr;
	struct zhpe_mr		*zmr;

	access |= ZHPE_MR_KEY_ONESHOT;
	for (tlen = len, i = 0; tlen > 0; tlen -= rlen, i++) {
		rlen = tlen;
		if (rlen > ziov[i].iov_len)
			rlen = ziov[i].iov_len;
		zmr = ziov[i].iov_desc;
		if (zmr)
			continue;
		ret = zhpe_mr_reg_int(domain, ziov[i].iov_base, rlen,
				      access, &mr);
		if (ret < 0)
			goto done;
		zmr = ziov[i].iov_desc = fi_mr_desc(mr);
		if (!(access & FI_RECV))
			continue;
		ret = zhpeq_lcl_key_access(zmr->kdata,
					   ziov[i].iov_base, rlen,
					   ZHPEQ_MR_RECV, &ziov[i].iov_zaddr);
		if (ret < 0)
			goto done;
	}
 done:
	return ret;
}

static int zhpe_regattr(struct fid *fid, const struct fi_mr_attr *attr,
			uint64_t flags, struct fid_mr **mr_out)
{
	int			ret = -FI_EINVAL;
	struct fi_mr_attr	dup_attr;
	struct zhpe_domain	*domain;
	struct fi_eq_entry	eq_entry;

	if (!fid || fid->fclass != FI_CLASS_DOMAIN ||
	    !attr || attr->iov_count != 1 ||
	    (attr->access & ~(FI_SEND | FI_RECV | FI_READ | FI_WRITE |
			      FI_REMOTE_READ | FI_REMOTE_WRITE)) || flags)
		goto done;

	domain = container_of(fid, struct zhpe_domain, dom_fid);

	dup_attr = *attr;
	if (domain->attr.mr_mode & FI_MR_PROV_KEY)
		dup_attr.requested_key =
			__sync_fetch_and_add(&domain->mr_user_key, 1);

	if (zhpe_mr_key_int(dup_attr.requested_key)) {
		ret = -FI_ENOKEY;
		goto done;
	}

	ret = zhpe_regattr_int(domain, &dup_attr, flags, mr_out);
	if (ret >= 0 && domain->mr_eq) {
		eq_entry.fid = &domain->dom_fid.fid;
		eq_entry.context = attr->context;
		ret = zhpe_eq_report_event(domain->mr_eq, FI_MR_COMPLETE,
					   &eq_entry, sizeof(eq_entry), 0);
	}
 done:
	return ret;
}

static int zhpe_regv(struct fid *fid, const struct iovec *iov,
		size_t count, uint64_t access,
		uint64_t offset, uint64_t requested_key,
		uint64_t flags, struct fid_mr **mr, void *context)
{
	struct fi_mr_attr	attr;

	attr.mr_iov = iov;
	attr.iov_count = count;
	attr.access = access;
	attr.offset = offset;
	attr.requested_key = requested_key;
	attr.context = context;
	return zhpe_regattr(fid, &attr, flags, mr);
}

static int zhpe_reg(struct fid *fid, const void *buf, size_t len,
		    uint64_t access, uint64_t offset, uint64_t requested_key,
		    uint64_t flags, struct fid_mr **mr, void *context)
{
	struct iovec		iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;
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
	.stx_ctx = zhpe_stx_ctx,
	.srx_ctx = zhpe_srx_ctx,
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
	struct zhpe_domain *zhpe_domain;
	struct zhpe_fabric *fab;
	int ret;
	uint32_t		user32;

	fab = container_of(fabric, struct zhpe_fabric, fab_fid);
	if (info && info->domain_attr) {
		ret = zhpe_verify_domain_attr(fabric->api_version, info);
		if (ret)
			return -FI_EINVAL;
	}

	zhpe_domain = calloc(1, sizeof(*zhpe_domain));
	if (!zhpe_domain)
		return -FI_ENOMEM;

	fastlock_init(&zhpe_domain->lock);
	ofi_atomic_initialize32(&zhpe_domain->ref, 0);

	if (info) {
		zhpe_domain->info = *info;
	} else {
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
		zhpe_domain->progress_mode = FI_PROGRESS_AUTO;
	else
		zhpe_domain->progress_mode = info->domain_attr->data_progress;

	zhpe_domain->pe = zhpe_pe_init(zhpe_domain);
	if (!zhpe_domain->pe) {
		ZHPE_LOG_ERROR("Failed to init PE\n");
		goto err1;
	}

	zhpe_domain->fab = fab;
	*dom = &zhpe_domain->dom_fid;

	if (info->domain_attr)
		zhpe_domain->attr = *(info->domain_attr);
	else
		zhpe_domain->attr = zhpe_domain_attr;

	user_mr_mode(info->fabric_attr->api_version, info, &user32);
	/* Disable key allocation in ofi_mr_map routines. */
	ret = ofi_mr_map_init(&zhpe_prov, user32 & ~FI_MR_PROV_KEY,
			      &zhpe_domain->mr_map);
	if (ret)
		goto err2;
	ret = zhpeq_domain_alloc(NULL, &zhpe_domain->zdom);
	if (ret < 0)
		goto err3;

	zhpe_dom_add_to_list(zhpe_domain);
	return 0;
 err3:
	ofi_mr_map_close(&zhpe_domain->mr_map);
 err2:
	zhpe_pe_finalize(zhpe_domain->pe);
 err1:
	fastlock_destroy(&zhpe_domain->lock);
	free(zhpe_domain);
	return -FI_EINVAL;
}
