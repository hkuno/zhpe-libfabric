/*
 * Copyright (c) 2013-2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2017-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_CQ, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_CQ, __VA_ARGS__)

void zhpe_cq_add_tx_ctx(struct zhpe_cq *zcq, struct zhpe_tx_ctx *tx_ctx)
{
	struct zhpe_tx_ctx	*curr_ctx;

	fastlock_acquire(&zcq->list_lock);
	dlist_foreach_container(&zcq->tx_list, struct zhpe_tx_ctx, curr_ctx,
				cq_lentry) {
		if (tx_ctx == curr_ctx)
			goto out;
	}
	dlist_insert_tail(&tx_ctx->cq_lentry, &zcq->tx_list);
	ofi_atomic_inc32(&zcq->util_cq.ref);
out:
	fastlock_release(&zcq->list_lock);
}

void zhpe_cq_remove_tx_ctx(struct zhpe_cq *zcq, struct zhpe_tx_ctx *tx_ctx)
{
	fastlock_acquire(&zcq->list_lock);
	dlist_remove(&tx_ctx->cq_lentry);
	ofi_atomic_dec32(&zcq->util_cq.ref);
	fastlock_release(&zcq->list_lock);
}

void zhpe_cq_add_rx_ctx(struct zhpe_cq *zcq, struct zhpe_rx_ctx *rx_ctx)
{
	struct zhpe_rx_ctx	*curr_ctx;

	fastlock_acquire(&zcq->list_lock);
	dlist_foreach_container(&zcq->rx_list, struct zhpe_rx_ctx, curr_ctx,
				cq_lentry) {
		if (rx_ctx == curr_ctx)
			goto out;
	}
	dlist_insert_tail(&rx_ctx->cq_lentry, &zcq->rx_list);
	ofi_atomic_inc32(&zcq->util_cq.ref);
out:
	fastlock_release(&zcq->list_lock);
}

void zhpe_cq_remove_rx_ctx(struct zhpe_cq *zcq, struct zhpe_rx_ctx *rx_ctx)
{
	fastlock_acquire(&zcq->list_lock);
	dlist_remove(&rx_ctx->cq_lentry);
	ofi_atomic_dec32(&zcq->util_cq.ref);
	fastlock_release(&zcq->list_lock);
}

static void zhpe_cq_progress(struct util_cq *cq)
{
	struct zhpe_cq		*zcq = ucq2zcq(cq);
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_rx_ctx	*rx_ctx;
	struct zhpe_pe		*zpe;

	zpe = zcq2zdom(zcq)->pe;
	fastlock_acquire(&zcq->list_lock);
	dlist_foreach_container(&zcq->tx_list, struct zhpe_tx_ctx, tx_ctx,
				cq_lentry) {
		if (!tx_ctx->enabled)
			continue;

		zhpe_pe_progress_tx_ctx(zpe, tx_ctx);
	}

	dlist_foreach_container(&zcq->rx_list, struct zhpe_rx_ctx, rx_ctx,
				cq_lentry) {
		if (!rx_ctx->enabled)
			continue;

		zhpe_pe_progress_rx_ctx(zpe, rx_ctx);
	}
	fastlock_release(&zcq->list_lock);
}

static void zhpe_cq_progress_dummy(struct util_cq *cq)
{
}

static uint64_t zhpe_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (FI_SEND | FI_RECV | FI_RMA | FI_ATOMIC |
			 FI_MSG | FI_TAGGED | FI_READ | FI_WRITE |
			 FI_REMOTE_READ | FI_REMOTE_WRITE |
			 FI_REMOTE_CQ_DATA | FI_MULTI_RECV));
}

int zhpe_cq_report_success(struct util_cq *cq,
			    struct fi_cq_tagged_entry *tcqe)
{
	int			ret;
	uint64_t		flags = zhpe_cq_sanitize_flags(tcqe->flags);

	ret = ofi_cq_write(cq, tcqe->op_context, flags, tcqe->len, tcqe->buf,
			   tcqe->data, tcqe->tag);
	if (ret < 0)
		goto done;
	if (cq->wait)
		util_cq_signal(cq);
 done:

	return ret;
}

int zhpe_cq_report_error(struct util_cq *cq, struct fi_cq_tagged_entry *tcqe,
			 size_t olen, int err, int prov_err,
			 const void *err_data, size_t err_data_size)
{
	int			ret = -FI_ENOMEM;
	uint64_t		flags = zhpe_cq_sanitize_flags(tcqe->flags);
	void			*err_data_buf = NULL;
	struct fi_cq_err_entry	err_entry;

	if (err_data && err_data_size) {
		err_data_buf = malloc(err_data_size);
		if (!err_data_buf)
			goto done;
		memcpy(err_data_buf, err_data, err_data_size);
	} else
		err_data_size = 0;

	err_entry.op_context	= tcqe->op_context;
	err_entry.flags		= flags;
	err_entry.len		= tcqe->len;
	err_entry.buf		= tcqe->buf;
	err_entry.data		= tcqe->data;
	err_entry.tag		= tcqe->tag;
	err_entry.olen		= olen;
	err_entry.err		= err;
	err_entry.prov_errno	= prov_err;
	err_entry.err_data	= err_data_buf;
	err_entry.err_data_size = err_data_size;

	ret = ofi_cq_write_error(cq, &err_entry);
 done:
	if (ret < 0) {
		free(err_data_buf);
		ZHPE_LOG_ERROR("error %d:%s\n", ret, fi_strerror(-ret));
	}

	return ret;
}

static int zhpe_cq_close(struct fid *fid)
{
	int			ret;
	struct zhpe_cq		*zcq;

	zcq = fid2zcq(fid);
	ret = ofi_cq_cleanup(&zcq->util_cq);
	if (ret < 0)
		goto done;
	fastlock_destroy(&zcq->list_lock);
	free(zcq);
 done:

	return ret;
}

static struct fi_ops zhpe_cq_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= zhpe_cq_close,
	.bind		= fi_no_bind,
	.control	= ofi_cq_control,
	.ops_open	= fi_no_ops_open,
};

int zhpe_cq_open(struct fid_domain *fid_domain, struct fi_cq_attr *attr,
		 struct fid_cq **fid_cq, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_domain	*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_cq		*zcq = NULL;
	ofi_cq_progress_func	progress;
	struct fi_cq_attr	attr_copy;

	if (!fid_cq)
		goto done;
	*fid_cq = NULL;
	if (!fid_domain || !attr)
		goto done;

	zcq = calloc(1, sizeof(*zcq));
	if (!zcq) {
		ret = -FI_ENOMEM;
		goto done;
	}
	fastlock_init(&zcq->list_lock);

	attr_copy = *attr;
	attr = &attr_copy;
	if (!attr->size)
		attr->size = zhpe_cq_def_sz;

	if (zdom->util_domain.data_progress == FI_PROGRESS_AUTO)
		progress = zhpe_cq_progress_dummy;
	else
		progress = zhpe_cq_progress;

	ret = ofi_cq_init(&zhpe_prov, fid_domain, attr, &zcq->util_cq,
			  progress, context);
	if (ret < 0)
		goto done;

	dlist_init(&zcq->tx_list);
	dlist_init(&zcq->rx_list);

	*fid_cq = &zcq->util_cq.cq_fid;
	(*fid_cq)->fid.ops = &zhpe_cq_fi_ops;
 done:
	if (ret < 0 && zcq) {
		fastlock_destroy(&zcq->list_lock);
		free(zcq);
	}

	return ret;
}
