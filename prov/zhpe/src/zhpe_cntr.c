/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_CNTR, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_CNTR, __VA_ARGS__)

void zhpe_cntr_add_tx_ctx(struct zhpe_cntr *zcntr, struct zhpe_tx_ctx *tx_ctx)
{
	struct fid		*fid = &tx_ctx->ctx.fid;
	int			rc;

	rc = fid_list_insert(&zcntr->tx_list, &zcntr->list_lock, fid);
	if (rc < 0)
		ZHPE_LOG_ERROR("Error %d in adding ctx to progress list\n",
			       rc);
	else
		ofi_atomic_inc32(&zcntr->util_cntr.ref);
}

void zhpe_cntr_remove_tx_ctx(struct zhpe_cntr *zcntr,
			     struct zhpe_tx_ctx *tx_ctx)
{
	struct fid		*fid = &tx_ctx->ctx.fid;

	fid_list_remove(&zcntr->tx_list, &zcntr->list_lock, fid);
	ofi_atomic_dec32(&zcntr->util_cntr.ref);
}

void zhpe_cntr_add_rx_ctx(struct zhpe_cntr *zcntr, struct zhpe_rx_ctx *rx_ctx)
{
	struct fid		*fid = &rx_ctx->ctx.fid;
	int			rc;

	rc = fid_list_insert(&zcntr->rx_list, &zcntr->list_lock, fid);
	if (rc < 0)
		ZHPE_LOG_ERROR("Error %d in adding ctx to progress list\n",
			       rc);
	else
		ofi_atomic_inc32(&zcntr->util_cntr.ref);
}

void zhpe_cntr_remove_rx_ctx(struct zhpe_cntr *zcntr,
			     struct zhpe_rx_ctx *rx_ctx)
{
	struct fid *fid = &rx_ctx->ctx.fid;

	fid_list_remove(&zcntr->rx_list, &zcntr->list_lock, fid);
	ofi_atomic_dec32(&zcntr->util_cntr.ref);
}

static void zhpe_cntr_progress(struct util_cntr *cntr)
{
	struct zhpe_cntr	*zcntr;
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_rx_ctx	*rx_ctx;
	struct zhpe_pe		*zpe;
	struct fid_list_entry	*fid_entry;

	zcntr = ucntr2zcntr(cntr);
	zpe = zcntr2zdom(zcntr)->pe;
	fastlock_acquire(&zcntr->list_lock);
	dlist_foreach_container(&zcntr->tx_list, struct fid_list_entry,
				fid_entry, entry) {
		tx_ctx = container_of(fid_entry->fid, struct zhpe_tx_ctx,
				      ctx.fid);
		zhpe_pe_progress_tx_ctx(zpe, tx_ctx);
	}

	dlist_foreach_container(&zcntr->rx_list, struct fid_list_entry,
				fid_entry, entry) {
		rx_ctx = container_of(fid_entry->fid, struct zhpe_rx_ctx,
				      ctx.fid);
		zhpe_pe_progress_rx_ctx(zpe, rx_ctx);
	}

	fastlock_release(&zcntr->list_lock);
}

static void zhpe_cntr_progress_dummy(struct util_cntr *cntr)
{
}

void zhpe_cntr_check_trigger_list(struct zhpe_cntr *zcntr)
{
	struct zhpe_trigger	*trigger;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;
	int			rc;
	size_t			count;

	fastlock_acquire(&zcntr->trigger_lock);
	count = zhpe_cntr_read(zcntr);
	dlist_foreach_safe(&zcntr->trigger_list, dentry, dnext) {
		trigger = container_of(dentry, struct zhpe_trigger, lentry);
		if (count < trigger->threshold.threshold)
			continue;

		switch (trigger->op_type) {

		case FI_OP_SEND:
			rc = zhpe_do_sendmsg(trigger->fid_ep,
					     &trigger->op.msg.msg,
					     trigger->flags, false);
			break;

		case FI_OP_RECV:
			rc = zhpe_do_recvmsg(trigger->fid_ep,
					     &trigger->op.msg.msg,
					     trigger->flags, false);
			break;

		case FI_OP_TSEND:
			rc = zhpe_do_sendmsg(trigger->fid_ep,
					     &trigger->op.tmsg.msg,
					     trigger->flags, true);
			break;

		case FI_OP_TRECV:
			rc = zhpe_do_recvmsg(trigger->fid_ep,
					     &trigger->op.tmsg.msg,
					     trigger->flags, true);
			break;

		case FI_OP_READ:
		case FI_OP_WRITE:
			rc = zhpe_do_rma_msg(trigger->fid_ep,
					     &trigger->op.rma.msg,
					     trigger->flags);
			break;

		case FI_OP_ATOMIC:
		case FI_OP_FETCH_ATOMIC:
		case FI_OP_COMPARE_ATOMIC:
			rc = zhpe_do_tx_atomic(
				trigger->fid_ep, &trigger->op.atomic.msg,
				trigger->op.atomic.comparev, NULL,
				trigger->op.atomic.compare_count,
				trigger->op.atomic.resultv, NULL,
				trigger->op.atomic.result_count,
				trigger->flags);
			break;

		default:
			ZHPE_LOG_ERROR("unsupported op\n");
			rc = 0;
			break;
		}
		if (rc == -FI_EAGAIN)
			break;

		dlist_remove(&trigger->lentry);
		free(trigger);
	}
	fastlock_release(&zcntr->trigger_lock);
}

static int zhpe_cntr_close(struct fid *fid)
{
	int			ret;
	struct zhpe_cntr	*zcntr;
	struct zhpe_trigger	*trigger;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;

	zcntr = fid2zcntr(fid);
	ret = ofi_cntr_cleanup(&zcntr->util_cntr);
	if (ret < 0)
		goto done;
	fastlock_acquire(&zcntr->trigger_lock);
	dlist_foreach_safe(&zcntr->trigger_list, dentry, dnext) {
		trigger = container_of(dentry, struct zhpe_trigger, lentry);
		dlist_remove(&trigger->lentry);
		free(trigger);
	}
	fastlock_release(&zcntr->trigger_lock);
	fastlock_destroy(&zcntr->trigger_lock);
	fastlock_destroy(&zcntr->list_lock);
	free(zcntr);
 done:

	return ret;
}

static int zhpe_cntr_control(struct fid *fid, int command, void *arg)
{
	struct util_cntr *cntr;

	cntr = &fid2zcntr(fid)->util_cntr;

	switch (command) {
	case FI_GETWAIT:
		if (!cntr->wait)
			return -FI_ENODATA;
		return fi_control(&cntr->wait->wait_fid.fid, FI_GETWAIT, arg);
	default:
		FI_INFO(&zhpe_prov, FI_LOG_CNTR, "Unsupported command\n");
		return -FI_ENOSYS;
	}
}

static struct fi_ops zhpe_cntr_fi_ops = {
	.size		= sizeof(struct fi_ops),
	.close		= zhpe_cntr_close,
	.bind		= fi_no_bind,
	.control	= zhpe_cntr_control,
	.ops_open	= fi_no_ops_open,
};

int zhpe_cntr_open(struct fid_domain *fid_domain, struct fi_cntr_attr *attr,
		   struct fid_cntr **fid_cntr, void *context)
{
	int			ret = -FI_EINVAL;
	struct zhpe_domain	*zdom = fid2zdom(&fid_domain->fid);
	struct zhpe_cntr	*zcntr = NULL;
	ofi_cntr_progress_func	progress;

	if (!fid_cntr)
		goto done;
	*fid_cntr = NULL;
	if (!fid_domain || !attr)
		goto done;

	zcntr = calloc(1, sizeof(*zcntr));
	if (!zcntr) {
		ret = -FI_ENOMEM;
		goto done;
	}
	fastlock_init(&zcntr->list_lock);
	fastlock_init(&zcntr->trigger_lock);

	if (zdom->util_domain.data_progress == FI_PROGRESS_AUTO)
		progress = zhpe_cntr_progress_dummy;
	else
		progress = zhpe_cntr_progress;

	ret = ofi_cntr_init(&zhpe_prov, fid_domain, attr, &zcntr->util_cntr,
			    progress, context);
	if (ret < 0)
		goto done;

	dlist_init(&zcntr->tx_list);
	dlist_init(&zcntr->rx_list);

	dlist_init(&zcntr->trigger_list);
	fastlock_init(&zcntr->trigger_lock);

	*fid_cntr = &zcntr->util_cntr.cntr_fid;
	(*fid_cntr)->fid.ops = &zhpe_cntr_fi_ops;
 done:
	if (ret < 0 && zcntr) {
		fastlock_destroy(&zcntr->list_lock);
		fastlock_destroy(&zcntr->trigger_lock);
		free(zcntr);
	}

	return ret;
}
