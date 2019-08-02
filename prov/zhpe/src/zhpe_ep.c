/*
 * Copyright (c) 2013-2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2017-2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

static void zhpe_tx_ctx_close(struct zhpe_tx_ctx *tx_ctx)
{
	if (tx_ctx->comp.send_cq)
		zhpe_cq_remove_tx_ctx(tx_ctx->comp.send_cq, tx_ctx);

	if (tx_ctx->comp.send_cntr)
		zhpe_cntr_remove_tx_ctx(tx_ctx->comp.send_cntr, tx_ctx);

	if (tx_ctx->comp.read_cntr)
		zhpe_cntr_remove_tx_ctx(tx_ctx->comp.read_cntr, tx_ctx);

	if (tx_ctx->comp.write_cntr)
		zhpe_cntr_remove_tx_ctx(tx_ctx->comp.write_cntr, tx_ctx);
}

static void zhpe_rx_ctx_close(struct zhpe_rx_ctx *rx_ctx)
{
	if (rx_ctx->comp.recv_cq)
		zhpe_cq_remove_rx_ctx(rx_ctx->comp.recv_cq, rx_ctx);

	if (rx_ctx->comp.recv_cntr)
		zhpe_cntr_remove_rx_ctx(rx_ctx->comp.recv_cntr, rx_ctx);

	if (rx_ctx->comp.rem_read_cntr)
		zhpe_cntr_remove_rx_ctx(rx_ctx->comp.rem_read_cntr, rx_ctx);

	if (rx_ctx->comp.rem_write_cntr)
		zhpe_cntr_remove_rx_ctx(rx_ctx->comp.rem_write_cntr, rx_ctx);
}

static int zhpe_ctx_close(struct fid *fid)
{
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	switch (fid->fclass) {

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct zhpe_tx_ctx, ctx.fid);
		zhpe_pe_remove_tx_ctx(tx_ctx);
		atm_dec(&tx_ctx->ep_attr->num_tx_ctx);
		atm_dec(&tx_ctx->domain->ref);
		zhpe_tx_ctx_close(tx_ctx);
		zhpe_tx_ctx_free(tx_ctx);
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);
		zhpe_pe_remove_rx_ctx(rx_ctx);
		atm_dec(&rx_ctx->ep_attr->num_rx_ctx);
		atm_dec(&rx_ctx->domain->ref);
		zhpe_rx_ctx_close(rx_ctx);
		zhpe_rx_ctx_free(rx_ctx);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}
	return 0;
}

static int zhpe_ctx_bind_cq(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct zhpe_cq *zhpe_cq;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	if ((flags | ZHPE_EP_CQ_FLAGS) != ZHPE_EP_CQ_FLAGS) {
		ZHPE_LOG_ERROR("Invalid cq flag\n");
		return -FI_EINVAL;
	}

	zhpe_cq = container_of(bfid, struct zhpe_cq, cq_fid.fid);

	switch (fid->fclass) {

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct zhpe_tx_ctx, ctx.fid);
		if (flags & FI_SEND) {
			tx_ctx->comp.send_cq = zhpe_cq;
			if (flags & FI_SELECTIVE_COMPLETION)
				tx_ctx->comp.send_cq_event = 1;
		}
		zhpe_cq_add_tx_ctx(zhpe_cq, tx_ctx);
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);
		if (flags & FI_RECV) {
			rx_ctx->comp.recv_cq = zhpe_cq;
			if (flags & FI_SELECTIVE_COMPLETION)
				rx_ctx->comp.recv_cq_event = 1;
		}

		zhpe_cq_add_rx_ctx(zhpe_cq, rx_ctx);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}

	return 0;
}

static int zhpe_ctx_bind_cntr(struct fid *fid, struct fid *bfid,
			      uint64_t flags)
{
	struct zhpe_cntr *cntr;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	if ((flags | ZHPE_EP_CNTR_FLAGS) != ZHPE_EP_CNTR_FLAGS) {
		ZHPE_LOG_ERROR("Invalid cntr flag\n");
		return -FI_EINVAL;
	}

	cntr = container_of(bfid, struct zhpe_cntr, cntr_fid.fid);

	switch (fid->fclass) {

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct zhpe_tx_ctx, ctx.fid);
		if (flags & FI_SEND) {
			tx_ctx->comp.send_cntr = cntr;
			zhpe_cntr_add_tx_ctx(cntr, tx_ctx);
		}

		if (flags & FI_READ) {
			tx_ctx->comp.read_cntr = cntr;
			zhpe_cntr_add_tx_ctx(cntr, tx_ctx);
		}

		if (flags & FI_WRITE) {
			tx_ctx->comp.write_cntr = cntr;
			zhpe_cntr_add_tx_ctx(cntr, tx_ctx);
		}
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);
		if (flags & FI_RECV) {
			rx_ctx->comp.recv_cntr = cntr;
			zhpe_cntr_add_rx_ctx(cntr, rx_ctx);
		}

		if (flags & FI_REMOTE_READ) {
			rx_ctx->comp.rem_read_cntr = cntr;
			zhpe_cntr_add_rx_ctx(cntr, rx_ctx);
		}

		if (flags & FI_REMOTE_WRITE) {
			rx_ctx->comp.rem_write_cntr = cntr;
			zhpe_cntr_add_rx_ctx(cntr, rx_ctx);
		}
		break;

	default:
		ZHPE_LOG_ERROR("Invalid fid\n");
		return -FI_EINVAL;
	}
	return 0;
}

static int zhpe_ctx_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	switch (bfid->fclass) {
	case FI_CLASS_CQ:
		return zhpe_ctx_bind_cq(fid, bfid, flags);

	case FI_CLASS_CNTR:
		return zhpe_ctx_bind_cntr(fid, bfid, flags);

	case FI_CLASS_MR:
		return 0;

	default:
		ZHPE_LOG_ERROR("Invalid bind()\n");
		return -FI_EINVAL;
	}

}

static int zhpe_ctx_enable(struct fid_ep *ep)
{
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	switch (ep->fid.fclass) {

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(ep, struct zhpe_rx_ctx, ctx);
		zhpe_pe_add_rx_ctx(rx_ctx);

		if (!rx_ctx->ep_attr->listener.listener_thread &&
		    zhpe_conn_listen(rx_ctx->ep_attr)) {
			ZHPE_LOG_ERROR("failed to create listener\n");
		}
		rx_ctx->enabled = 1;
		return 0;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_tx_ctx, ctx);
		zhpe_pe_add_tx_ctx(tx_ctx);

		if (!tx_ctx->ep_attr->listener.listener_thread &&
		    zhpe_conn_listen(tx_ctx->ep_attr)) {
			ZHPE_LOG_ERROR("failed to create listener\n");
		}
		tx_ctx->enabled = 1;
		return 0;

	default:
		ZHPE_LOG_ERROR("Invalid CTX\n");
		break;
	}
	return -FI_EINVAL;
}

int zhpe_getopflags(struct fi_tx_attr *tx_attr, struct fi_rx_attr *rx_attr,
			uint64_t *flags)
{
	if ((*flags & FI_TRANSMIT) && (*flags & FI_RECV)) {
		ZHPE_LOG_ERROR("Both Tx/Rx flags cannot be specified\n");
		return -FI_EINVAL;
	} else if (tx_attr && (*flags & FI_TRANSMIT)) {
		*flags = tx_attr->op_flags;
	} else if (rx_attr && (*flags & FI_RECV)) {
		*flags = rx_attr->op_flags;
	} else {
		ZHPE_LOG_ERROR("Tx/Rx flags not specified\n");
		return -FI_EINVAL;
	}
	return 0;
}

int zhpe_setopflags(struct fi_tx_attr *tx_attr, struct fi_rx_attr *rx_attr,
			uint64_t flags)
{
	if ((flags & FI_TRANSMIT) && (flags & FI_RECV)) {
		ZHPE_LOG_ERROR("Both Tx/Rx flags cannot be specified\n");
		return -FI_EINVAL;
	} else if (tx_attr && (flags & FI_TRANSMIT)) {
		tx_attr->op_flags = flags | (tx_attr->op_flags & FI_RMA_EVENT);
		tx_attr->op_flags &= ~FI_TRANSMIT;
		if (!(flags & ZHPE_MASK_COMPLETE))
			tx_attr->op_flags |= FI_TRANSMIT_COMPLETE;
	} else if (rx_attr && (flags & FI_RECV)) {
		rx_attr->op_flags = flags;
		rx_attr->op_flags &= ~FI_RECV;
	} else {
		ZHPE_LOG_ERROR("Tx/Rx flags not specified\n");
		return -FI_EINVAL;
	}
	return 0;
}

static int zhpe_ctx_control(struct fid *fid, int command, void *arg)
{
	struct fid_ep *ep;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;
	int ret;

	switch (fid->fclass) {

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(fid, struct zhpe_tx_ctx, ctx.fid);

		switch (command) {

		case FI_GETOPSFLAG:
			ret = zhpe_getopflags(&tx_ctx->attr, NULL,
					      (uint64_t *) arg);
			if (ret)
				return -EINVAL;
			break;

		case FI_SETOPSFLAG:
			ret = zhpe_setopflags(&tx_ctx->attr, NULL,
					      *(uint64_t *) arg);
			if (ret)
				return -EINVAL;
			break;

		case FI_ENABLE:
			ep = container_of(fid, struct fid_ep, fid);
			return zhpe_ctx_enable(ep);

		default:
			return -FI_ENOSYS;
		}
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);

		switch (command) {

		case FI_GETOPSFLAG:
			ret = zhpe_getopflags(NULL, &rx_ctx->attr,
					      (uint64_t *) arg);
			if (ret)
				return -EINVAL;
			break;
		case FI_SETOPSFLAG:
			ret = zhpe_setopflags(NULL, &rx_ctx->attr,
					      *(uint64_t *) arg);
			if (ret)
				return -EINVAL;
			break;
		case FI_ENABLE:
			ep = container_of(fid, struct fid_ep, fid);
			return zhpe_ctx_enable(ep);

		default:
			return -FI_ENOSYS;
		}
		break;

	default:
		return -FI_ENOSYS;
	}

	return 0;
}

static struct fi_ops zhpe_ctx_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_ctx_close,
	.bind = zhpe_ctx_bind,
	.control = zhpe_ctx_control,
	.ops_open = fi_no_ops_open,
};

static int zhpe_ctx_getopt(struct fid *fid, int level, int optname,
			   void *optval, size_t *optlen)
{
	struct zhpe_rx_ctx *rx_ctx;

	rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);
	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		if (*optlen < sizeof(size_t))
			return -FI_ETOOSMALL;
		*(size_t *)optval = rx_ctx->min_multi_recv;
		*optlen = sizeof(size_t);
		break;
	case FI_OPT_CM_DATA_SIZE:
		if (*optlen < sizeof(size_t))
			return -FI_ETOOSMALL;
		*((size_t *) optval) = ZHPE_EP_MAX_CM_DATA_SZ;
		*optlen = sizeof(size_t);
		break;
	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int zhpe_ctx_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	struct zhpe_rx_ctx *rx_ctx;
	rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		rx_ctx->min_multi_recv = *(size_t *)optval;
		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

static ssize_t zhpe_rx_ctx_cancel(struct zhpe_rx_ctx *rx_ctx, void *context)
{
	ssize_t			ret = -FI_ENOENT;
	struct zhpe_rx_entry	*rx_entry;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;

	/* Don't care if the locking may not be required.  */
	mutex_lock(&rx_ctx->mutex);
	dlist_foreach_safe(&rx_ctx->rx_posted_list, dentry, dnext) {
		rx_entry = container_of(dentry, struct zhpe_rx_entry, lentry);
		if (context != rx_entry->context)
			continue;

		ret = 0;
		dlist_remove(&rx_entry->lentry);
		dlist_insert_tail(&rx_entry->lentry, &rx_ctx->rx_work_list);
		rx_entry->buf = NULL;
		rx_entry->zhdr.flags = 0;
		zhpe_pe_rx_complete(rx_ctx, rx_entry, -FI_ECANCELED);
		break;
	}
	mutex_unlock(&rx_ctx->mutex);

 	return ret;
}

static ssize_t zhpe_ep_cancel(struct fid *fid, void *context)
{
	struct zhpe_rx_ctx *rx_ctx = NULL;
	struct zhpe_ep *zhpe_ep;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		rx_ctx = zhpe_ep->attr->rx_ctx;
		break;

	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(fid, struct zhpe_rx_ctx, ctx.fid);
		break;

	case FI_CLASS_TX_CTX:
		return -FI_ENOENT;

	default:
		ZHPE_LOG_ERROR("Invalid ep type\n");
		return -FI_EINVAL;
	}

	return zhpe_rx_ctx_cancel(rx_ctx, context);
}

static ssize_t zhpe_rx_size_left(struct fid_ep *ep)
{
	struct zhpe_ep *zhpe_ep;
	struct zhpe_rx_ctx *rx_ctx;

	switch (ep->fid.fclass) {
	case FI_CLASS_EP:
		zhpe_ep = container_of(ep, struct zhpe_ep, ep);
		rx_ctx = zhpe_ep->attr->rx_ctx;
		break;

	case FI_CLASS_RX_CTX:
	case FI_CLASS_SRX_CTX:
		rx_ctx = container_of(ep, struct zhpe_rx_ctx, ctx);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid EP type\n");
		return -FI_EINVAL;
	}

	return rx_ctx->enabled ? 1 : -FI_EOPBADSTATE;
}

static ssize_t zhpe_tx_size_left(struct fid_ep *ep)
{
	struct zhpe_ep *zhpe_ep;
	struct zhpe_tx_ctx *tx_ctx;

	switch (ep->fid.fclass) {

	case FI_CLASS_EP:
		zhpe_ep = container_of(ep, struct zhpe_ep, ep);
		tx_ctx = zhpe_ep->attr->tx_ctx;
		break;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_tx_ctx, ctx);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid EP type\n");
		return -FI_EINVAL;
	}

	return tx_ctx->enabled ? 1 : -FI_EOPBADSTATE;
}

struct fi_ops_ep zhpe_ctx_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = zhpe_ep_cancel,
	.getopt = zhpe_ctx_getopt,
	.setopt = zhpe_ctx_setopt,
	.tx_ctx = fi_no_tx_ctx,
	.rx_ctx = fi_no_rx_ctx,
	.rx_size_left = zhpe_rx_size_left,
	.tx_size_left = zhpe_tx_size_left,
};

static int zhpe_eq_fid_match(struct dlist_entry *entry, const void *arg)
{
	struct zhpe_eq_entry *zhpe_eq_entry;
	struct fi_eq_entry *eq_entry;
	fid_t fid = (fid_t)arg;

	zhpe_eq_entry = container_of(entry, struct zhpe_eq_entry, lentry);
	/* fi_eq_entry, fi_eq_cm_entry and fi_eq_err_entry all
	 * have fid_t as first member */
	eq_entry = (struct fi_eq_entry *)zhpe_eq_entry->event;
	return (fid == eq_entry->fid);
}

static void zhpe_ep_clear_eq_list(struct dlistfd_head *list,
				  struct fid_ep *ep_fid)
{
	struct dlist_entry *entry;

	while (!dlistfd_empty(list)) {
		entry = dlist_remove_first_match(&list->list,
						 zhpe_eq_fid_match, ep_fid);
		if (!entry)
			break;
		dlistfd_reset(list);
		free(container_of(entry, struct zhpe_eq_entry, lentry));
	}
}

static int zhpe_ep_close(struct fid *fid)
{
	struct zhpe_ep *zhpe_ep;
	char c = 0;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	case FI_CLASS_SEP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	default:
		return -FI_EINVAL;
	}

	if (zhpe_ep->is_alias) {
		atm_dec(&zhpe_ep->attr->ref);
		return 0;
	}
	if (atm_load_rlx(&zhpe_ep->attr->ref) ||
	    atm_load_rlx(&zhpe_ep->attr->num_rx_ctx) ||
	    atm_load_rlx(&zhpe_ep->attr->num_tx_ctx))
		return -FI_EBUSY;

	if (zhpe_ep->attr->ep_type == FI_EP_MSG) {
		zhpe_ep->attr->cm.do_listen = 0;
		if (ofi_write_socket(zhpe_ep->attr->cm.signal_fds[0], &c, 1)
		    != 1)
			ZHPE_LOG_DBG("Failed to signal\n");

		if (zhpe_ep->attr->cm.listener_thread &&
		    pthread_join(zhpe_ep->attr->cm.listener_thread, NULL)) {
			ZHPE_LOG_ERROR("pthread join failed (%d)\n", errno);
		}
		ofi_close_socket(zhpe_ep->attr->cm.signal_fds[0]);
		ofi_close_socket(zhpe_ep->attr->cm.signal_fds[1]);
	} else {
		if (zhpe_ep->attr->av)
			atm_dec(&zhpe_ep->attr->av->ref);
	}
	if (zhpe_ep->attr->av)
		fid_list_remove(&zhpe_ep->attr->av->ep_list,
				&zhpe_ep->attr->av->list_lock, &zhpe_ep->ep.fid);

	if (zhpe_ep->attr->listener.do_listen) {
		zhpe_ep->attr->listener.do_listen = 0;
		if (ofi_write_socket(zhpe_ep->attr->listener.signal_fds[0],
				     &c, 1) != 1)
			ZHPE_LOG_DBG("Failed to signal\n");

		if (zhpe_ep->attr->listener.listener_thread_valid &&
		     pthread_join(zhpe_ep->attr->listener.listener_thread,
				  NULL)) {
			ZHPE_LOG_ERROR("pthread join failed (%d)\n", errno);
		}

		ofi_close_socket(zhpe_ep->attr->listener.signal_fds[0]);
		ofi_close_socket(zhpe_ep->attr->listener.signal_fds[1]);
	}

	fastlock_destroy(&zhpe_ep->attr->cm.lock);

	if (zhpe_ep->attr->eq) {
		fastlock_acquire(&zhpe_ep->attr->eq->lock);
		zhpe_ep_clear_eq_list(&zhpe_ep->attr->eq->list,
				      &zhpe_ep->ep);
		/* Any err_data if present would be freed by
		 * zhpe_eq_clean_err_data_list when EQ is closed */
		zhpe_ep_clear_eq_list(&zhpe_ep->attr->eq->err_list,
				      &zhpe_ep->ep);
		fastlock_release(&zhpe_ep->attr->eq->lock);
	}

	if (zhpe_ep->attr->fclass != FI_CLASS_SEP) {
		zhpe_pe_remove_tx_ctx(zhpe_ep->attr->tx_array[0]);
		zhpe_tx_ctx_close(zhpe_ep->attr->tx_array[0]);
		zhpe_tx_ctx_free(zhpe_ep->attr->tx_array[0]);
		zhpe_pe_remove_rx_ctx(zhpe_ep->attr->rx_array[0]);
		zhpe_rx_ctx_close(zhpe_ep->attr->rx_array[0]);
		zhpe_rx_ctx_free(zhpe_ep->attr->rx_array[0]);
	}

	ofi_idm_reset(&zhpe_ep->attr->av_idm);
	zhpe_pe_remove_queue(zhpe_ep->attr->ztx);
	zhpe_conn_list_destroy(zhpe_ep->attr);
	zhpe_tx_put(zhpe_ep->attr->ztx);
	mutex_destroy(&zhpe_ep->attr->conn_mutex);
	cond_destroy(&zhpe_ep->attr->conn_cond);

	free(zhpe_ep->attr->tx_array);
	free(zhpe_ep->attr->rx_array);

	atm_dec(&zhpe_ep->attr->domain->ref);

	free(zhpe_ep->attr);
	free(zhpe_ep);

	return 0;
}

static int zhpe_ep_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	int ret;
	size_t i;
	struct zhpe_ep *ep;
	struct zhpe_eq *eq;
	struct zhpe_cq *cq;
	struct zhpe_av *av;
	struct zhpe_cntr *cntr;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	ret = ofi_ep_bind_valid(&zhpe_prov, bfid, flags);
	if (ret)
		return ret;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	case FI_CLASS_SEP:
		ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	default:
		return -FI_EINVAL;
	}

	switch (bfid->fclass) {
	case FI_CLASS_EQ:
		eq = container_of(bfid, struct zhpe_eq, eq.fid);
		ep->attr->eq = eq;
		break;

	case FI_CLASS_MR:
		return 0;

	case FI_CLASS_CQ:
		cq = container_of(bfid, struct zhpe_cq, cq_fid.fid);
		if (ep->attr->domain != cq->domain)
			return -FI_EINVAL;

		if (flags & FI_SEND) {
			for (i = 0; i < ep->attr->ep_attr.tx_ctx_cnt; i++) {
				tx_ctx = ep->attr->tx_array[i];

				if (!tx_ctx)
					continue;

				ret = zhpe_ctx_bind_cq(&tx_ctx->ctx.fid, bfid,
						       flags);
				if (ret)
					return ret;
			}
		}

		if (flags & FI_RECV) {
			for (i = 0; i < ep->attr->ep_attr.rx_ctx_cnt; i++) {
				rx_ctx = ep->attr->rx_array[i];

				if (!rx_ctx)
					continue;

				ret = zhpe_ctx_bind_cq(&rx_ctx->ctx.fid, bfid, flags);
				if (ret)
					return ret;
			}
		}
		break;

	case FI_CLASS_CNTR:
		cntr = container_of(bfid, struct zhpe_cntr, cntr_fid.fid);
		if (ep->attr->domain != cntr->domain)
			return -FI_EINVAL;

		if (flags & (FI_SEND | FI_WRITE | FI_READ)) {
			for (i = 0; i < ep->attr->ep_attr.tx_ctx_cnt; i++) {
				tx_ctx = ep->attr->tx_array[i];

				if (!tx_ctx)
					continue;

				ret = zhpe_ctx_bind_cntr(&tx_ctx->ctx.fid,
							 bfid, flags);
				if (ret)
					return ret;
			}
		}

		if (flags & (FI_RECV | FI_REMOTE_READ | FI_REMOTE_WRITE)) {
			for (i = 0; i < ep->attr->ep_attr.rx_ctx_cnt; i++) {
				rx_ctx = ep->attr->rx_array[i];

				if (!rx_ctx)
					continue;

				ret = zhpe_ctx_bind_cntr(&rx_ctx->ctx.fid,
							 bfid, flags);
				if (ret)
					return ret;
			}
		}
		break;

	case FI_CLASS_AV:
		av = container_of(bfid, struct zhpe_av, av_fid.fid);
		if (ep->attr->domain != av->domain)
			return -FI_EINVAL;

		ep->attr->av = av;
		atm_inc(&av->ref);

		for (i = 0; i < ep->attr->ep_attr.tx_ctx_cnt; i++) {
			if (ep->attr->tx_array[i])
				ep->attr->tx_array[i]->av = av;
		}

		for (i = 0; i < ep->attr->ep_attr.rx_ctx_cnt; i++) {
			if (ep->attr->rx_array[i])
				ep->attr->rx_array[i]->av = av;
		}
		ret = fid_list_insert(&av->ep_list, &av->list_lock,
				      &ep->ep.fid);
		if (ret) {
			ZHPE_LOG_ERROR("Error in adding fid in the EP list\n");
			return ret;
		}
		break;

	default:
		return -ENOSYS;
	}

	return 0;
}

static int zhpe_ep_control(struct fid *fid, int command, void *arg)
{
	int ret;
	struct fid_ep *ep_fid;
	struct fi_alias *alias;
	struct zhpe_ep *zhpe_ep, *new_ep;

	switch (fid->fclass) {
	case FI_CLASS_EP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	case FI_CLASS_SEP:
		zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);
		break;

	default:
		return -FI_EINVAL;
	}

	switch (command) {

	case FI_ALIAS:
		alias = (struct fi_alias *)arg;
		new_ep = calloc_cachealigned(1, sizeof(*new_ep));
		if (!new_ep)
			return -FI_ENOMEM;

		memcpy(&new_ep->tx_attr, &zhpe_ep->tx_attr,
		       sizeof(struct fi_tx_attr));
		memcpy(&new_ep->rx_attr, &zhpe_ep->rx_attr,
		       sizeof(struct fi_rx_attr));
		ret = zhpe_setopflags(&new_ep->tx_attr, &new_ep->rx_attr,
				       alias->flags);
		if (ret) {
			free(new_ep);
			return -FI_EINVAL;
		}
		new_ep->attr = zhpe_ep->attr;
		new_ep->is_alias = 1;
		memcpy(&new_ep->ep, &zhpe_ep->ep, sizeof(struct fid_ep));
		*alias->fid = &new_ep->ep.fid;
		atm_inc(&new_ep->attr->ref);
		break;

	case FI_GETOPSFLAG:
		ret = zhpe_getopflags(&zhpe_ep->tx_attr, &zhpe_ep->rx_attr,
				      (uint64_t *)arg);
		if (ret)
			return -EINVAL;
		break;

	case FI_SETOPSFLAG:
		ret = zhpe_setopflags(&zhpe_ep->tx_attr, &zhpe_ep->rx_attr,
				      *(uint64_t *)arg);
		if (ret)
			return -FI_EINVAL;
		break;

	case FI_ENABLE:
		ep_fid = container_of(fid, struct fid_ep, fid);
		return zhpe_ep_enable(ep_fid);

	default:
		return -FI_EINVAL;
	}

	return 0;
}


struct fi_ops zhpe_ep_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_ep_close,
	.bind = zhpe_ep_bind,
	.control = zhpe_ep_control,
	.ops_open = fi_no_ops_open,
};

int zhpe_ep_enable(struct fid_ep *ep)
{
	size_t i;
	struct zhpe_ep *zhpe_ep;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	zhpe_ep = container_of(ep, struct zhpe_ep, ep);
	for (i = 0; i < zhpe_ep->attr->ep_attr.tx_ctx_cnt; i++) {
		tx_ctx = zhpe_ep->attr->tx_array[i];
		if (tx_ctx) {
			tx_ctx->enabled = 1;
			zhpe_pe_add_tx_ctx(tx_ctx);
		}
	}

	for (i = 0; i < zhpe_ep->attr->ep_attr.rx_ctx_cnt; i++) {
		rx_ctx = zhpe_ep->attr->rx_array[i];
		if (rx_ctx) {
			rx_ctx->enabled = 1;
			zhpe_pe_add_rx_ctx(rx_ctx);
		}
	}

	if (zhpe_ep->attr->ep_type != FI_EP_MSG &&
	    !zhpe_ep->attr->listener.listener_thread_valid &&
	    zhpe_conn_listen(zhpe_ep->attr))
		ZHPE_LOG_ERROR("cannot start connection thread\n");
	zhpe_ep->attr->is_enabled = 1;
	return 0;
}

int zhpe_ep_disable(struct fid_ep *ep)
{
	size_t i;
	struct zhpe_ep *zhpe_ep;

	zhpe_ep = container_of(ep, struct zhpe_ep, ep);

	for (i = 0; i < zhpe_ep->attr->ep_attr.tx_ctx_cnt; i++) {
		if (zhpe_ep->attr->tx_array[i])
			zhpe_ep->attr->tx_array[i]->enabled = 0;
	}

	for (i = 0; i < zhpe_ep->attr->ep_attr.rx_ctx_cnt; i++) {
		if (zhpe_ep->attr->rx_array[i])
			zhpe_ep->attr->rx_array[i]->enabled = 0;
	}
	zhpe_ep->attr->is_enabled = 0;
	return 0;
}

static int zhpe_ep_getopt(fid_t fid, int level, int optname,
		       void *optval, size_t *optlen)
{
	struct zhpe_ep *zhpe_ep;
	zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:
		*(size_t *)optval = zhpe_ep->attr->min_multi_recv;
		*optlen = sizeof(size_t);
		break;

	case FI_OPT_CM_DATA_SIZE:
		if (*optlen < sizeof(size_t)) {
			*optlen = sizeof(size_t);
			return -FI_ETOOSMALL;
		}
		*((size_t *) optval) = ZHPE_EP_MAX_CM_DATA_SZ;
		*optlen = sizeof(size_t);
		break;

	default:
		return -FI_ENOPROTOOPT;
	}
	return 0;
}

static int zhpe_ep_setopt(fid_t fid, int level, int optname,
		       const void *optval, size_t optlen)
{
	size_t i;
	struct zhpe_ep *zhpe_ep;
	zhpe_ep = container_of(fid, struct zhpe_ep, ep.fid);

	if (level != FI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	switch (optname) {
	case FI_OPT_MIN_MULTI_RECV:

		zhpe_ep->attr->min_multi_recv = *(size_t *)optval;
		for (i = 0; i < zhpe_ep->attr->ep_attr.rx_ctx_cnt; i++) {
			if (zhpe_ep->attr->rx_array[i] != NULL) {
				zhpe_ep->attr->rx_array[i]->min_multi_recv =
					zhpe_ep->attr->min_multi_recv;
			}
		}
		break;

	default:
		return -ENOPROTOOPT;
	}
	return 0;
}

static int zhpe_ep_tx_ctx(struct fid_ep *ep, int index,
			  struct fi_tx_attr *attr,
			  struct fid_ep **tx_ep, void *context)
{
	struct zhpe_ep *zhpe_ep;
	struct zhpe_tx_ctx *tx_ctx;

	zhpe_ep = container_of(ep, struct zhpe_ep, ep);
	if (zhpe_ep->attr->fclass != FI_CLASS_SEP ||
		index >= (int)zhpe_ep->attr->ep_attr.tx_ctx_cnt)
		return -FI_EINVAL;

	if (attr) {
		if (ofi_check_tx_attr(&zhpe_prov, &zhpe_ep->tx_attr, attr, 0))
			return -FI_ENODATA;
		tx_ctx = zhpe_tx_ctx_alloc(attr, context);
	} else {
		tx_ctx = zhpe_tx_ctx_alloc(&zhpe_ep->tx_attr, context);
	}
	if (!tx_ctx)
		return -FI_ENOMEM;

	tx_ctx->tx_id = index;
	tx_ctx->ep_attr = zhpe_ep->attr;
	tx_ctx->domain = zhpe_ep->attr->domain;
	tx_ctx->av = zhpe_ep->attr->av;

	tx_ctx->ctx.fid.ops = &zhpe_ctx_ops;
	tx_ctx->ctx.ops = &zhpe_ctx_ep_ops;
	if (zhpe_needs_locking(zhpe_ep->attr->domain)) {
		tx_ctx->ctx.msg = &zhpe_ep_msg_ops_locked;
		tx_ctx->ctx.tagged = &zhpe_ep_tagged_locked;
		tx_ctx->ctx.rma = &zhpe_ep_rma;
		tx_ctx->ctx.atomic = &zhpe_ep_atomic;
	} else {
		tx_ctx->ctx.msg = &zhpe_ep_msg_ops_unlocked;
		tx_ctx->ctx.tagged = &zhpe_ep_tagged_unlocked;
		tx_ctx->ctx.rma = &zhpe_ep_rma;
		tx_ctx->ctx.atomic = &zhpe_ep_atomic;
	}

	*tx_ep = &tx_ctx->ctx;
	zhpe_ep->attr->tx_array[index] = tx_ctx;
	atm_inc(&zhpe_ep->attr->num_tx_ctx);
	atm_inc(&zhpe_ep->attr->domain->ref);
	return 0;
}

static int zhpe_ep_rx_ctx(struct fid_ep *ep, int index,
			  struct fi_rx_attr *attr,
			  struct fid_ep **rx_ep, void *context)
{
	struct zhpe_ep *zhpe_ep;
	struct zhpe_rx_ctx *rx_ctx;

	zhpe_ep = container_of(ep, struct zhpe_ep, ep);
	if (zhpe_ep->attr->fclass != FI_CLASS_SEP ||
		index >= (int)zhpe_ep->attr->ep_attr.rx_ctx_cnt)
		return -FI_EINVAL;

	if (attr) {
		if (ofi_check_rx_attr(&zhpe_prov, &zhpe_ep->attr->info,
				      attr, 0))
			return -FI_ENODATA;
		rx_ctx = zhpe_rx_ctx_alloc(attr, context,
					   zhpe_ep->attr->domain);
	} else {
		rx_ctx = zhpe_rx_ctx_alloc(&zhpe_ep->rx_attr, context,
					   zhpe_ep->attr->domain);
	}
	if (!rx_ctx)
		return -FI_ENOMEM;

	rx_ctx->rx_id = index;
	rx_ctx->ep_attr = zhpe_ep->attr;
	rx_ctx->av = zhpe_ep->attr->av;
	rx_ctx->ctx.fid.ops = &zhpe_ctx_ops;
	rx_ctx->ctx.ops = &zhpe_ctx_ep_ops;
	if (zhpe_needs_locking(zhpe_ep->attr->domain)) {
		rx_ctx->ctx.msg = &zhpe_ep_msg_ops_locked;
		rx_ctx->ctx.tagged = &zhpe_ep_tagged_locked;
	} else {
		rx_ctx->ctx.msg = &zhpe_ep_msg_ops_unlocked;
		rx_ctx->ctx.tagged = &zhpe_ep_tagged_unlocked;
	}

	rx_ctx->min_multi_recv = zhpe_ep->attr->min_multi_recv;
	*rx_ep = &rx_ctx->ctx;
	zhpe_ep->attr->rx_array[index] = rx_ctx;
	atm_inc(&zhpe_ep->attr->num_rx_ctx);
	atm_inc(&zhpe_ep->attr->domain->ref);

	return 0;
}

struct fi_ops_ep zhpe_ep_ops = {
	.size = sizeof(struct fi_ops_ep),
	.cancel = zhpe_ep_cancel,
	.getopt = zhpe_ep_getopt,
	.setopt = zhpe_ep_setopt,
	.tx_ctx = zhpe_ep_tx_ctx,
	.rx_ctx = zhpe_ep_rx_ctx,
	.rx_size_left = zhpe_rx_size_left,
	.tx_size_left = zhpe_tx_size_left,
};

static void zhpe_set_fabric_attr(void *src_addr,
				 const struct fi_fabric_attr *hint_attr,
				 struct fi_fabric_attr *attr)
{
	struct zhpe_fabric *fabric;

	*attr = zhpe_fabric_attr;
	if (hint_attr && hint_attr->fabric) {
		attr->fabric = hint_attr->fabric;
	} else {
		fabric = zhpe_fab_list_head();
		attr->fabric = fabric ? &fabric->fab_fid : NULL;
	}

	attr->name = strdup(zhpe_fab_name);
	attr->prov_name = NULL;
}

static void zhpe_set_domain_attr(uint32_t api_version, void *src_addr,
				 const struct fi_domain_attr *hint_attr,
				 struct fi_info *info)
{
	struct fi_domain_attr	*attr = info->domain_attr;
	struct zhpe_domain *domain;

	domain = zhpe_dom_list_head();
	attr->domain = domain ? &domain->util_domain.domain_fid : NULL;
	if (!hint_attr) {
		*attr = zhpe_domain_attr;
		if (FI_VERSION_LT(api_version, FI_VERSION(1, 5)))
			attr->mr_mode = FI_MR_BASIC;
		else
			attr->mr_mode |= FI_MR_LOCAL;
		goto out;
	}

	if (hint_attr->domain) {
		domain = container_of(hint_attr->domain,
				      struct zhpe_domain,
				      util_domain.domain_fid);
		*attr = domain->attr;
		attr->domain = hint_attr->domain;
		goto out;
	}

	*attr = *hint_attr;
	if (FI_VERSION_LT(api_version, FI_VERSION(1, 5)))
		attr->mr_mode = FI_MR_BASIC;
	else if (attr->mr_mode != FI_MR_BASIC)
		attr->mr_mode &= (OFI_MR_BASIC_MAP | FI_MR_LOCAL);

	if (!attr->caps)
		attr->caps = zhpe_domain_attr.caps;

	attr->mode &= zhpe_domain_attr.mode;

	if (attr->threading == FI_THREAD_UNSPEC)
		attr->threading = zhpe_domain_attr.threading;
	if (attr->control_progress == FI_PROGRESS_UNSPEC)
		attr->control_progress = zhpe_domain_attr.control_progress;
	if (attr->data_progress == FI_PROGRESS_UNSPEC)
		attr->data_progress = zhpe_domain_attr.data_progress;

	if (attr->cq_cnt == 0)
		attr->cq_cnt = zhpe_domain_attr.cq_cnt;
	if (attr->ep_cnt == 0)
		attr->ep_cnt = zhpe_domain_attr.ep_cnt;
	if (attr->tx_ctx_cnt == 0)
		attr->tx_ctx_cnt = zhpe_domain_attr.tx_ctx_cnt;
	if (attr->rx_ctx_cnt == 0)
		attr->rx_ctx_cnt = zhpe_domain_attr.rx_ctx_cnt;
	if (attr->max_ep_tx_ctx == 0)
		attr->max_ep_tx_ctx = zhpe_domain_attr.max_ep_tx_ctx;
	if (attr->max_ep_rx_ctx == 0)
		attr->max_ep_rx_ctx = zhpe_domain_attr.max_ep_rx_ctx;
	if (attr->cntr_cnt == 0)
		attr->cntr_cnt = zhpe_domain_attr.cntr_cnt;
	if (attr->mr_iov_limit == 0)
		attr->mr_iov_limit = zhpe_domain_attr.mr_iov_limit;

	attr->mr_key_size = zhpe_domain_attr.mr_key_size;
	attr->cq_data_size = zhpe_domain_attr.cq_data_size;
	attr->resource_mgmt = zhpe_domain_attr.resource_mgmt;
out:
	/* reverse lookup interface from node and assign it as domain name */
	attr->name = strdup(zhpe_fab_name);
}

#define SET_EQUAL(_ptrname, _field)					\
do {									\
	info->_ptrname->_field = _ptrname->_field;			\
} while (0)

#define CHECK_SET_EQUAL(_ptrname, _field, _value)			\
do {									\
	if (info->_ptrname->_field == _value)				\
		SET_EQUAL(_ptrname, _field);				\
} while (0)

struct fi_info *zhpe_fi_info(uint32_t version,
			     const struct fi_info *hints,
			     const union sockaddr_in46 *src_addr,
			     const union sockaddr_in46 *dest_addr,
			     uint64_t caps, uint64_t mode,
			     const struct fi_ep_attr *ep_attr,
			     const struct fi_tx_attr *tx_attr,
			     const struct fi_rx_attr *rx_attr)
{
	struct fi_info		*info;


	info = fi_allocinfo();
	if (!info)
		return NULL;

	if (src_addr) {
		info->src_addrlen = sockaddr_len(src_addr);
		info->src_addr = sockaddr_dup(src_addr);
		if (!info->src_addr)
			goto err;
	}

	if (dest_addr) {
		info->dest_addrlen = sockaddr_len(dest_addr);
		info->dest_addr = sockaddr_dup(dest_addr);
		if (!info->dest_addr)
			goto err;
	}

	if (hints) {
		info->mode = hints->mode;
		if (hints->addr_format == FI_SOCKADDR_IN6)
			info->addr_format = FI_SOCKADDR_IN6;
		else
			info->addr_format = FI_SOCKADDR_IN;

		if (hints->caps)
			info->caps = hints->caps;

		if (hints->ep_attr)
			*info->ep_attr = *hints->ep_attr;

		SET_EQUAL(ep_attr, type);
		if (info->ep_attr->protocol == FI_PROTO_UNSPEC) {
			SET_EQUAL(ep_attr, protocol);
			SET_EQUAL(ep_attr, protocol_version);
		}
		CHECK_SET_EQUAL(ep_attr, max_msg_size, 0);
		CHECK_SET_EQUAL(ep_attr, msg_prefix_size, 0);
		CHECK_SET_EQUAL(ep_attr, max_order_raw_size, 0);
		CHECK_SET_EQUAL(ep_attr, max_order_war_size, 0);
		CHECK_SET_EQUAL(ep_attr, max_order_waw_size, 0);
		CHECK_SET_EQUAL(ep_attr, mem_tag_format, 0);
		CHECK_SET_EQUAL(ep_attr, tx_ctx_cnt, 0);
		CHECK_SET_EQUAL(ep_attr, rx_ctx_cnt, 0);
		CHECK_SET_EQUAL(ep_attr, auth_key_size, 0);
		CHECK_SET_EQUAL(ep_attr, auth_key, NULL);

		if (hints->tx_attr)
			*info->tx_attr = *hints->tx_attr;

		CHECK_SET_EQUAL(tx_attr, op_flags, 0);
		CHECK_SET_EQUAL(tx_attr, msg_order, FI_ORDER_NONE);
		CHECK_SET_EQUAL(tx_attr, comp_order, FI_ORDER_NONE);
		CHECK_SET_EQUAL(tx_attr, inject_size, 0);
		CHECK_SET_EQUAL(tx_attr, size, 0);
		CHECK_SET_EQUAL(tx_attr, iov_limit, 0);
		CHECK_SET_EQUAL(tx_attr, rma_iov_limit, 0);

		if (hints->rx_attr)
			*info->rx_attr = *hints->rx_attr;

		CHECK_SET_EQUAL(rx_attr, op_flags, 0);
		CHECK_SET_EQUAL(rx_attr, msg_order, FI_ORDER_NONE);
		CHECK_SET_EQUAL(rx_attr, comp_order, FI_ORDER_NONE);
		CHECK_SET_EQUAL(rx_attr, total_buffered_recv, 0);
		CHECK_SET_EQUAL(rx_attr, size, 0);
		CHECK_SET_EQUAL(rx_attr, iov_limit, 0);

		if (hints->handle)
			info->handle = hints->handle;

		zhpe_set_domain_attr(version, info->src_addr,
				     hints->domain_attr, info);
		zhpe_set_fabric_attr(info->src_addr, hints->fabric_attr,
				     info->fabric_attr);

	} else {
		info->mode = mode;
		zhpe_set_domain_attr(version, info->src_addr, NULL, info);
		zhpe_set_fabric_attr(info->src_addr, NULL, info->fabric_attr);
		*info->ep_attr = *ep_attr;
		*info->tx_attr = *tx_attr;
		*info->rx_attr = *rx_attr;
	}

	info->caps |= info->tx_attr->caps | info->rx_attr->caps;
	if (!info->caps)
		info->caps = caps;
	if (!info->tx_attr->caps)
		info->tx_attr->caps = info->caps;
	if (!info->rx_attr->caps)
		info->rx_attr->caps = info->caps;

	info->mode |= info->tx_attr->mode | info->rx_attr->mode;
	if (FI_VERSION_LT(version, FI_VERSION(1, 5)))
		mode |= FI_LOCAL_MR;
	info->mode &= mode;
	if (!info->tx_attr->mode)
		info->tx_attr->mode = info->mode;
	if (!info->rx_attr->mode)
		info->rx_attr->mode = info->mode;

	return info;
err:
	fi_freeinfo(info);
	return NULL;
}

int zhpe_alloc_endpoint(struct fid_domain *domain, struct fi_info *info,
		  struct zhpe_ep **ep, void *context, size_t fclass)
{
	int ret;
	struct zhpe_ep *zhpe_ep;
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;
	struct zhpe_domain *zhpe_dom;

	zhpe_dom = container_of(domain, struct zhpe_domain,
				util_domain.domain_fid);
	if (info) {
		ret = zhpe_verify_info(zhpe_dom->fab->fab_fid.api_version,
				       info, 0);
		if (ret) {
			ZHPE_LOG_DBG("Cannot support requested options!\n");
			return -FI_EINVAL;
		}
	}

	zhpe_ep = calloc_cachealigned(1, sizeof(*zhpe_ep));
	if (!zhpe_ep)
		return -FI_ENOMEM;

	switch (fclass) {
	case FI_CLASS_EP:
		zhpe_ep->ep.fid.fclass = FI_CLASS_EP;
		zhpe_ep->ep.fid.context = context;
		zhpe_ep->ep.fid.ops = &zhpe_ep_fi_ops;

		zhpe_ep->ep.ops = &zhpe_ep_ops;
		zhpe_ep->ep.cm = &zhpe_ep_cm_ops;
		if (zhpe_needs_locking(zhpe_dom)) {
			zhpe_ep->ep.msg = &zhpe_ep_msg_ops_locked;
			zhpe_ep->ep.tagged = &zhpe_ep_tagged_locked;
			zhpe_ep->ep.rma = &zhpe_ep_rma;
			zhpe_ep->ep.atomic = &zhpe_ep_atomic;
		} else {
			zhpe_ep->ep.msg = &zhpe_ep_msg_ops_unlocked;
			zhpe_ep->ep.tagged = &zhpe_ep_tagged_unlocked;
			zhpe_ep->ep.rma = &zhpe_ep_rma;
			zhpe_ep->ep.atomic = &zhpe_ep_atomic;
		}
		break;

	case FI_CLASS_SEP:
		zhpe_ep->ep.fid.fclass = FI_CLASS_SEP;
		zhpe_ep->ep.fid.context = context;
		zhpe_ep->ep.fid.ops = &zhpe_ep_fi_ops;

		zhpe_ep->ep.ops = &zhpe_ep_ops;
		zhpe_ep->ep.cm = &zhpe_ep_cm_ops;
		break;

	default:
		ret = -FI_EINVAL;
		goto err1;
	}

	zhpe_ep->attr = calloc_cachealigned(1, sizeof(*zhpe_ep->attr));
	if (!zhpe_ep->attr) {
		ret = -FI_ENOMEM;
		goto err1;
	}
	zhpe_ep->attr->fclass = fclass;
	zhpe_ep->attr->ep = zhpe_ep;
	mutex_init(&zhpe_ep->attr->conn_mutex, NULL);
	cond_init(&zhpe_ep->attr->conn_cond, NULL);
	dlist_init(&zhpe_ep->attr->conn_list);
	*ep = zhpe_ep;

	if (info) {
		zhpe_ep->attr->info.caps = info->caps;
		zhpe_ep->attr->info.addr_format = info->addr_format;

		if (info->ep_attr) {
			zhpe_ep->attr->ep_type = info->ep_attr->type;
			zhpe_ep->attr->ep_attr.tx_ctx_cnt =
				info->ep_attr->tx_ctx_cnt;
			zhpe_ep->attr->ep_attr.rx_ctx_cnt =
				info->ep_attr->rx_ctx_cnt;
		}

		if (info->src_addr)
			sockaddr_cpy(&zhpe_ep->attr->src_addr, info->src_addr);

		if (info->dest_addr)
			sockaddr_cpy(&zhpe_ep->attr->dest_addr,
				     info->dest_addr);

		if (info->tx_attr) {
			zhpe_ep->tx_attr = *info->tx_attr;
			zhpe_ep->tx_attr.op_flags |=
				(info->caps & FI_RMA_EVENT);
			zhpe_ep->tx_attr.size = zhpe_ep->tx_attr.size ?
				zhpe_ep->tx_attr.size : ZHPE_EP_TX_SZ;
		}

		if (info->rx_attr)
			zhpe_ep->rx_attr = *info->rx_attr;
		zhpe_ep->attr->info.handle = info->handle;
	}

	if (zhpe_ep->attr->fclass != FI_CLASS_SEP) {
		zhpe_ep->attr->ep_attr.tx_ctx_cnt = 1;
		zhpe_ep->attr->ep_attr.rx_ctx_cnt = 1;
	}

	zhpe_ep->attr->tx_array = calloc(zhpe_ep->attr->ep_attr.tx_ctx_cnt,
				   sizeof(struct zhpe_tx_ctx *));
	if (!zhpe_ep->attr->tx_array) {
		ret = -FI_ENOMEM;
		goto err2;
	}

	zhpe_ep->attr->rx_array = calloc(zhpe_ep->attr->ep_attr.rx_ctx_cnt,
				   sizeof(struct zhpe_rx_ctx *));
	if (!zhpe_ep->attr->rx_array) {
		ret = -FI_ENOMEM;
		goto err2;
	}

	if (zhpe_ep->attr->fclass != FI_CLASS_SEP) {
		/* default tx ctx */
		tx_ctx = zhpe_tx_ctx_alloc(&zhpe_ep->tx_attr, context);
		if (!tx_ctx) {
			ret = -FI_ENOMEM;
			goto err2;
		}
		tx_ctx->ep_attr = zhpe_ep->attr;
		tx_ctx->domain = zhpe_dom;
		tx_ctx->tx_id = 0;
		zhpe_ep->attr->tx_array[0] = tx_ctx;
		zhpe_ep->attr->tx_ctx = tx_ctx;

		/* default rx_ctx */
		rx_ctx = zhpe_rx_ctx_alloc(&zhpe_ep->rx_attr, context,
					   zhpe_dom);
		if (!rx_ctx) {
			ret = -FI_ENOMEM;
			goto err2;
		}
		rx_ctx->ep_attr = zhpe_ep->attr;
		rx_ctx->rx_id = 0;
		zhpe_ep->attr->rx_array[0] = rx_ctx;
		zhpe_ep->attr->rx_ctx = rx_ctx;
	}

	/* default config */
	zhpe_ep->attr->min_multi_recv = ZHPE_EP_MIN_MULTI_RECV;

	if (info)
		memcpy(&zhpe_ep->attr->info, info, sizeof(struct fi_info));

	zhpe_ep->attr->domain = zhpe_dom;
	fastlock_init(&zhpe_ep->attr->cm.lock);
	if (zhpe_ep->attr->ep_type == FI_EP_MSG) {
		dlist_init(&zhpe_ep->attr->cm.msg_list);
		if (socketpair(AF_UNIX, SOCK_STREAM, 0,
			       zhpe_ep->attr->cm.signal_fds) < 0) {
			ret = -FI_EINVAL;
			goto err2;
		}

		if (fi_fd_nonblock(zhpe_ep->attr->cm.signal_fds[1]))
			ZHPE_LOG_ERROR("fi_fd_nonblock failed");
	}

	atm_inc(&zhpe_dom->ref);

	return 0;

err2:
	free(zhpe_ep->attr);
err1:
	free(zhpe_ep);
	return ret;
}

static int zhpe_ep_lookup_conn(struct zhpe_ep_attr *ep_attr, fi_addr_t fi_addr,
			       struct zhpe_conn **pconn)
{
	int			ret;
	bool			first = true;
	size_t			av_index = ((ep_attr->ep_type == FI_EP_MSG) ?
					    0 : (fi_addr & ep_attr->av->mask));
	struct zhpe_conn	*conn;
	union sockaddr_in46	addr;
	bool			rem_local;

	for (;;) {
		conn = ofi_idm_lookup(&ep_attr->av_idm, av_index);
		if (conn) {
			/* Only in av_idm if conn fully ready. */
			ret = 0;
			break;
		}
		if (first) {
			if (ep_attr->ep_type == FI_EP_MSG) {
				sockaddr_cpy(&addr, &ep_attr->dest_addr);
				addr.sin_port = htons(ep_attr->msg_dest_port);
			} else {
				ret = zhpe_av_get_addr(ep_attr->av, av_index,
						       &addr);
				if (ret < 0)
					break;
			}

			ret = zhpe_checklocaladdr(NULL, &addr);
			if (ret < 0)
				break;
			rem_local = !!ret;
			first = false;
		}

		/* Need locking until we do away with the listener thread */
		mutex_lock(&ep_attr->conn_mutex);
		conn = ofi_idm_lookup(&ep_attr->av_idm, av_index);
		if (conn) {
			mutex_unlock(&ep_attr->conn_mutex);
			ret = 0;
			break;
		}
		conn = zhpe_conn_lookup(ep_attr, &addr, rem_local);
		if (!conn) {
			ret = 1;
			conn = zhpe_conn_insert(ep_attr, &addr, rem_local);
			if (!conn)
				ret = -FI_ENOMEM;
			conn->fi_addr = fi_addr;
			mutex_unlock(&ep_attr->conn_mutex);
			break;
		}
		if (conn->state != ZHPE_CONN_STATE_READY) {
			cond_wait(&ep_attr->conn_cond, &ep_attr->conn_mutex);
			mutex_unlock(&ep_attr->conn_mutex);
			continue;
		}
		if (conn->fi_addr != FI_ADDR_NOTAVAIL &&
		    conn->fi_addr != fi_addr)
			ret = -EEXIST;
		conn->fi_addr = fi_addr;
		/* An error here should be noted, but not be fatal. */
		if (ret >= 0 &&
		    ofi_idm_set(&ep_attr->av_idm, av_index, conn) == -1) {
			ret = -errno;
			ZHPE_LOG_ERROR("ofi_idm_set() failed, error %d\n", ret);
		}
		mutex_unlock(&ep_attr->conn_mutex);
		ret = 0;
		break;
	}
	*pconn = (ret < 0 ? NULL : conn);

	return ret;
}

int zhpe_ep_get_conn(struct zhpe_ep_attr *attr,
		     fi_addr_t fi_addr, struct zhpe_conn **pconn)
{
	int			ret = 0;

	for (;;) {
		ret = 0;
		ret = zhpe_ep_lookup_conn(attr, fi_addr, pconn);
		if (ret <= 0)
			break;
		ret = zhpe_ep_connect(attr, *pconn);
		if (ret >= 0)
			continue;
		if (*pconn)
			zhpe_conn_release_entry(attr, *pconn);
		if (ret != -FI_EAGAIN)
			break;
	}

	return ret;
}
