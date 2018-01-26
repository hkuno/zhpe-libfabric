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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

static inline ssize_t do_rma_msg(struct fid_ep *ep,
				 const struct fi_msg_rma *msg,
				 uint64_t flags)
{
	int64_t			ret = -FI_EINVAL;
	int64_t			tindex = -1;
	struct zhpe_pe_entry	*pe_entry;
	size_t			i;
	size_t			j;
	struct zhpe_conn	*conn;
	struct zhpe_tx_ctx	*tx_ctx;
	uint64_t		rma_len;
	uint64_t		op_flags;
	struct zhpe_ep		*zhpe_ep;
	struct zhpe_ep_attr	*ep_attr;
	struct zhpe_mr		*zmr;
	struct zhpe_msg_hdr	ohdr;

	switch (ep->fid.fclass) {

	case FI_CLASS_EP:
		zhpe_ep = container_of(ep, struct zhpe_ep, ep);
		tx_ctx = zhpe_ep->attr->tx_ctx->use_shared ?
			zhpe_ep->attr->tx_ctx->stx_ctx : zhpe_ep->attr->tx_ctx;
		ep_attr = zhpe_ep->attr;
		op_flags = zhpe_ep->tx_attr.op_flags;
		break;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_tx_ctx, fid.ctx);
		ep_attr = tx_ctx->ep_attr;
		op_flags = tx_ctx->attr.op_flags;
		break;

	default:
		ZHPE_LOG_ERROR("Invalid EP type\n");
		goto done;
	}

	if (!tx_ctx->enabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	if (msg->iov_count > ZHPE_EP_MAX_IOV_LIMIT)
		goto done;

	if (msg->rma_iov_count > ZHPE_EP_MAX_IOV_LIMIT)
		goto done;

	if (likely(!(flags & ZHPE_TRIGGERED_OP))) {
		switch (flags & (FI_READ | FI_WRITE)) {

		case FI_READ:
			if (flags &
			    ~(ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS |
			      FI_COMPLETION | FI_TRIGGER |
			      FI_FENCE | FI_RMA | FI_READ))
				goto done;
			if (op_flags & FI_RMA_EVENT)
				flags |= FI_REMOTE_READ;
			break;

		case FI_WRITE:
			if (flags &
			    ~(ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS |
			      FI_COMPLETION | FI_TRIGGER |
			      FI_FENCE | FI_RMA | FI_WRITE |
			      FI_INJECT | FI_INJECT_COMPLETE |
			      FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |
			      FI_REMOTE_CQ_DATA))
				goto done;
			if (op_flags & FI_RMA_EVENT)
				flags |= FI_REMOTE_WRITE;
			break;

		default:
			goto done;
		}

		if (flags & ZHPE_USE_OP_FLAGS)
			flags |= op_flags;

		flags = zhpe_tx_fixup_completion(flags);
	}

	if (flags & FI_TRIGGER) {
		ret = zhpe_queue_rma_op(ep, msg, flags,
					((flags & FI_READ) ?
					 FI_OP_READ : FI_OP_WRITE));
		if (ret != 1)
			goto done;
	}

 	ret = zhpe_ep_get_conn(ep_attr, msg->addr, &conn);
	if (ret < 0)
		goto done;

	ret = zhpe_tx_reserve(conn->ztx, 0);
	if (ret < 0)
		goto done;
	tindex = ret;
	pe_entry = &conn->ztx->pentries[tindex];
	pe_entry->pe_root.handler = zhpe_pe_tx_handle_rma;
	pe_entry->pe_root.conn = conn;
	pe_entry->pe_root.context = msg->context;
	pe_entry->pe_root.status = 0;
	pe_entry->pe_root.completions = 0;
	pe_entry->pe_root.flags = ZHPE_PE_NO_RINDEX;
	pe_entry->cq_data = msg->data;
	pe_entry->rx_id = zhpe_get_rx_id(tx_ctx, msg->addr);

	pe_entry->rma.lstate.viov = pe_entry->rma.liov;
	pe_entry->rma.lstate.off = 0;
	pe_entry->rma.lstate.idx = 0;

	pe_entry->rem = 0;
	for (i = 0, j = 0; i < msg->iov_count; i++) {
		if (!msg->msg_iov[i].iov_len)
			continue;
		pe_entry->rma.liov[j].iov_base = msg->msg_iov[i].iov_base;
		pe_entry->rma.liov[j].iov_len = msg->msg_iov[i].iov_len;
		pe_entry->rem += msg->msg_iov[i].iov_len;
		if (msg->desc && (zmr = msg->desc[i])) {
			pe_entry->rma.liov[j].iov_desc = zmr;
			ret = zhpeq_lcl_key_access(
				zmr->kdata, pe_entry->rma.liov[j].iov_base,
				pe_entry->rma.liov[j].iov_len,
				((flags & FI_READ) ?
				 ZHPEQ_MR_GET : ZHPEQ_MR_PUT),
				&pe_entry->rma.liov[j].iov_zaddr);
			if (ret < 0)
				goto done;
		} else
			pe_entry->rma.liov[j].iov_desc = NULL;
		j++;
		pe_entry->rma.lstate.cnt = j;
	}
	if (pe_entry->rem <= ZHPEQ_IMM_MAX)
		flags |= FI_INJECT;
	else
		ret = zhpe_mr_reg_int_oneshot(ep_attr->domain,
					      pe_entry->rma.liov,
					      pe_entry->rem, FI_WRITE);
	if (ret < 0)
		goto done;
	pe_entry->zstate.viov = pe_entry->ziov;
	pe_entry->zstate.off = 0;
	pe_entry->zstate.idx = 0;

	rma_len = 0;
	for (i = 0, j = 0; i < msg->rma_iov_count; i++) {
		if (!msg->rma_iov[i].len)
			continue;
		pe_entry->ziov[j].iov_addr = msg->rma_iov[i].addr;
		pe_entry->ziov[j].iov_len = msg->rma_iov[i].len;
		rma_len += msg->rma_iov[i].len;
		pe_entry->ziov[j].iov_key = msg->rma_iov[i].key;
		pe_entry->rkeys[j] =
			zhpe_conn_rkey_get(conn, pe_entry->ziov[j].iov_key);
		if (pe_entry->rkeys[j]) {
			ret = zhpeq_rem_key_access(
				pe_entry->rkeys[j]->kdata,
				pe_entry->ziov[j].iov_addr,
				pe_entry->ziov[j].iov_len,
				((flags & FI_READ) ?
				 ZHPEQ_MR_GET_REMOTE : ZHPEQ_MR_PUT_REMOTE),
				&pe_entry->ziov[j].iov_zaddr);
			if (ret < 0)
				goto done;
		} else {
			pe_entry->pe_root.completions++;
			pe_entry->ziov[j].iov_zaddr = 0;
		}
		j++;
		pe_entry->zstate.cnt = j;
	}

	if (pe_entry->rem != rma_len ||
	    ((flags & FI_INJECT) && pe_entry->rem > ZHPEQ_IMM_MAX)) {
		ret = -FI_EINVAL;
		goto done;
	}

	if ((flags & (FI_INJECT | FI_WRITE)) == (FI_INJECT | FI_WRITE)) {
		memcpy(pe_entry->rma.inline_data, msg->msg_iov[0].iov_base,
		       pe_entry->rem);
		zhpe_pe_tx_report_complete(pe_entry, FI_INJECT_COMPLETE);
	}

	pe_entry->flags = flags;
	pe_entry->pe_root.flags |= ZHPE_PE_KEY_WAIT;
	if (pe_entry->pe_root.completions > 0) {
		ohdr.rx_id = pe_entry->rx_id;
		ohdr.pe_entry_id = htons(tindex);
		zhpe_pe_rkey_request(conn, ohdr, &pe_entry->zstate);
	} else
		zhpe_pe_tx_rma(pe_entry);
 done:
	if (ret < 0 && tindex != -1) {
		if (!(flags & FI_INJECT))
			zhpe_mr_close_oneshot(pe_entry->rma.liov,
					      pe_entry->rma.lstate.cnt, true);
		for (i = 0; i < pe_entry->zstate.cnt; i++)
			zhpe_rkey_put(pe_entry->rkeys[j]);
		zhpe_tx_release(conn->ztx, tindex, 0);
	}

	return ret;
}

ssize_t zhpe_do_rma_msg(struct fid_ep *ep, const struct fi_msg_rma *msg,
			uint64_t flags)
{
	/* Used by trigger: flags are assumed to be correct. */
	return do_rma_msg(ep, msg, flags);
}

static ssize_t zhpe_ep_rma_readmsg(struct fid_ep *ep,
				   const struct fi_msg_rma *msg,
				   uint64_t flags)
{
	/* FIXME: Check for provider flags. */
	if (flags & FI_WRITE)
		return -FI_EINVAL;

	return do_rma_msg(ep, msg, flags | FI_READ);
}

static ssize_t zhpe_ep_rma_read(struct fid_ep *ep, void *buf, size_t len,
				 void *desc, fi_addr_t src_addr, uint64_t addr,
				 uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;
	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = src_addr;
	msg.context = context;

	return zhpe_ep_rma_readmsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_readv(struct fid_ep *ep, const struct iovec *iov,
				void **desc, size_t count,
				fi_addr_t src_addr, uint64_t addr,
				 uint64_t key,void *context)
{
	size_t len, i;
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;

	for (i = 0, len = 0; i < count; i++)
		len += iov[i].iov_len;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.addr = src_addr;
	msg.context = context;

	return zhpe_ep_rma_readmsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_writemsg(struct fid_ep *ep,
				    const struct fi_msg_rma *msg,
				    uint64_t flags)
{
	/* FIXME: Check for provider flags. */
	if (flags & FI_READ)
		return -FI_EINVAL;

	return do_rma_msg(ep, msg, flags | FI_WRITE);
}

static ssize_t zhpe_ep_rma_write(struct fid_ep *ep, const void *buf,
				  size_t len, void *desc, fi_addr_t dest_addr,
				  uint64_t addr, uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = dest_addr;
	msg.context = context;

	return zhpe_ep_rma_writemsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_writev(struct fid_ep *ep, const struct iovec *iov,
				void **desc, size_t count, fi_addr_t dest_addr,
				uint64_t addr, uint64_t key, void *context)
{
	size_t i;
	size_t len;
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.rma_iov_count = 1;

	for (i = 0, len = 0; i < count; i++)
		len += iov[i].iov_len;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.context = context;
	msg.addr = dest_addr;

	return zhpe_ep_rma_writemsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_writedata(struct fid_ep *ep, const void *buf,
				      size_t len, void *desc, uint64_t data,
				      fi_addr_t dest_addr, uint64_t addr,
				      uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;

	msg.addr = dest_addr;
	msg.context = context;
	msg.data = data;

	return zhpe_ep_rma_writemsg(ep, &msg, FI_REMOTE_CQ_DATA |
					ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_inject(struct fid_ep *ep, const void *buf,
				size_t len, fi_addr_t dest_addr, uint64_t addr,
				uint64_t key)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;
	msg.addr = dest_addr;

	return zhpe_ep_rma_writemsg(ep, &msg, FI_INJECT |
				    ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_rma_injectdata(struct fid_ep *ep, const void *buf,
					size_t len, uint64_t data,
					fi_addr_t dest_addr, uint64_t addr,
					uint64_t key)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;
	msg.addr = dest_addr;
	msg.data = data;
	return zhpe_ep_rma_writemsg(ep, &msg, FI_INJECT | FI_REMOTE_CQ_DATA |
		ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS);
}


struct fi_ops_rma zhpe_ep_rma = {
	.size  = sizeof(struct fi_ops_rma),
	.read = zhpe_ep_rma_read,
	.readv = zhpe_ep_rma_readv,
	.readmsg = zhpe_ep_rma_readmsg,
	.write = zhpe_ep_rma_write,
	.writev = zhpe_ep_rma_writev,
	.writemsg = zhpe_ep_rma_writemsg,
	.inject = zhpe_ep_rma_inject,
	.injectdata = zhpe_ep_rma_injectdata,
	.writedata = zhpe_ep_rma_writedata,
};

