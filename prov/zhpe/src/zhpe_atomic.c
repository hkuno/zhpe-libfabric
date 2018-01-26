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

ssize_t zhpe_do_tx_atomic(struct fid_ep *ep,
			  const struct fi_msg_atomic *msg,
			  const struct fi_ioc *comparev, void **compare_desc,
			  size_t compare_count, struct fi_ioc *resultv,
			  void **result_desc, size_t result_count,
			  uint64_t flags)
{
	ssize_t			ret = -FI_EINVAL;
	int64_t			tindex = -1;
	struct zhpe_msg_hdr	hdr = { .op_type = ZHPE_OP_ATOMIC };
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_msg_hdr	*zhdr;
	union zhpe_msg_payload	*zpay;
	uint64_t		lzaddr;
	struct zhpe_conn	*conn;
	struct zhpe_tx_ctx	*tx_ctx;
	uint64_t		op_flags;
	struct zhpe_ep		*zhpe_ep;
	struct zhpe_ep_attr	*ep_attr;
	struct zhpe_mr		*zmr;
	size_t			datasize;
	void			*vaddr;
	size_t			cmd_len;
	enum fi_datatype	datatype;
	uint64_t		o64;
	uint64_t		c64;
	uint64_t		dontcare;

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

	/* When used by trigger, flags are assumed to be correct. */
	if (likely(!(flags & ZHPE_TRIGGERED_OP))) {
		if (flags &
		    ~(ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS |
		      ZHPE_TRIGGERED_OP | FI_COMPLETION | FI_TRIGGER |
		      FI_FENCE | FI_ATOMICS | FI_FETCH_ATOMIC |
		      FI_COMPARE_ATOMIC | FI_INJECT | FI_INJECT_COMPLETE |
		      FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |
		      FI_REMOTE_CQ_DATA))
			goto done;

		if (flags & ZHPE_USE_OP_FLAGS)
			flags |= op_flags;

		flags &= ~ZHPE_MASK_COMPLETE;
		flags |= FI_DELIVERY_COMPLETE;
	}

	/* FIXME: Assuming precisely 1 IOV and 1 item. */
	ret = -FI_EMSGSIZE;
	if (msg->op != FI_ATOMIC_READ && msg->iov_count != 1)
		goto done;
	if (msg->rma_iov_count != 1)
		goto done;
	if (msg->msg_iov[0].count != 1 || msg->rma_iov[0].count != 1)
		goto done;
	if (resultv && (result_count != 1 || resultv[0].count != 1))
		goto done;
	if (comparev && (compare_count != 1 || comparev[0].count != 1))
		goto done;

	ret = -FI_EOPNOTSUPP;

	switch (msg->op) {

	case FI_ATOMIC_READ:
		flags |= FI_READ;
		break;
	case FI_ATOMIC_WRITE:
	case FI_BAND:
	case FI_BOR:
	case FI_BXOR:
	case FI_CSWAP:
	case FI_SUM:
		flags |= FI_WRITE;
		break;

	default:
		goto done;
	}

	datatype = msg->datatype;

	switch (datatype) {

	case FI_INT8:
	case FI_UINT8:
		datatype = FI_UINT8;
		datasize = sizeof(uint8_t);
		break;

	case FI_INT16:
	case FI_UINT16:
		datatype = FI_UINT16;
		datasize = sizeof(uint16_t);
		break;

	case FI_INT32:
	case FI_UINT32:
		datatype = FI_UINT32;
		datasize = sizeof(uint32_t);
		break;

	case FI_INT64:
	case FI_UINT64:
		datatype = FI_UINT64;
		datasize = sizeof(uint64_t);
		break;

	default:
		goto done;
	}

	if (flags & FI_TRIGGER) {
		ret = zhpe_queue_atomic_op(ep, msg, comparev, compare_count,
					   resultv, result_count, flags,
					   FI_OP_ATOMIC);
		if (ret != 1)
			goto done;
	}

	ret = zhpe_ep_get_conn(ep_attr, msg->addr, &conn);
	if (ret < 0)
		goto done;

	zhpe_tx_reserve_vars(ret, zhpe_pe_tx_handle_atomic, conn,
			     msg->context, tindex, pe_entry, zhdr, lzaddr,
			     done, 0);

	hdr.rx_id = zhpe_get_rx_id(tx_ctx, msg->addr);
	hdr.pe_entry_id = htons(tindex);
	/* FIXME: get rid of the extra roundtrip. */
	if (flags & FI_REMOTE_CQ_DATA) {
		hdr.flags |= ZHPE_MSG_DELIVERY_COMPLETE;
		pe_entry->cq_data = msg->data;
		pe_entry->pe_root.completions++;
	}

	zpay = zhpe_pay_ptr(conn, zhdr, 0, alignof(*zpay));

	o64 = 0;
	if (msg->op != FI_ATOMIC_READ) {
		vaddr  = msg->msg_iov[0].addr;
		zmr = msg->desc[0];
		if (zmr) {
			ret = zhpeq_lcl_key_access(zmr->kdata, vaddr, datasize,
						   ZHPEQ_MR_PUT,  &dontcare);
			if (ret < 0)
				goto done;
		}
		o64 = *(uint64_t *)vaddr;
	}

	c64 = 0;
	if (comparev) {
		vaddr = comparev[0].addr;
		zmr = compare_desc[0];
		if (zmr) {
			ret = zhpeq_lcl_key_access(zmr->kdata, vaddr, datasize,
						   ZHPEQ_MR_PUT, &dontcare);
			if (ret < 0)
				goto done;
		}
		c64 = *(uint64_t *)vaddr;
	}

	pe_entry->result = NULL;
	if (resultv) {
		vaddr = resultv[0].addr;
		zmr = result_desc[0];
		if (zmr) {
			ret = zhpeq_lcl_key_access(zmr->kdata, vaddr, datasize,
						   ZHPEQ_MR_GET, &dontcare);
			if (ret < 0)
				goto done;
		}
		if (!(hdr.flags & ZHPE_MSG_DELIVERY_COMPLETE)) {
			hdr.flags |= ZHPE_MSG_DELIVERY_COMPLETE;
			pe_entry->pe_root.completions++;
		}
		pe_entry->result = vaddr;
		pe_entry->result_type = datatype;
	}

	zpay->atomic_req.operand = htobe64(o64);
	zpay->atomic_req.compare = htobe64(c64);
	zpay->atomic_req.vaddr = htobe64(msg->rma_iov[0].addr);
	zpay->atomic_req.key =  htobe64(msg->rma_iov[0].key);
	zpay->atomic_req.op = msg->op;
	zpay->atomic_req.datatype = datatype;
	zpay->atomic_req.datasize = datasize;

	pe_entry->flags = flags;

	*zhdr = hdr;
	cmd_len = zpay->atomic_req.end - (char *)zhdr;
	ret = zhpe_pe_tx_ring(pe_entry, zhdr, lzaddr, cmd_len);
 done:
	if (ret < 0 && tindex != -1)
		zhpe_tx_release(conn->ztx, tindex, false);

	return ret;
}

static ssize_t zhpe_ep_atomic_writemsg(struct fid_ep *ep,
			const struct fi_msg_atomic *msg, uint64_t flags)
{
#if ENABLE_DEBUG
	switch (msg->op) {
	case FI_MIN:
	case FI_MAX:
	case FI_SUM:
	case FI_PROD:
	case FI_LOR:
	case FI_LAND:
	case FI_BOR:
	case FI_BAND:
	case FI_LXOR:
	case FI_BXOR:
	case FI_ATOMIC_WRITE:
		break;
	default:
		ZHPE_LOG_ERROR("Invalid operation type\n");
		return -FI_EINVAL;
	}
#endif
	return zhpe_do_tx_atomic(ep, msg, NULL, NULL, 0,
				  NULL, NULL, 0, flags);
}

static ssize_t zhpe_ep_atomic_write(struct fid_ep *ep,
				    const void *buf, size_t count, void *desc,
				    fi_addr_t dest_addr, uint64_t addr,
				    uint64_t key, enum fi_datatype datatype,
				    enum fi_op op, void *context)
{
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.count = count;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;
	msg.data = 0;

	return zhpe_ep_atomic_writemsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_writev(struct fid_ep *ep,
			const struct fi_ioc *iov, void **desc, size_t count,
			fi_addr_t dest_addr,
			uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	size_t i;
	struct fi_msg_atomic msg;
	struct fi_rma_ioc rma_iov;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.key = key;

	for (i = 0, rma_iov.count = 0; i < count; i++)
		rma_iov.count += iov[i].count;

	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;
	msg.data = 0;

	return zhpe_ep_atomic_writemsg(ep, &msg, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_inject(struct fid_ep *ep, const void *buf,
				size_t count, fi_addr_t dest_addr,
				uint64_t addr,
				uint64_t key, enum fi_datatype datatype,
				enum fi_op op)
{
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.count = count;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;

	msg.datatype = datatype;
	msg.op = op;
	msg.data = 0;

	return zhpe_ep_atomic_writemsg(ep, &msg, FI_INJECT |
				       ZHPE_NO_COMPLETION | ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_readwritemsg(struct fid_ep *ep,
				const struct fi_msg_atomic *msg,
				struct fi_ioc *resultv, void **result_desc,
				size_t result_count, uint64_t flags)
{
	switch (msg->op) {
	case FI_MIN:
	case FI_MAX:
	case FI_SUM:
	case FI_PROD:
	case FI_LOR:
	case FI_LAND:
	case FI_BOR:
	case FI_BAND:
	case FI_LXOR:
	case FI_BXOR:
	case FI_ATOMIC_READ:
	case FI_ATOMIC_WRITE:
		break;
	default:
		ZHPE_LOG_ERROR("Invalid operation type\n");
		return -FI_EINVAL;
	}

	return zhpe_do_tx_atomic(ep, msg, NULL, NULL, 0,
				 resultv, result_desc, result_count, flags);
}

static ssize_t zhpe_ep_atomic_readwrite(struct fid_ep *ep,
			const void *buf, size_t count, void *desc,
			void *result, void *result_desc,
			fi_addr_t dest_addr,
			uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc resultv;

	if (!buf && op != FI_ATOMIC_READ)
		return -FI_EINVAL;
	if (op == FI_ATOMIC_READ)
		msg_iov.addr = NULL;
	else
		msg_iov.addr = (void *)buf;

	msg_iov.count = count;
	msg.msg_iov = &msg_iov;

	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.count = count;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	resultv.addr = result;
	resultv.count = count;

	return zhpe_ep_atomic_readwritemsg(ep, &msg, &resultv, &result_desc, 1,
						ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_readwritev(struct fid_ep *ep,
			const struct fi_ioc *iov, void **desc, size_t count,
			struct fi_ioc *resultv, void **result_desc,
			size_t result_count, fi_addr_t dest_addr,
			uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	struct fi_msg_atomic msg;
	struct fi_rma_ioc rma_iov;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.count = ofi_total_ioc_cnt(iov, count);
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	return zhpe_ep_atomic_readwritemsg(ep, &msg,
					   resultv, result_desc, result_count,
					   ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_compwritemsg(struct fid_ep *ep,
			const struct fi_msg_atomic *msg,
			const struct fi_ioc *comparev, void **compare_desc,
			size_t compare_count, struct fi_ioc *resultv,
			void **result_desc, size_t result_count,
			uint64_t flags)
{
	switch (msg->op) {
	case FI_CSWAP:
	case FI_CSWAP_NE:
	case FI_CSWAP_LE:
	case FI_CSWAP_LT:
	case FI_CSWAP_GE:
	case FI_CSWAP_GT:
	case FI_MSWAP:
		break;
	default:
		ZHPE_LOG_ERROR("Invalid operation type\n");
		return -FI_EINVAL;
	}

	return zhpe_do_tx_atomic(ep, msg, comparev, compare_desc,
				 compare_count, resultv, result_desc,
				 result_count, flags);
}

static ssize_t zhpe_ep_atomic_compwrite(struct fid_ep *ep,
			const void *buf, size_t count, void *desc,
			const void *compare, void *compare_desc,
			void *result, void *result_desc,
			fi_addr_t dest_addr,
			uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	struct fi_msg_atomic msg;
	struct fi_ioc msg_iov;
	struct fi_rma_ioc rma_iov;
	struct fi_ioc resultv;
	struct fi_ioc comparev;

	msg_iov.addr = (void *)buf;
	msg_iov.count = count;
	msg.msg_iov = &msg_iov;

	msg.desc = &desc;
	msg.iov_count = 1;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.count = count;
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	resultv.addr = result;
	resultv.count = count;
	comparev.addr = (void *)compare;
	comparev.count = count;

	return zhpe_ep_atomic_compwritemsg(ep, &msg, &comparev, &compare_desc,
			1, &resultv, &result_desc, 1, ZHPE_USE_OP_FLAGS);
}

static ssize_t zhpe_ep_atomic_compwritev(struct fid_ep *ep,
			const struct fi_ioc *iov, void **desc, size_t count,
			const struct fi_ioc *comparev, void **compare_desc,
			size_t compare_count, struct fi_ioc *resultv,
			void **result_desc, size_t result_count,
			fi_addr_t dest_addr, uint64_t addr, uint64_t key,
			enum fi_datatype datatype, enum fi_op op,
			void *context)
{
	struct fi_msg_atomic msg;
	struct fi_rma_ioc rma_iov;

	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.addr = dest_addr;

	rma_iov.addr = addr;
	rma_iov.count = ofi_total_ioc_cnt(iov, count);
	rma_iov.key = key;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.datatype = datatype;
	msg.op = op;
	msg.context = context;

	return zhpe_ep_atomic_compwritemsg(ep, &msg,
					   comparev, compare_desc,
					   compare_count,
					   resultv, result_desc, result_count,
					   ZHPE_USE_OP_FLAGS);
}

/* Domain parameter is ignored, okay to pass in NULL */
int zhpe_query_atomic(struct fid_domain *domain,
		      enum fi_datatype datatype, enum fi_op op,
		      struct fi_atomic_attr *attr, uint64_t flags)
{
	int ret;

	ret = ofi_atomic_valid(&zhpe_prov, datatype, op, flags);
	if (ret < 0)
		return ret;

	attr->count = 1;

	switch (datatype) {

	case FI_INT8:
	case FI_UINT8:
		attr->size = sizeof(uint8_t);
		break;

	case FI_INT16:
	case FI_UINT16:
		attr->size = sizeof(uint16_t);
		break;

	case FI_INT32:
	case FI_UINT32:
		attr->size = sizeof(uint32_t);
		break;

	case FI_INT64:
	case FI_UINT64:
		attr->size = sizeof(uint64_t);
		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	switch (op) {

	case FI_ATOMIC_READ:
	case FI_ATOMIC_WRITE:
	case FI_BAND:
	case FI_BOR:
	case FI_BXOR:
	case FI_CSWAP:
	case FI_SUM:
		break;

	default:
		return -FI_EOPNOTSUPP;
	}

	return 0;
}

static int zhpe_ep_atomic_valid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	ret = zhpe_query_atomic(NULL, datatype, op, &attr, 0);
	if (!ret)
		*count = attr.count;

	return ret;
}

static int zhpe_ep_atomic_fetch_valid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	ret = zhpe_query_atomic(NULL, datatype, op, &attr, FI_FETCH_ATOMIC);
	if (!ret)
		*count = attr.count;
	return ret;
}

static int zhpe_ep_atomic_cswap_valid(struct fid_ep *ep,
		enum fi_datatype datatype, enum fi_op op, size_t *count)
{
	struct fi_atomic_attr attr;
	int ret;

	/* domain parameter is ignored - okay to pass in NULL */
	ret = zhpe_query_atomic(NULL, datatype, op, &attr, FI_COMPARE_ATOMIC);
	if (!ret)
		*count = attr.count;
	return ret;
}

struct fi_ops_atomic zhpe_ep_atomic = {
	.size = sizeof(struct fi_ops_atomic),
	.write = zhpe_ep_atomic_write,
	.writev = zhpe_ep_atomic_writev,
	.writemsg = zhpe_ep_atomic_writemsg,
	.inject = zhpe_ep_atomic_inject,
	.readwrite = zhpe_ep_atomic_readwrite,
	.readwritev = zhpe_ep_atomic_readwritev,
	.readwritemsg = zhpe_ep_atomic_readwritemsg,
	.compwrite = zhpe_ep_atomic_compwrite,
	.compwritev = zhpe_ep_atomic_compwritev,
	.compwritemsg = zhpe_ep_atomic_compwritemsg,
	.writevalid = zhpe_ep_atomic_valid,
	.readwritevalid = zhpe_ep_atomic_fetch_valid,
	.compwritevalid = zhpe_ep_atomic_cswap_valid,
};
