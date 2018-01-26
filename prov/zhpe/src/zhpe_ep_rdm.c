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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

const struct fi_ep_attr zhpe_rdm_ep_attr = {
	.type = FI_EP_RDM,
	.protocol = FI_PROTO_UNSPEC,
	.protocol_version = ZHPE_WIRE_PROTO_VERSION,
	.max_msg_size = ZHPE_EP_MAX_MSG_SZ,
	.msg_prefix_size = ZHPE_EP_MSG_PREFIX_SZ,
	.max_order_raw_size = ZHPE_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size = ZHPE_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size = ZHPE_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format = ZHPE_EP_MEM_TAG_FMT,
	.tx_ctx_cnt = ZHPE_EP_MAX_TX_CNT,
	.rx_ctx_cnt = ZHPE_EP_MAX_RX_CNT,
};

const struct fi_tx_attr zhpe_rdm_tx_attr = {
	.caps = ZHPE_EP_RDM_CAP,
	.mode = ZHPE_MODE,
	.op_flags = ZHPE_EP_DEFAULT_OP_FLAGS,
	.msg_order = ZHPE_EP_MSG_ORDER,
	.inject_size = ZHPE_EP_MAX_INJECT_SZ,
	.size = ZHPE_EP_TX_SZ,
	.iov_limit = ZHPE_EP_MAX_IOV_LIMIT,
	.rma_iov_limit = ZHPE_EP_MAX_IOV_LIMIT,
};

const struct fi_rx_attr zhpe_rdm_rx_attr = {
	.caps = ZHPE_EP_RDM_CAP,
	.mode = ZHPE_MODE,
	.op_flags = 0,
	.msg_order = ZHPE_EP_MSG_ORDER,
	.comp_order = ZHPE_EP_COMP_ORDER,
	.total_buffered_recv = ZHPE_EP_DEF_BUFF_RECV,
	.size = ZHPE_EP_RX_SZ,
	.iov_limit = ZHPE_EP_MAX_IOV_LIMIT,
};

static int zhpe_rdm_verify_rx_attr(const struct fi_rx_attr *attr)
{
	if (!attr)
		return 0;

	if ((attr->caps | ZHPE_EP_RDM_CAP) != ZHPE_EP_RDM_CAP) {
		ZHPE_LOG_DBG("Unsupported RDM rx caps\n");
		return -FI_ENODATA;
	}

	if ((attr->msg_order | ZHPE_EP_MSG_ORDER) != ZHPE_EP_MSG_ORDER) {
		ZHPE_LOG_DBG("Unsuported rx message order\n");
		return -FI_ENODATA;
	}

	if ((attr->comp_order | ZHPE_EP_COMP_ORDER) != ZHPE_EP_COMP_ORDER) {
		ZHPE_LOG_DBG("Unsuported rx completion order\n");
		return -FI_ENODATA;
	}

	if (attr->total_buffered_recv > zhpe_rdm_rx_attr.total_buffered_recv) {
		ZHPE_LOG_DBG("Buffered receive size too large\n");
		return -FI_ENODATA;
	}

	if (roundup_power_of_two(attr->size) > zhpe_rdm_rx_attr.size) {
		ZHPE_LOG_DBG("Rx size too large\n");
		return -FI_ENODATA;
	}

	if (attr->iov_limit > zhpe_rdm_rx_attr.iov_limit) {
		ZHPE_LOG_DBG("Rx iov limit too large\n");
		return -FI_ENODATA;
	}

	return 0;
}

static int zhpe_rdm_verify_tx_attr(const struct fi_tx_attr *attr)
{
	if (!attr)
		return 0;

	if ((attr->caps | ZHPE_EP_RDM_CAP) != ZHPE_EP_RDM_CAP) {
		ZHPE_LOG_DBG("Unsupported RDM tx caps\n");
		return -FI_ENODATA;
	}

	if ((attr->msg_order | ZHPE_EP_MSG_ORDER) != ZHPE_EP_MSG_ORDER) {
		ZHPE_LOG_DBG("Unsupported tx message order\n");
		return -FI_ENODATA;
	}

	if (attr->inject_size > zhpe_rdm_tx_attr.inject_size) {
		ZHPE_LOG_DBG("Inject size too large\n");
		return -FI_ENODATA;
	}

	if (roundup_power_of_two(attr->size) > zhpe_rdm_tx_attr.size) {
		ZHPE_LOG_DBG("Tx size too large\n");
		return -FI_ENODATA;
	}

	if (attr->iov_limit > zhpe_rdm_tx_attr.iov_limit) {
		ZHPE_LOG_DBG("Tx iov limit too large\n");
		return -FI_ENODATA;
	}

	if (attr->rma_iov_limit > zhpe_rdm_tx_attr.rma_iov_limit) {
		ZHPE_LOG_DBG("RMA iov limit too large\n");
		return -FI_ENODATA;
	}

	return 0;
}

int zhpe_rdm_verify_ep_attr(struct fi_ep_attr *ep_attr,
			    struct fi_tx_attr *tx_attr,
			    struct fi_rx_attr *rx_attr)
{
	int ret;

	if (ep_attr) {
		switch (ep_attr->protocol) {

		case FI_PROTO_UNSPEC:
			break;
		default:
			ZHPE_LOG_DBG("Unsupported protocol\n");
			return -FI_ENODATA;
		}

		if (ep_attr->protocol_version &&
		    (ep_attr->protocol_version !=
		     zhpe_rdm_ep_attr.protocol_version)) {
			ZHPE_LOG_DBG("Invalid protocol version\n");
			return -FI_ENODATA;
		}

		if (ep_attr->max_msg_size > zhpe_rdm_ep_attr.max_msg_size) {
			ZHPE_LOG_DBG("Message size too large\n");
			return -FI_ENODATA;
		}

		if (ep_attr->msg_prefix_size >
		    zhpe_rdm_ep_attr.msg_prefix_size) {
			ZHPE_LOG_DBG("Msg prefix size not supported\n");
			return -FI_ENODATA;
		}

		if (ep_attr->max_order_raw_size >
		   zhpe_rdm_ep_attr.max_order_raw_size) {
			ZHPE_LOG_DBG("RAW order size too large\n");
			return -FI_ENODATA;
		}

		if (ep_attr->max_order_war_size >
		   zhpe_rdm_ep_attr.max_order_war_size) {
			ZHPE_LOG_DBG("WAR order size too large\n");
			return -FI_ENODATA;
		}

		if (ep_attr->max_order_waw_size >
		   zhpe_rdm_ep_attr.max_order_waw_size) {
			ZHPE_LOG_DBG("WAW order size too large\n");
			return -FI_ENODATA;
		}

		if ((ep_attr->tx_ctx_cnt > ZHPE_EP_MAX_TX_CNT) &&
		    ep_attr->tx_ctx_cnt != FI_SHARED_CONTEXT)
			return -FI_ENODATA;

		if ((ep_attr->rx_ctx_cnt > ZHPE_EP_MAX_RX_CNT) &&
		    ep_attr->rx_ctx_cnt != FI_SHARED_CONTEXT)
			return -FI_ENODATA;
	}

	ret = zhpe_rdm_verify_tx_attr(tx_attr);
	if (ret)
		return ret;

	ret = zhpe_rdm_verify_rx_attr(rx_attr);
	if (ret)
		return ret;

	return 0;
}

int zhpe_rdm_fi_info(uint32_t version,
		     const union sockaddr_in46 *src_addr,
		     const union sockaddr_in46 *dest_addr,
		     const struct fi_info *hints, struct fi_info **info)
{
	*info = zhpe_fi_info(version, hints, src_addr, dest_addr,
			     ZHPE_EP_RDM_CAP, ZHPE_MODE,
			     &zhpe_rdm_ep_attr, &zhpe_rdm_tx_attr,
			     &zhpe_rdm_rx_attr);

	return (*info ? 0 : -FI_ENOMEM);
}

static int zhpe_rdm_endpoint(struct fid_domain *domain, struct fi_info *info,
		struct zhpe_ep **ep, void *context, size_t fclass)
{
	int ret;

	if (info) {
		ret = zhpe_rdm_verify_ep_attr(info->ep_attr, info->tx_attr,
					      info->rx_attr);
		if (ret < 0)
			return -FI_EINVAL;
	}

	ret = zhpe_alloc_endpoint(domain, info, ep, context, fclass);
	if (ret)
		return ret;

	if (!info || !info->ep_attr)
		(*ep)->attr->ep_attr = zhpe_rdm_ep_attr;

	if (!info || !info->tx_attr)
		(*ep)->tx_attr = zhpe_rdm_tx_attr;

	if (!info || !info->rx_attr)
		(*ep)->rx_attr = zhpe_rdm_rx_attr;

	return 0;
}

int zhpe_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context)
{
	int ret;
	struct zhpe_ep *endpoint;

	ret = zhpe_rdm_endpoint(domain, info, &endpoint, context, FI_CLASS_EP);
	if (ret)
		return ret;

	*ep = &endpoint->ep;
	return 0;
}

int zhpe_rdm_sep(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **sep, void *context)
{
	int ret;
	struct zhpe_ep *endpoint;

	ret = zhpe_rdm_endpoint(domain, info, &endpoint, context, FI_CLASS_SEP);
	if (ret)
		return ret;

	*sep = &endpoint->ep;
	return 0;
}

