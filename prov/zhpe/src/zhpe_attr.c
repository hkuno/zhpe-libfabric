/*
 * Copyright (c) 2014,2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2019 Hewlett Packard Enterprise Development LP.  All rights reserved.
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

#define ZHPE_AV_DEF_SZ		(1<<8)

#define ZHPE_CM_DEF_MAP_SZ	(1<<10)
#define ZHPE_CM_DEF_RETRY	(5)

#define ZHPE_CQ_DATA_SIZE (sizeof(uint64_t))
#define ZHPE_CQ_DEF_SZ		(1<<8)

#define ZHPE_DOMAIN_CAP	(FI_LOCAL_COMM | FI_REMOTE_COMM)
#define ZHPE_DOMAIN_MODE	(0)
#define ZHPE_DOMAIN_MR_CNT	(65535)

#define ZHPE_EQ_DEF_SZ		(1<<8)

#define ZHPE_EP_CAP		(FI_ATOMICS | FI_MSG | FI_RMA |		\
				 FI_RMA_EVENT | FI_TAGGED | FI_TRIGGER)
#define ZHPE_EP_COMP_ORDER	(FI_ORDER_NONE)
#define ZHPE_EP_DEF_BUFF_RECV	(1024 * 1024)
#define ZHPE_EP_MAX_ATOMIC_SZ	(8)
#define ZHPE_EP_MAX_CNTR	(128)
#define ZHPE_EP_MAX_CQ		(32)
#define ZHPE_EP_MAX_EAGER_SZ	(16 * 1024)
#define ZHPE_EP_MAX_EP		(128)
#define ZHPE_EP_MAX_INJECT_SZ	(40)
#define ZHPE_EP_MAX_MSG_SZ	(ZHPE_EP_MAX_IOV_LEN * ZHPE_EP_MAX_IOV_LIMIT)
#define ZHPE_EP_MAX_ORDER_RAW_SZ (0)
#define ZHPE_EP_MAX_ORDER_WAR_SZ (0)
#define ZHPE_EP_MAX_ORDER_WAW_SZ (0)
#define ZHPE_EP_MAX_RX_CTX	(16)
#define ZHPE_EP_MAX_RX_QUEUE_SZ	(4096)
#define ZHPE_EP_MEM_TAG_FMT	FI_TAG_GENERIC
#define ZHPE_EP_MAX_TX_CTX	(16)
#define ZHPE_EP_MAX_TX_QUEUE_SZ	(4096)
#define ZHPE_EP_MODE		(0)
#define ZHPE_EP_MSG_ORDER	(FI_ORDER_SAS)
#define ZHPE_EP_MSG_PREFIX_SZ	(0)
#define ZHPE_EP_MAX_CM_DATA_SZ  (256)
#define ZHPE_EP_MAX_CM_DATA_SZ  (256)
#define ZHPE_EP_RX_CAP		(FI_DIRECTED_RECV | FI_MULTI_RECV |	\
				 FI_NAMED_RX_CTX | FI_RECV |		\
				 FI_REMOTE_READ | FI_REMOTE_WRITE)
#define ZHPE_EP_RX_OP_FLAGS	(FI_MULTI_RECV | FI_COMPLETION)
#define ZHPE_EP_TX_CAP		(FI_READ | FI_SEND | FI_WRITE)
#define ZHPE_EP_TX_OP_FLAGS	(FI_INJECT | FI_INJECT_COMPLETE | \
				 FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE | \
				 FI_COMMIT_COMPLETE | FI_COMPLETION)

#define ZHPE_MR_CACHE_ENABLE	(true)

#define ZHPE_INFO_CAP		(ZHPE_DOMAIN_CAP | ZHPE_EP_CAP |	\
				 ZHPE_EP_RX_CAP | ZHPE_EP_TX_CAP)

#define ZHPE_KEY_SIZE		(sizeof(uint64_t))

#define ZHPE_PE_WAITTIME	(10)

#define ZHPE_PROTO_VERSION_WIRE	(1)

#define	ZHPE_PROV_API_VERSION	FI_VERSION(1, 5)
#define	ZHPE_PROV_FI_VERSION	FI_VERSION(1, 8)
#define ZHPE_PROV_NAME		"zhpe"
#define ZHPE_PROV_VERSION	FI_VERSION(1, 0)

static struct fi_ep_attr zhpe_msg_ep_attr = {
	.type			= FI_EP_MSG,
	.protocol		= FI_PROTO_UNSPEC,
	.protocol_version	= ZHPE_PROTO_VERSION_WIRE,
	.max_msg_size		= ZHPE_EP_MAX_MSG_SZ,
	.msg_prefix_size	= ZHPE_EP_MSG_PREFIX_SZ,
	.max_order_raw_size	= ZHPE_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size	= ZHPE_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size	= ZHPE_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format		= ZHPE_EP_MEM_TAG_FMT,
	.tx_ctx_cnt		= ZHPE_EP_MAX_TX_CTX,
	.rx_ctx_cnt		= ZHPE_EP_MAX_RX_CTX,
};

static struct fi_ep_attr zhpe_rdm_ep_attr = {
	.type			= FI_EP_RDM,
	.protocol		= FI_PROTO_UNSPEC,
	.protocol_version	= ZHPE_PROTO_VERSION_WIRE,
	.max_msg_size		= ZHPE_EP_MAX_MSG_SZ,
	.msg_prefix_size	= ZHPE_EP_MSG_PREFIX_SZ,
	.max_order_raw_size	= ZHPE_EP_MAX_ORDER_RAW_SZ,
	.max_order_war_size	= ZHPE_EP_MAX_ORDER_WAR_SZ,
	.max_order_waw_size	= ZHPE_EP_MAX_ORDER_WAW_SZ,
	.mem_tag_format		= ZHPE_EP_MEM_TAG_FMT,
	.tx_ctx_cnt		= ZHPE_EP_MAX_TX_CTX,
	.rx_ctx_cnt		= ZHPE_EP_MAX_RX_CTX,
};

static struct fi_tx_attr zhpe_tx_attr = {
	.caps			= ZHPE_EP_CAP | ZHPE_EP_TX_CAP,
	.mode			= ZHPE_EP_MODE,
	.op_flags		= ZHPE_EP_TX_OP_FLAGS,
	.msg_order		= ZHPE_EP_MSG_ORDER,
	.inject_size		= ZHPE_EP_MAX_INJECT_SZ,
	.size			= ZHPE_EP_MAX_TX_QUEUE_SZ,
	.iov_limit		= ZHPE_EP_MAX_IOV_LIMIT,
	.rma_iov_limit		= ZHPE_EP_MAX_IOV_LIMIT,
};

static struct fi_rx_attr zhpe_rx_attr = {
	.caps			= ZHPE_EP_CAP | ZHPE_EP_RX_CAP,
	.mode			= ZHPE_EP_MODE,
	.op_flags		= ZHPE_EP_RX_OP_FLAGS,
	.msg_order		= ZHPE_EP_MSG_ORDER,
	.comp_order		= ZHPE_EP_COMP_ORDER,
	.total_buffered_recv	= ZHPE_EP_DEF_BUFF_RECV,
	.size			= ZHPE_EP_MAX_RX_QUEUE_SZ,
	.iov_limit		= ZHPE_EP_MAX_IOV_LIMIT,
};

struct fi_domain_attr zhpe_domain_attr = {
	.name			= "zhpe-bridge",
	.threading		= FI_THREAD_COMPLETION,
	.control_progress	= FI_PROGRESS_AUTO,
	.data_progress		= FI_PROGRESS_MANUAL,
	.resource_mgmt		= FI_RM_ENABLED,
	.mr_mode		= FI_MR_ALLOCATED | FI_MR_BASIC,
	.mr_key_size		= ZHPE_KEY_SIZE,
	.cq_data_size		= ZHPE_CQ_DATA_SIZE,
	.cq_cnt			= ZHPE_EP_MAX_CQ,
	.ep_cnt			= ZHPE_EP_MAX_EP,
	.tx_ctx_cnt		= ZHPE_EP_MAX_TX_CTX,
	.rx_ctx_cnt		= ZHPE_EP_MAX_RX_CTX,
	.max_ep_tx_ctx		= ZHPE_EP_MAX_TX_CTX,
	.max_ep_rx_ctx		= ZHPE_EP_MAX_RX_CTX,
	.max_ep_stx_ctx		= 0,
	.max_ep_srx_ctx		= 0,
	.cntr_cnt		= ZHPE_EP_MAX_CNTR,
	.mr_iov_limit		= ZHPE_EP_MAX_IOV_LIMIT,
	.max_err_data		= ZHPE_MAX_ERR_CQ_EQ_DATA_SZ,
	.mr_cnt			= ZHPE_DOMAIN_MR_CNT,
	.caps			= ZHPE_DOMAIN_CAP,
	.mode			= ZHPE_DOMAIN_MODE,
};

struct fi_fabric_attr zhpe_fabric_attr = {
	.name			= "ZHPE",
	.prov_version		= ZHPE_PROV_VERSION,
};

struct fi_info zhpe_info_msg = {
	.caps			= ZHPE_INFO_CAP,
	.addr_format		= FI_SOCKADDR,
	.tx_attr		= &zhpe_tx_attr,
	.rx_attr		= &zhpe_rx_attr,
	.ep_attr		= &zhpe_msg_ep_attr,
	.domain_attr		= &zhpe_domain_attr,
	.fabric_attr		= &zhpe_fabric_attr
};

struct fi_info zhpe_info_rdm = {
#ifdef NOTYET
	.next			= &zhpe_info_msg,
#endif
	.caps			= ZHPE_INFO_CAP,
	.addr_format		= FI_SOCKADDR,
	.tx_attr		= &zhpe_tx_attr,
	.rx_attr		= &zhpe_rx_attr,
	.ep_attr		= &zhpe_rdm_ep_attr,
	.domain_attr		= &zhpe_domain_attr,
	.fabric_attr		= &zhpe_fabric_attr
};

struct fi_provider zhpe_prov = {
	.name			= ZHPE_PROV_NAME,
	.version		= ZHPE_PROV_VERSION,
	.fi_version		= ZHPE_PROV_FI_VERSION,
	.getinfo		= zhpe_getinfo,
	.fabric			= zhpe_fabric,
	.cleanup		= fi_zhpe_fini
};

struct util_prov zhpe_util_prov = {
	.prov			= &zhpe_prov,
	.info			= &zhpe_info_rdm,
};

/* Parameter variables */
int zhpe_av_def_sz		= ZHPE_AV_DEF_SZ;
int zhpe_cm_def_map_sz		= ZHPE_CM_DEF_MAP_SZ;
int zhpe_conn_retry		= ZHPE_CM_DEF_RETRY;
int zhpe_cq_def_sz		= ZHPE_CQ_DEF_SZ;
size_t zhpe_ep_max_eager_sz	= ZHPE_EP_MAX_EAGER_SZ;
int zhpe_eq_def_sz		= ZHPE_EQ_DEF_SZ;
int zhpe_mr_cache_enable	= ZHPE_MR_CACHE_ENABLE;
char *zhpe_pe_affinity_str	= NULL;
int zhpe_pe_waittime		= ZHPE_PE_WAITTIME;
