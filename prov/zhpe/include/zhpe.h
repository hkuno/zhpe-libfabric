/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc. All rights reserved.
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

#ifndef _ZHPE_H_
#define _ZHPE_H_

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <zhpeq.h>

#include <rdma/fabric.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_trigger.h>

#include <rdma/providers/fi_log.h>

#include <rbtree.h>
#include <prov.h>

#include <fi.h>
#include <fi_enosys.h>
#include <fi_file.h>
#include <fi_indexer.h>
#include <fi_iov.h>
#include <fi_list.h>
#include <fi_osd.h>
#include <fi_rbuf.h>
#include <fi_util.h>

#include <ofi_atomic.h>

#define _ZHPE_LOG_DBG(subsys, ...) FI_DBG(&zhpe_prov, subsys, __VA_ARGS__)
#define _ZHPE_LOG_ERROR(subsys, ...) FI_WARN(&zhpe_prov, subsys, __VA_ARGS__)

#ifdef ENABLE_DEBUG
void gdb_hook(void);
#endif

typedef long long		llong;
typedef unsigned long long	ullong;

union sockaddr_in46 {
	uint64_t		alignment;
	/* sa_family common to all, sin_port common to IPv4/6. */
	struct {
		sa_family_t	sa_family;
		in_port_t	sin_port;
	};
	struct sockaddr_in	addr4;
	struct sockaddr_in6	addr6;
};

static inline size_t sockaddr_len(const void *addr)
{
	const union sockaddr_in46 *sa = addr;

	switch (sa->sa_family) {

	case AF_INET:
		return sizeof(struct sockaddr_in);

	case AF_INET6:
		return sizeof(struct sockaddr_in6);

	default:
		return 0;
	}
}

static inline bool sockaddr_valid(const void *addr, size_t src_len,
				  bool check_len)
{
	size_t			len = sockaddr_len(addr);

	if (!len)
		return false;

	return (!check_len || src_len >= len);
}

static inline void sockaddr_cpy(union sockaddr_in46 *dst, const void *src)
{
	memcpy(dst, src, sockaddr_len(src));
}

static inline union sockaddr_in46 *sockaddr_dup(const void *src)
{
	union sockaddr_in46	*ret = NULL;
	size_t			len = sockaddr_len(src);

	if (len)
		ret = malloc(sizeof(*ret));
	if (ret)
		memcpy(ret, src, len);

	return ret;
}

static inline int sockaddr_cmp_noport(const void *addr1, const void *addr2)
{
	int			ret;
	const union sockaddr_in46 *sa1 = addr1;
	const union sockaddr_in46 *sa2 = addr2;

	ret = memcmp(&sa1->sa_family, &sa2->sa_family, sizeof(sa1->sa_family));
	if (ret)
		goto done;

	switch (sa1->sa_family) {

	case AF_INET:
		ret = memcmp(&sa1->addr4.sin_addr, &sa2->addr4.sin_addr,
			     sizeof(sa1->addr4.sin_addr));
		break;

	case AF_INET6:
		ret = memcmp(&sa1->addr6.sin6_addr, &sa2->addr6.sin6_addr,
			     sizeof(sa1->addr6.sin6_addr));
		break;

	default:
		ret = -1;
		break;
	}

 done:
	return ret;
}

static inline int sockaddr_cmp(const void *addr1, const void *addr2)
{
	int			ret;
	const union sockaddr_in46 *sa1 = addr1;
	const union sockaddr_in46 *sa2 = addr2;

	ret = sockaddr_cmp_noport(sa1, sa2);
	if (ret)
		goto done;

	ret = memcmp(&sa1->sin_port, &sa2->sin_port, sizeof(sa1->sin_port));
 done:
	return ret;
}

static inline const char *sockaddr_ntop(const union sockaddr_in46 *sa,
					char *buf, size_t len)
{
	const char		*ret = NULL;

	switch (sa->sa_family) {

	case AF_INET:
		ret = inet_ntop(AF_INET, &sa->addr4.sin_addr, buf, len);
		break;

	case AF_INET6:
		ret = inet_ntop(AF_INET6, &sa->addr6.sin6_addr, buf, len);
		break;

	default:
		if (*buf && len)
			buf[0] = '\0';
		errno = EAFNOSUPPORT;
		break;
	}

	return ret;
}

static inline bool sockaddr_wildcard(const union sockaddr_in46 *sa)
{
	bool			ret = false;

	switch (sa->sa_family) {

	case AF_INET:
		ret = (sa->addr4.sin_addr.s_addr == htonl(INADDR_ANY));
		break;

	case AF_INET6:
		ret = !memcmp(&sa->addr6.sin6_addr, &in6addr_any,
			      sizeof(in6addr_any));
		break;

	default:
		break;
	}

	return ret;
}

static inline bool zhpe_sa_family(const struct fi_info *info)
{
	return (info->addr_format == FI_SOCKADDR_IN6 ? AF_INET6 : AF_INET);
}

/* FIXME. */
#define alignof			__alignof__

#define NOOPTIMIZE      asm volatile("")

#if defined(__x86_32__) || defined( __x86_64__)

#define _BARRIER_DEFINED

static inline void smp_mb(void)
{
	asm volatile("mfence":::"memory");
}

static inline void smp_rmb(void)
{
	asm volatile("lfence":::"memory");
}

static inline void smp_wmb(void)
{
	asm volatile("sfence":::"memory");
}

#endif

/* Compiler won't reorder; lazy (no CPU barriers); won't be torn. */

static inline uint32_t atomic_load_lazy_uint32(uint32_t *p)
{
	return *(volatile uint32_t *)p;
}

static inline void atomic_store_lazy_uint32(uint32_t *p, uint32_t v)
{
	*(volatile uint32_t *)p = v;
}

static inline uint64_t atomic_load_lazy_uint64(uint64_t *p)
{
	return *(volatile uint64_t *)p;
}

static inline void atomic_store_lazy_uint64(uint64_t *p, uint64_t v)
{
	*(volatile uint64_t *)p = v;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

extern const char zhpe_fab_name[];
extern const char zhpe_dom_name[];
extern const char zhpe_prov_name[];
extern struct fi_provider zhpe_prov;
extern int zhpe_pe_waittime;
extern int zhpe_conn_retry;
extern int zhpe_cm_def_map_sz;
extern int zhpe_av_def_sz;
extern int zhpe_cq_def_sz;
extern int zhpe_eq_def_sz;
extern char *zhpe_pe_affinity_str;
extern int zhpe_ep_max_eager_sz;

static inline void *zhpe_mremap(void *old_address, size_t old_size,
				size_t new_size)
{
#ifdef __APPLE__
	return (void *) -1;
#elif defined __FreeBSD__
	return (void *) -1;
#else
	return mremap(old_address, old_size, new_size, 0);
#endif
}
#define ZHPE_EP_MAX_INJECT_SZ	(40)
#define ZHPE_EP_MAX_MSG_SZ (1<<31)
#define ZHPE_EP_MAX_EAGER_SZ (16 * 1024)
#define ZHPE_EP_DEF_BUFF_RECV (1024 * 1024)
#define ZHPE_EP_MAX_ORDER_RAW_SZ (0)
#define ZHPE_EP_MAX_ORDER_WAR_SZ (0)
#define ZHPE_EP_MAX_ORDER_WAW_SZ (0)
#define ZHPE_EP_MEM_TAG_FMT FI_TAG_GENERIC
#define ZHPE_EP_MAX_EP_CNT (128)
#define ZHPE_EP_MAX_CQ_CNT (32)
#define ZHPE_EP_MAX_CNTR_CNT (128)
#define ZHPE_EP_MAX_TX_CNT (16)
#define ZHPE_EP_MAX_RX_CNT (16)
#define ZHPE_EP_MAX_IOV_LIMIT (1)
#define ZHPE_EP_TX_SZ		(4096)
#define ZHPE_EP_RX_SZ		(256)
#define ZHPE_EP_MIN_MULTI_RECV (64)
#define ZHPE_EP_MAX_ATOMIC_SZ (8)
#define ZHPE_EP_MAX_CTX_BITS (16)
#define ZHPE_EP_MSG_PREFIX_SZ (0)
#define ZHPE_EP_MAX_IO_BYTES	(16UL * 1024 * 1024)
#define ZHPE_EP_MAX_IO_OPS	(2)
#define ZHPE_DOMAIN_MR_CNT (65535)

#define ZHPE_PE_POLL_TIMEOUT (100000)
#define ZHPE_PE_WAITTIME (10)

#define ZHPE_EQ_DEF_SZ (1<<8)
#define ZHPE_CQ_DEF_SZ (1<<8)
#define ZHPE_AV_DEF_SZ (1<<8)
#define ZHPE_CMAP_DEF_SZ (1<<10)

#define ZHPE_KEY_SIZE (sizeof(uint32_t))
#define ZHPE_CQ_DATA_SIZE (sizeof(uint64_t))
#define ZHPE_TAG_SIZE (sizeof(uint64_t))
#define ZHPE_MAX_NETWORK_ADDR_SZ (35)

#define ZHPE_PEP_LISTENER_TIMEOUT (10000)
#define ZHPE_CM_COMM_TIMEOUT (2000)
#define ZHPE_EP_MAX_RETRY (5)
#define ZHPE_EP_MAX_CM_DATA_SZ (256)
#define ZHPE_CM_DEF_BACKLOG (128)
#define ZHPE_CM_DEF_RETRY (5)
#define ZHPE_CM_CONN_IN_PROGRESS ((struct zhpe_conn *)(0x1L))

enum {
	ZHPE_CONN_ACTION_NEW,
	ZHPE_CONN_ACTION_DROP,
	ZHPE_CONN_ACTION_SELF,
	ZHPE_CONN_ACTION_SAMEHOST,
};

enum {
	ZHPE_CONN_STATE_FREE,
	ZHPE_CONN_STATE_INIT,
	ZHPE_CONN_STATE_RACED,
	ZHPE_CONN_STATE_READY,
};

#define ZHPE_EP_RDM_PRI_CAP (FI_MSG | FI_TAGGED | FI_RMA | FI_ATOMICS | \
			 FI_NAMED_RX_CTX | \
			 FI_DIRECTED_RECV | \
			 FI_READ | FI_WRITE | FI_RECV | FI_SEND | \
			 FI_REMOTE_READ | FI_REMOTE_WRITE)

#define ZHPE_EP_RDM_SEC_CAP (FI_MULTI_RECV | FI_SOURCE | FI_RMA_EVENT | \
			 FI_SHARED_AV | FI_FENCE | FI_TRIGGER)

#define ZHPE_EP_RDM_CAP (ZHPE_EP_RDM_PRI_CAP | ZHPE_EP_RDM_SEC_CAP)

#define ZHPE_EP_MSG_PRI_CAP ZHPE_EP_RDM_PRI_CAP

#define ZHPE_EP_MSG_SEC_CAP ZHPE_EP_RDM_SEC_CAP

#define ZHPE_EP_MSG_CAP (ZHPE_EP_MSG_PRI_CAP | ZHPE_EP_MSG_SEC_CAP)

#define ZHPE_EP_MSG_ORDER	(FI_ORDER_SAS)

#define ZHPE_EP_COMP_ORDER	(FI_ORDER_NONE)
#define ZHPE_EP_DEFAULT_OP_FLAGS (FI_TRANSMIT_COMPLETE)

#define ZHPE_EP_CQ_FLAGS (FI_SEND | FI_TRANSMIT | FI_RECV | \
			FI_SELECTIVE_COMPLETION)
#define ZHPE_EP_CNTR_FLAGS (FI_SEND | FI_RECV | FI_READ | \
			FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE)

#define ZHPE_MODE		(0)
#define ZHPE_NO_COMPLETION	(1ULL << 60)
#define ZHPE_USE_OP_FLAGS	(1ULL << 61)
#define ZHPE_TRIGGERED_OP	(1ULL << 62)

/* it must be adjusted if error data size in CQ/EQ 
 * will be larger than ZHPE_EP_MAX_CM_DATA_SZ */
#define ZHPE_MAX_ERR_CQ_EQ_DATA_SZ ZHPE_EP_MAX_CM_DATA_SZ

enum {
	ZHPE_SIGNAL_RD_FD = 0,
	ZHPE_SIGNAL_WR_FD
};

#define ZHPE_MAJOR_VERSION 1
#define ZHPE_MINOR_VERSION 0

#define ZHPE_WIRE_PROTO_VERSION (1)

struct zhpe_fabric {
	struct fid_fabric	fab_fid;
	ofi_atomic32_t		ref;
	struct dlist_entry	service_list;
	struct dlist_entry	fab_lentry;
	fastlock_t		lock;
};

#define ZHPE_RING_ENTRY_LEN		((size_t)64)

#define ZHPE_RING_TX_CQ_ENTRIES		(16)

#define ZHPE_BAD_INDEX			(~(uint32_t)0)

union zhpe_free_index {
	struct {
		uint32_t        seq;
		uint16_t        index;
		uint16_t	count;
	};
	uint64_t		blob;
};

/* Free entry:on pointer boundary.
 * Bit 0 of size zero => prev_size valid
 */

struct zhpe_slab_limit {
	size_t			current;
	size_t			limit;
	size_t			entry_max;
};

struct zhpe_slab_free_entry {
	uintptr_t		prev_size;
	uintptr_t		size;
	struct dlist_entry	lentry;
};

struct zhpe_slab {
	void			*mem;
	uint32_t		size;
	struct dlist_entry	free_list;
	struct zhpe_mr		*zmr;
	uint64_t		zaddr;
	fastlock_t		lock;
	int32_t			use_count;
};

struct zhpe_rkey_data {
	uint64_t		key;
	struct zhpe_tx		*ztx;
	struct zhpeq_key_data	*kdata;
	int32_t			use_count;
};

struct zhpe_kexp_data {
	uint64_t		key;
	struct zhpe_conn	*conn;
	struct dlist_entry	lentry;
	int32_t			use_count;
	bool			exporting;
};

struct zhpe_tx {
	char			*zentries;
	struct zhpe_pe_entry	*pentries;
	struct zhpe_mr		*zmr;
	uint64_t		lz_zentries;
	union zhpe_free_index	ufree;
	union zhpe_free_index	pfree;
	struct zhpeq		*zq;
	uint32_t		mask;
	int32_t			use_count;
};

struct zhpe_rx_common {
	union {
		struct zhpe_mr	*zmr;		/* Local */
		struct zhpe_rkey_data *rkey;	/* Remote. */
	};
	unsigned long		*scoreboard;
	uint32_t		completed;
	uint32_t		mask;
};

/* peer_visible items are stored in network byte order. */
struct zhpe_rx_peer_visible {
	uint32_t		completed;
};

struct zhpe_pe_root;

typedef int (*zhpe_pe_tx_handler)(struct zhpe_pe_root *pe_root,
				  struct zhpeq_cq_entry *zq_cqe);

#define ZHPE_PE_PROV			(0x01)
#define ZHPE_PE_RETRY			(0x02)
#define ZHPE_PE_KEY_WAIT		(0x04)
#define ZHPE_PE_NO_RINDEX		(0x08)

struct zhpe_conn;

struct zhpe_pe_root {
	zhpe_pe_tx_handler	handler;
	struct zhpe_conn	*conn;
	void			*context;
	int32_t			status;
	uint16_t		rindex;
	uint8_t			completions;
	uint8_t			flags;
};

struct zhpe_rx_remote {
	struct zhpe_rx_common	cmn;
	uint64_t		rz_zentries;
	uint64_t		rz_peer_visible;
	uint32_t		completed;
	uint32_t		tail;
	struct zhpe_pe_root	pull_pe_root;
	uint32_t		pull_busy;
	uint32_t		shadow;
};

struct zhpe_rx_local {
	struct zhpe_rx_common	cmn;
	char			*zentries;
	struct zhpe_rx_peer_visible *peer_visible;
	uint32_t		head;
};

struct zhpe_conn {
	union sockaddr_in46	addr;
	struct zhpe_ep_attr	*ep_attr;
	fi_addr_t		fi_addr;
	size_t			av_index;
	struct dlist_entry	ep_lentry;
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_rx_ctx	*rx_ctx;
	fi_addr_t		zq_index;
	struct zhpe_tx		*ztx;
	struct zhpe_rx_local	rx_local;
	struct zhpe_rx_remote	rx_remote;
	fastlock_t		mr_lock;
	RbtHandle		rkey_tree;
	RbtHandle		kexp_tree;
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
	uint8_t			hdr_off;
	uint8_t			state;
};

struct zhpe_conn_map {
	struct zhpe_conn	*table;
	int			used;
	int			size;
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

struct zhpe_domain {
	struct fid_domain	dom_fid;
	struct fi_info		info;
	struct fi_domain_attr	attr;
	struct zhpe_fabric	*fab;
	fastlock_t		lock;
	ofi_atomic32_t		ref;

	struct zhpe_eq		*eq;
	struct zhpe_eq		*mr_eq;

	enum fi_progress	progress_mode;
	struct ofi_mr_map	mr_map;
	uint64_t		mr_user_key;
	uint64_t		mr_zhpe_key;
	struct zhpe_pe		*pe;
	struct dlist_entry	dom_lentry;
	struct zhpeq_dom	*zdom;
};

/* move to fi_trigger.h when removing experimental tag from work queues */
enum {
	ZHPE_DEFERRED_WORK = FI_TRIGGER_THRESHOLD + 1
};

/* move to fi_trigger.h when removing experimental tag from work queues */
/* Overlay with fi_trigger_threshold and within fi_trigger_context */
struct zhpe_trigger_work {
	struct fid_cntr		*triggering_cntr;
	size_t			threshold;
	struct fid_cntr		*completion_cntr;
};

/* must overlay fi_triggered_context */
struct zhpe_triggered_context {
	int					event_type;
	union {
		struct fi_trigger_threshold	threshold;
		struct zhpe_trigger_work	work;
		void				*internal[3];
	} trigger;
};

struct zhpe_trigger {
	enum fi_op_type op_type;
	size_t threshold;
	struct dlist_entry lentry;

	struct zhpe_triggered_context *context;
	struct fid_ep *ep;
	uint64_t flags;

	union {
		struct {
			struct fi_msg msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
		} msg;

		struct {
			struct fi_msg_tagged msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
		} tmsg;

		struct {
			struct fi_msg_rma msg;
			struct iovec msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_rma_iov rma_iov[ZHPE_EP_MAX_IOV_LIMIT];
		} rma;

		struct {
			struct fi_msg_atomic msg;
			struct fi_ioc msg_iov[ZHPE_EP_MAX_IOV_LIMIT];
			void *desc[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_rma_ioc rma_iov[ZHPE_EP_MAX_IOV_LIMIT];
			struct fi_ioc comparev[ZHPE_EP_MAX_IOV_LIMIT];
			void *compare_desc[ZHPE_EP_MAX_IOV_LIMIT];
			size_t compare_count;
			struct fi_ioc resultv[ZHPE_EP_MAX_IOV_LIMIT];
			void *result_desc[ZHPE_EP_MAX_IOV_LIMIT];
			size_t result_count;
		} atomic;
	} op;
};

struct zhpe_cntr {
	struct fid_cntr		cntr_fid;
	struct zhpe_domain	*domain;
	ofi_atomic32_t		value;
	ofi_atomic32_t		ref;
	ofi_atomic32_t		err_cnt;
	ofi_atomic32_t		last_read_val;
	pthread_cond_t 		cond;
	pthread_mutex_t		mut;
	struct fi_cntr_attr	attr;

	struct dlist_entry	rx_list;
	struct dlist_entry	tx_list;
	fastlock_t		list_lock;

	fastlock_t		trigger_lock;
	struct dlist_entry	trigger_list;

	struct fid_wait		*waitset;
	int			signal;
	ofi_atomic32_t		num_waiting;
	int			err_flag;
};

struct zhpe_mr {
	struct fid_mr		mr_fid;
	struct zhpe_domain	*domain;
	uint64_t		flags;
	struct zhpeq_key_data	*kdata;
	struct dlist_entry	kexp_list;
	int32_t			use_count;
};

struct zhpe_av_addr {
	union sockaddr_in46	addr;
};

struct zhpe_av_table_hdr {
	uint64_t		size;
	uint64_t		stored;
};

struct zhpe_av {
	struct fid_av av_fid;
	struct zhpe_domain *domain;
	ofi_atomic32_t ref;
	struct fi_av_attr attr;
	uint64_t mask;
	int rx_ctx_bits;
	socklen_t addrlen;
	struct zhpe_eq *eq;
	struct zhpe_av_table_hdr *table_hdr;
	struct zhpe_av_addr *table;
	uint64_t *idx_arr;
	struct util_shm shm;
	int    shared;
	struct dlist_entry ep_list;
	fastlock_t list_lock;
};

struct zhpe_fid_list {
	struct dlist_entry lentry;
	struct fid *fid;
};

struct zhpe_poll {
	struct fid_poll poll_fid;
	struct zhpe_domain *domain;
	struct dlist_entry fid_list;
};

struct zhpe_wait {
	struct fid_wait wait_fid;
	struct zhpe_fabric *fab;
	struct dlist_entry fid_list;
	enum fi_wait_obj type;
	union {
		int fd[2];
		struct zhpe_mutex_cond {
			pthread_mutex_t	mutex;
			pthread_cond_t	cond;
		} mutex_cond;
	} wobj;
};

#define ZHPE_MSG_TRANSMIT_COMPLETE	(0x01)
#define ZHPE_MSG_DELIVERY_COMPLETE	(0x02)
#define ZHPE_MSG_REMOTE_CQ_DATA		(0x04)
#define ZHPE_MSG_TAGGED			(0x08)
#define ZHPE_MSG_INLINE			(0x10)
#define ZHPE_MSG_VALID_TOGGLE		(0x80)

#define ZHPE_MSG_ANY_COMPLETE \
	(ZHPE_MSG_TRANSMIT_COMPLETE | ZHPE_MSG_DELIVERY_COMPLETE)

enum {
	/* wire protocol */
        ZHPE_OP_NONE = 0,
	ZHPE_OP_NOP,
	ZHPE_OP_SEND,
	ZHPE_OP_STATUS,

	ZHPE_OP_WRITEDATA,

	ZHPE_OP_ATOMIC,

	ZHPE_OP_KEY_REQUEST,
	ZHPE_OP_KEY_RESPONSE,
	ZHPE_OP_KEY_EXPORT,
	ZHPE_OP_KEY_REVOKE,
	ZHPE_OP_SHUTDOWN,
};


enum zhpe_iov_type {
	ZHPE_IOV_IOVEC,
	ZHPE_IOV_ZIOV,
};

struct zhpe_iov_state {
	uint64_t		off;
	void			*viov;
	uint8_t			idx;
	uint8_t			cnt;
};

struct zhpe_iov {
	union {
		void		*iov_base;
		uint64_t	iov_addr;
	};
	uint64_t		iov_len;
	union {
		uint64_t	iov_key;
		struct zhpe_mr	*iov_desc;
	};
	uint64_t		iov_zaddr;
};

struct zhpe_eq_entry {
	uint32_t type;
	size_t len;
	uint64_t flags;
	struct dlist_entry lentry;
	char event[0];
};

struct zhpe_eq_err_data_entry {
	struct dlist_entry lentry;
	int do_free;
	char err_data[];
};

struct zhpe_eq {
	struct fid_eq eq;
	struct fi_eq_attr attr;
	struct zhpe_fabric *zhpe_fab;

	struct dlistfd_head list;
	struct dlistfd_head err_list;
	struct dlist_entry err_data_list;
	fastlock_t lock;

	struct fid_wait *waitset;
	int signal;
	int wait_fd;
	char service[NI_MAXSERV];
};

struct zhpe_comp {
	uint8_t send_cq_event;
	uint8_t recv_cq_event;
	char reserved[2];

	struct zhpe_cq	*send_cq;
	struct zhpe_cq	*recv_cq;

	struct zhpe_cntr *send_cntr;
	struct zhpe_cntr *recv_cntr;
	struct zhpe_cntr *read_cntr;
	struct zhpe_cntr *write_cntr;
	struct zhpe_cntr *rem_read_cntr;
	struct zhpe_cntr *rem_write_cntr;

	struct zhpe_eq *eq;
};

struct zhpe_cm_entry {
	int sock;
	int do_listen;
	int signal_fds[2];
	uint64_t next_msg_id;
	fastlock_t lock;
	int is_connected;
	pthread_t listener_thread;
	struct dlist_entry msg_list;
	bool			listener_thread_valid;
};

struct zhpe_conn_listener {
	int sock;
	int do_listen;
	int signal_fds[2];
	pthread_t listener_thread;
	bool			listener_thread_valid;
};

struct zhpe_ep_attr {
	size_t fclass;

	int tx_shared;
	int rx_shared;
	size_t min_multi_recv;

	ofi_atomic32_t ref;
	struct zhpe_eq *eq;
	struct zhpe_av *av;
	struct zhpe_domain *domain;

	struct zhpe_rx_ctx *rx_ctx;
	struct zhpe_tx_ctx *tx_ctx;

	struct zhpe_rx_ctx **rx_array;
	struct zhpe_tx_ctx **tx_array;
	ofi_atomic32_t num_rx_ctx;
	ofi_atomic32_t num_tx_ctx;

	struct dlist_entry rx_ctx_lentry;
	struct dlist_entry tx_ctx_lentry;

	struct fi_info info;
	struct fi_ep_attr ep_attr;

	enum fi_ep_type ep_type;
	union sockaddr_in46	src_addr;
	union sockaddr_in46	dest_addr;
	in_port_t		msg_src_port;
	in_port_t		msg_dest_port;

	bool			is_enabled;
	bool			rma_event;
	struct zhpe_cm_entry cm;
	struct zhpe_conn_listener listener;
	fastlock_t lock;

	struct index_map av_idm;
	struct zhpe_conn_map cmap;

	fastlock_t		pe_retry_lock;
	struct dlist_entry	pe_retry_list;
	/* Lower-level data */
	pthread_mutex_t		conn_mutex;
	struct zhpe_tx		*ztx;
	/* We need to get back to the ep and it less pain to have a pointer.
	 * I have no clue why the ep_attr is where everything hides.
	 */
	struct zhpe_ep		*ep;
};

struct zhpe_ep {
	struct fid_ep ep;
	struct fi_tx_attr tx_attr;
	struct fi_rx_attr rx_attr;
	struct zhpe_ep_attr *attr;
	int is_alias;
};

struct zhpe_pep {
	struct fid_pep		pep;
	struct zhpe_fabric	*zhpe_fab;
	struct zhpe_cm_entry	cm;
        union sockaddr_in46	src_addr;
	struct fi_info		info;
	struct zhpe_eq		*eq;
	int			name_set;
};

struct zhpe_pe_retry;
typedef void (*zhpe_pe_retry_handler)(struct zhpe_pe_retry *pe_retry);

struct zhpe_pe_retry {
	zhpe_pe_retry_handler	handler;
	struct dlist_entry	lentry;
	void			*data;
};

enum zhpe_rx_state {
	ZHPE_RX_STATE_IDLE,
	ZHPE_RX_STATE_INLINE,
	ZHPE_RX_STATE_RND,
	ZHPE_RX_STATE_RND_BUF,
	ZHPE_RX_STATE_RND_DIRECT,
	ZHPE_RX_STATE_EAGER,
	ZHPE_RX_STATE_EAGER_CLAIMED,
	ZHPE_RX_STATE_EAGER_DONE,
	ZHPE_RX_STATE_COMPLETE,
	ZHPE_RX_STATE_DISCARD,
	ZHPE_RX_STATE_DROP,
};

enum zhpe_rx_buf {
	ZHPE_RX_BUF_USER,
	ZHPE_RX_BUF,
	ZHPE_RX_BUF_EAGER,
};

struct zhpe_msg_hdr {
	uint16_t		seq;
	uint16_t		pe_entry_id;
	uint8_t			op_type;
	uint8_t			rx_id;
	uint8_t			flags;
	union {
		uint8_t		inline_len;
	};
} __attribute__ ((aligned(4)));

struct zhpe_rx_entry {
	struct dlist_entry	lentry;
	struct zhpe_pe_root	pe_root;

	uint64_t		flags;
	uint64_t		addr;
	uint64_t		cq_data;
	uint64_t		tag;
	uint64_t		ignore;
	uint64_t		total_len;
	uint64_t		rem;
	void			*context;
	void			*buf;
	struct zhpe_msg_hdr	zhdr;

	struct zhpe_iov_state	ustate;
	struct zhpe_iov_state	lstate;
	struct zhpe_iov		liov[ZHPE_EP_MAX_IOV_LIMIT];
	union {
		struct {
			struct zhpe_iov_state rstate;
			struct zhpe_iov riov[ZHPE_EP_MAX_IOV_LIMIT];
			struct zhpe_rkey_data *rkeys[ZHPE_EP_MAX_IOV_LIMIT];
			void	*inline_ptr;
		};
		char		inline_data[64];
	};
	ZHPEQ_TIMING_CODE(struct zhpeq_timing_stamp handler_timestamp);
	uint8_t			rx_state;
	uint8_t			buffered;
};

struct zhpe_rx_ctx {
	struct fid_ep ctx;

	uint8_t rx_id;
	int enabled;
	int progress;
	int recv_cq_event;
	int use_shared;

	size_t buffered_len;
	size_t min_multi_recv;
	uint64_t addr;
	struct zhpe_comp comp;
	struct zhpe_rx_ctx *srx_ctx;

	struct zhpe_ep_attr *ep_attr;
	struct zhpe_av *av;
	struct zhpe_eq *eq;
 	struct zhpe_domain *domain;

	struct dlist_entry	pe_lentry;
	struct dlist_entry	cq_lentry;

	struct dlist_entry	rx_posted_list;
	struct dlist_entry	rx_buffered_list;
	struct dlist_entry	rx_work_list;
	struct dlist_entry	ep_list;
	fastlock_t lock;

	struct fi_rx_attr attr;

	struct util_buf_pool	*rx_entry_pool;
	struct zhpe_slab	eager;
};

struct zhpe_tx_ctx {
	union {
		struct fid_ep ctx;
		struct fid_stx stx;
	} fid;
	size_t fclass;

	fastlock_t wlock;
	fastlock_t rlock;

	uint16_t tx_id;
	uint8_t enabled;
	uint8_t progress;

	int use_shared;
	uint64_t addr;
	struct zhpe_comp comp;
	struct zhpe_tx_ctx *stx_ctx;

	struct zhpe_ep_attr *ep_attr;
	struct zhpe_av *av;
	struct zhpe_eq *eq;
 	struct zhpe_domain *domain;

	struct dlist_entry pe_lentry;
	struct dlist_entry cq_lentry;

	struct dlist_entry ep_list;

	struct fi_tx_attr attr;
	fastlock_t lock;
};

struct zhpe_msg_send_indirect {
	uint64_t		tag;
	uint64_t		cq_data;
	uint64_t		vaddr;
	uint64_t		len;
	uint64_t		key;
	char			end[0];
};

struct zhpe_msg_key_request {
	/* ZHPE_EP_MAX_IOV_LIMIT currently 1, max 5 */
	uint64_t		keys[ZHPE_EP_MAX_IOV_LIMIT];
	char			end[0];
};

struct zhpe_msg_key_data {
	char			data[40];
};

/* Must fit in 32 bytes for put-immediate-based implementation. */
struct zhpe_msg_status {
	uint64_t		rem;
	int32_t			status;
	char			end[0];
};

struct zhpe_msg_atomic_req {
	uint64_t		operand;
	uint64_t		compare;
	uint64_t		vaddr;
	uint64_t		key;
	uint8_t			op;
	uint8_t			datatype;
	uint8_t			datasize;
	char			end[0];
};

struct zhpe_msg_writedata {
	uint64_t		flags;
	uint64_t		cq_data;
	char			end[0];
};

/* This structure can only be 40 bytes to fit in ENQA with 8-byte alignment.
 * However, there are 4 bytes free between the header and payload, in that
 * case. It will be used for inline sends, but nothing else, at the moment.
 */
union zhpe_msg_payload {
	struct zhpe_msg_send_indirect indirect;
	struct zhpe_msg_status	status;
	struct zhpe_msg_atomic_req atomic_req;
	struct zhpe_msg_writedata writedata;
	struct zhpe_msg_key_request key_req;
	struct zhpe_msg_key_data key_data;
};

/* PE entry type */

struct zhpe_cqe {
	fi_addr_t		addr;
	struct zhpe_comp	*comp;
	struct fi_cq_tagged_entry cqe;
};

struct zhpe_pe_rma {
	union {
		struct {
			struct zhpe_iov_state lstate;
			struct zhpe_iov liov[ZHPE_EP_MAX_IOV_LIMIT];
		};
		char		inline_data[ZHPEQ_IMM_MAX];
	};
};

struct zhpe_pe_entry {
	struct zhpe_pe_root	pe_root;
	uint64_t		flags;
	uint64_t		rem;
	struct zhpe_iov_state	zstate;
	struct zhpe_iov		ziov[ZHPE_EP_MAX_IOV_LIMIT];
	struct zhpe_rkey_data	*rkeys[ZHPE_EP_MAX_IOV_LIMIT];
	union {
		struct zhpe_pe_rma rma;
		struct {
			void	*result;
			uint8_t	result_type;
		};
	};
	uint64_t		cq_data;
	uint8_t			rx_id;
};

struct zhpe_pe {
	struct zhpe_domain *domain;
	fastlock_t signal_lock;
	pthread_mutex_t list_lock;
	int wcnt, rcnt;
	int signal_fds[2];
	uint64_t waittime;

	struct util_buf_pool *pe_rx_pool;
	struct util_buf_pool *atomic_rx_pool;

	struct dlist_entry tx_list;
	struct dlist_entry rx_list;

	pthread_t progress_thread;
	uint32_t do_progress;
	struct zhpe_pe_entry *pe_atomic;
};

typedef int (*zhpe_cq_report_fn) (struct zhpe_cq *cq, fi_addr_t addr,
				  struct fi_cq_tagged_entry *tcqe);

struct zhpe_cq_overflow_entry_t {
	size_t len;
	fi_addr_t addr;
	struct dlist_entry lentry;
	char cq_entry[0];
};

struct zhpe_cq {
	struct fid_cq cq_fid;
	struct zhpe_domain *domain;
	ssize_t cq_entry_size;
	ofi_atomic32_t ref;
	struct fi_cq_attr attr;

	struct ofi_ringbuf addr_rb;
	struct ofi_ringbuffd cq_rbfd;
	struct ofi_ringbuf cqerr_rb;
	struct dlist_entry overflow_list;
	fastlock_t lock;
	fastlock_t list_lock;

	struct fid_wait *waitset;
	int signal;
	ofi_atomic32_t signaled;

	struct dlist_entry ep_list;
	struct dlist_entry rx_list;
	struct dlist_entry tx_list;

	zhpe_cq_report_fn report_completion;
};

struct zhpe_conn_hdr {
	uint8_t type;
	uint8_t reserved[3];
	uint16_t port;
	uint16_t cm_data_sz;
	/* cm data follows cm_data_sz */
};

struct zhpe_conn_req {
	struct zhpe_conn_hdr	hdr;
	union sockaddr_in46	src_addr;
	uint64_t		caps;
	char			cm_data[0];
};

enum {
	ZHPE_CONN_REQ,
	ZHPE_CONN_ACCEPT,
	ZHPE_CONN_REJECT,
	ZHPE_CONN_SHUTDOWN,
};

struct zhpe_conn_req_handle {
	struct fid		handle;
	struct zhpe_conn_req	*req;
	int			zhpe_fd;
	int			is_accepted;
	struct zhpe_pep		*pep;
	struct zhpe_ep		*ep;
	size_t			paramlen;
	pthread_t		req_handler;
	union sockaddr_in46	dest_addr;
	struct dlist_entry	lentry;
	char			cm_data[ZHPE_EP_MAX_CM_DATA_SZ];
	bool			req_handler_valid;
};

struct zhpe_host_list_entry {
	char hostname[HOST_NAME_MAX];
	struct slist_entry entry;
};

int zhpe_verify_info(uint32_t version, const struct fi_info *hints,
		     uint64_t flags);
int zhpe_verify_fabric_attr(struct fi_fabric_attr *attr);
int zhpe_verify_domain_attr(uint32_t version, const struct fi_info *info);

int zhpe_rdm_verify_ep_attr(struct fi_ep_attr *ep_attr,
			    struct fi_tx_attr *tx_attr,
			    struct fi_rx_attr *rx_attr);
int zhpe_msg_verify_ep_attr(struct fi_ep_attr *ep_attr,
			    struct fi_tx_attr *tx_attr,
			    struct fi_rx_attr *rx_attr);

struct fi_info *zhpe_fi_info(uint32_t version,
			     const struct fi_info *hints,
			     const union sockaddr_in46 *src_addr,
			     const union sockaddr_in46 *dest_addr,
			     uint64_t caps, uint64_t mode,
			     const struct fi_ep_attr *ep_attr,
			     const struct fi_tx_attr *tx_attr,
			     const struct fi_rx_attr *rx_attr);
int zhpe_msg_fi_info(uint32_t version, const union sockaddr_in46 *src_addr,
		     const union sockaddr_in46 *dest_addr,
		     const struct fi_info *hints, struct fi_info **info);
int zhpe_rdm_fi_info(uint32_t version, const union sockaddr_in46 *src_addr,
		     const union sockaddr_in46 *dest_addr,
		     const struct fi_info *hints, struct fi_info **info);
void free_fi_info(struct fi_info *info);

int zhpe_msg_getinfo(uint32_t version, const char *node, const char *service,
		uint64_t flags, struct fi_info *hints, struct fi_info **info);

int zhpe_domain(struct fid_fabric *fabric, struct fi_info *info,
		struct fid_domain **dom, void *context);
void zhpe_dom_add_to_list(struct zhpe_domain *domain);
int zhpe_dom_check_list(struct zhpe_domain *domain);
void zhpe_dom_remove_from_list(struct zhpe_domain *domain);
struct zhpe_domain *zhpe_dom_list_head(void);
int zhpe_dom_check_manual_progress(struct zhpe_fabric *fabric);
int zhpe_query_atomic(struct fid_domain *domain,
		      enum fi_datatype datatype, enum fi_op op,
		      struct fi_atomic_attr *attr, uint64_t flags);

void zhpe_fab_add_to_list(struct zhpe_fabric *fabric);
int zhpe_fab_check_list(struct zhpe_fabric *fabric);
void zhpe_fab_remove_from_list(struct zhpe_fabric *fabric);
struct zhpe_fabric *zhpe_fab_list_head(void);

int zhpe_alloc_endpoint(struct fid_domain *domain, struct fi_info *info,
			struct zhpe_ep **ep, void *context, size_t fclass);
int zhpe_rdm_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int zhpe_rdm_sep(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **sep, void *context);

int zhpe_msg_ep(struct fid_domain *domain, struct fi_info *info,
		struct fid_ep **ep, void *context);
int zhpe_msg_sep(struct fid_domain *domain, struct fi_info *info,
		 struct fid_ep **sep, void *context);
int zhpe_msg_passive_ep(struct fid_fabric *fabric, struct fi_info *info,
			struct fid_pep **pep, void *context);
int zhpe_ep_enable(struct fid_ep *ep);
int zhpe_ep_disable(struct fid_ep *ep);

int zhpe_stx_ctx(struct fid_domain *domain,
		 struct fi_tx_attr *attr, struct fid_stx **stx, void *context);
int zhpe_srx_ctx(struct fid_domain *domain,
		 struct fi_rx_attr *attr, struct fid_ep **srx, void *context);


int zhpe_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context);
int zhpe_cq_report_error(struct zhpe_cq *cq, struct fi_cq_tagged_entry *entry,
			 size_t olen, int err, int prov_errno, void *err_data,
			 size_t err_data_size);
int zhpe_cq_progress(struct zhpe_cq *cq);
void zhpe_cq_add_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cq_remove_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cq_add_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx);
void zhpe_cq_remove_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx);


int zhpe_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		struct fid_eq **eq, void *context);
ssize_t zhpe_eq_report_event(struct zhpe_eq *zhpe_eq, uint32_t event,
			     const void *buf, size_t len, uint64_t flags);
ssize_t zhpe_eq_report_error(struct zhpe_eq *zhpe_eq, fid_t fid, void *context,
			     uint64_t data, int err, int prov_errno,
			     void *err_data, size_t err_data_size);
int zhpe_eq_openwait(struct zhpe_eq *eq, const char *service);

int zhpe_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		   struct fid_cntr **cntr, void *context);
void zhpe_cntr_inc(struct zhpe_cntr *cntr);
int zhpe_cntr_progress(struct zhpe_cntr *cntr);
void zhpe_cntr_add_tx_ctx(struct zhpe_cntr *cntr, struct zhpe_tx_ctx *tx_ctx);
void zhpe_cntr_remove_tx_ctx(struct zhpe_cntr *cntr,
			     struct zhpe_tx_ctx *tx_ctx);
void zhpe_cntr_add_rx_ctx(struct zhpe_cntr *cntr, struct zhpe_rx_ctx *rx_ctx);
void zhpe_cntr_remove_rx_ctx(struct zhpe_cntr *cntr,
			     struct zhpe_rx_ctx *rx_ctx);


struct zhpe_rx_ctx *zhpe_rx_ctx_alloc(const struct fi_rx_attr *attr,
				      void *context, int use_shared,
				      struct zhpe_domain *domain);
void zhpe_rx_ctx_free(struct zhpe_rx_ctx *rx_ctx);

struct zhpe_tx_ctx *zhpe_tx_ctx_alloc(const struct fi_tx_attr *attr,
				      void *context, int use_shared);
struct zhpe_tx_ctx *zhpe_stx_ctx_alloc(const struct fi_tx_attr *attr,
				       void *context);
void zhpe_tx_ctx_free(struct zhpe_tx_ctx *tx_ctx);

int zhpe_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		   struct fid_poll **pollset);
int zhpe_wait_open(struct fid_fabric *fabric, struct fi_wait_attr *attr,
		   struct fid_wait **waitset);
void zhpe_wait_signal(struct fid_wait *wait_fid);
int zhpe_wait_get_obj(struct fid_wait *fid, void *arg);
int zhpe_wait_close(fid_t fid);


int zhpe_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		 struct fid_av **av, void *context);
int zhpe_av_compare_addr(struct zhpe_av *av, fi_addr_t addr1, fi_addr_t addr2);
int zhpe_av_get_addr_index(struct zhpe_av *av,
			   const union sockaddr_in46 *addr);

int zhpe_ep_get_conn(struct zhpe_ep_attr *ep_attr, fi_addr_t index,
		     struct zhpe_conn **pconn);
int zhpe_ep_connect(struct zhpe_ep_attr *attr, struct zhpe_conn *conn);
struct zhpe_conn *zhpe_conn_map_lookup(struct zhpe_ep_attr *ep_attr,
				       const union sockaddr_in46 *addr);
struct zhpe_conn *zhpe_conn_map_insert(struct zhpe_ep_attr *ep_attr,
				       const union sockaddr_in46 *addr);
ssize_t zhpe_conn_send_src_addr(struct zhpe_ep_attr *ep_attr,
				struct zhpe_tx_ctx *tx_ctx,
				struct zhpe_conn *conn);
int zhpe_conn_listen(struct zhpe_ep_attr *ep_attr);
void zhpe_conn_map_destroy(struct zhpe_ep_attr *ep_attr);
void zhpe_conn_release_entry(struct zhpe_ep_attr *attr,
			     struct zhpe_conn *conn);
int zhpe_conn_map_init(struct zhpe_ep *ep, int init_size);
int zhpe_set_sockopts_connect(int sock);
int zhpe_set_sockopts_listen(int sock);
int zhpe_set_sockopts_accept(int sock);
int zhpe_set_sockopt_reuseaddr(int sock);
int zhpe_set_sockopt_nodelay(int sock);
int zhpe_set_fd_cloexec(int fd);
int zhpe_set_fd_nonblock(int fd);
int zhpe_listen(const struct fi_info *info,
		union sockaddr_in46 *ep_addr, int backlog);

int zhpe_conn_z_setup(struct zhpe_conn *conn, int conn_fd, int action);
void zhpe_conn_z_free(struct zhpe_conn *conn);
void zhpe_send_status(struct zhpe_conn *conn,
		      struct zhpe_msg_hdr ohdr, int32_t status, uint64_t rem);
void zhpe_send_key_revoke(struct zhpe_conn *conn, uint64_t key);

struct zhpe_pe *zhpe_pe_init(struct zhpe_domain *domain);
void zhpe_pe_add_tx_ctx(struct zhpe_pe *pe,
			struct zhpe_tx_ctx *ctx);
void zhpe_pe_add_rx_ctx(struct zhpe_pe *pe, struct zhpe_rx_ctx *ctx);
void zhpe_pe_signal(struct zhpe_pe *pe);
void zhpe_pe_poll_add(struct zhpe_pe *pe, int fd);
void zhpe_pe_poll_del(struct zhpe_pe *pe, int fd);
int zhpe_pe_progress_rx_ctx(struct zhpe_pe *pe, struct zhpe_rx_ctx *rx_ctx);
int zhpe_pe_progress_tx_ctx(struct zhpe_pe *pe, struct zhpe_tx_ctx *tx_ctx);
void zhpe_pe_remove_tx_ctx(struct zhpe_tx_ctx *tx_ctx);
void zhpe_pe_remove_rx_ctx(struct zhpe_rx_ctx *rx_ctx);
void zhpe_pe_finalize(struct zhpe_pe *pe);
int zhpe_pe_tx_handle_entry(struct zhpe_pe_root *pe_root,
			    struct zhpeq_cq_entry *zq_cqe);
void zhpe_pe_rx_peek_recv(struct zhpe_rx_ctx *rx_ctx, fi_addr_t addr,
			  uint64_t tag, uint64_t ignore,
			  uint64_t flags, struct fi_context *context);
void zhpe_pe_rx_claim_recv(struct zhpe_rx_entry *rx_claimed,
			   struct zhpe_rx_entry *rx_entry);
void zhpe_pe_rx_post_recv(struct zhpe_rx_ctx *rx_ctx,
			  struct zhpe_rx_entry *rx_entry);
void zhpe_pe_rx_complete(struct zhpe_rx_ctx *rx_ctx,
			 struct zhpe_rx_entry *rx_entry,
			 int status, bool locked);
int zhpe_pe_tx_handle_rma(struct zhpe_pe_root *pe_root,
			  struct zhpeq_cq_entry *zq_cqe);
int zhpe_pe_tx_handle_atomic(struct zhpe_pe_root *pe_root,
			     struct zhpeq_cq_entry *zq_cqe);
void zhpe_pe_tx_rma(struct zhpe_pe_entry *pe_entry);
void zhpe_pe_rkey_request(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			  struct zhpe_iov_state *rstate);

ssize_t zhpe_do_recvmsg(struct fid_ep *ep, const void *vmsg, uint64_t flags,
			bool tagged);
ssize_t zhpe_do_sendmsg(struct fid_ep *ep, const void *vmsg, uint64_t flags,
			bool tagged);
ssize_t zhpe_do_rma_msg(struct fid_ep *ep, const struct fi_msg_rma *msg,
			uint64_t flags);
ssize_t zhpe_do_tx_atomic(struct fid_ep *ep,
			  const struct fi_msg_atomic *msg,
			  const struct fi_ioc *comparev, void **compare_desc,
			  size_t compare_count, struct fi_ioc *resultv,
			  void **result_desc, size_t result_count,
			  uint64_t flags);

int zhpe_queue_work(struct zhpe_domain *dom, struct fi_deferred_work *work);
ssize_t zhpe_queue_rma_op(struct fid_ep *ep, const struct fi_msg_rma *msg,
			  uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_atomic_op(struct fid_ep *ep,
			     const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev,
			     size_t compare_count,
			     struct fi_ioc *resultv, size_t result_count,
			     uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_tmsg_op(struct fid_ep *ep, const struct fi_msg_tagged *msg,
			   uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_msg_op(struct fid_ep *ep, const struct fi_msg *msg,
			  uint64_t flags, enum fi_op_type op_type);
ssize_t zhpe_queue_cntr_op(struct fi_deferred_work *work, uint64_t flags);
void zhpe_cntr_check_trigger_list(struct zhpe_cntr *cntr);

int zhpe_tx_free_res(struct zhpe_conn *conn, int64_t tindex, int64_t zindex,
		     int64_t rindex, uint8_t pe_flags);
int zhpe_slab_init(struct zhpe_slab *mem, size_t size,
		   struct zhpe_domain *domain);
void zhpe_slab_destroy(struct zhpe_slab *mem);
int zhpe_slab_alloc(struct zhpe_slab *slab, size_t size, struct zhpe_iov *iov);
void zhpe_slab_free(struct zhpe_slab *mem, void *ptr);
int zhpe_iov_op_get(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context);
int zhpe_iov_op_get_imm(struct zhpeq *zq, uint32_t zindex, bool fence,
			void *lptr, uint64_t lza, size_t len, uint64_t rza,
			void *context);
int zhpe_iov_op_put(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context);
int zhpe_iov_op(struct zhpe_pe_root *pe_root,
		struct zhpe_iov_state *lstate,
		struct zhpe_iov_state *rstate,
		size_t max_bytes, uint8_t max_ops,
		int (*op)(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len,
			  uint64_t rza, void *context),
		size_t *rem);
int zhpe_put_imm_to_iov(struct zhpe_pe_root *pe_root, void *lbuf,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem);
int zhpe_iov_to_get_imm(struct zhpe_pe_root *pe_root,
			size_t llen, struct zhpe_iov_state *rstate,
			size_t *rem);

/* Cannot conflict with legal access flags. */
#define ZHPE_MR_KEY_FREEING	(1ULL << 62)
#define ZHPE_MR_KEY_ONESHOT	(1ULL << 63)

int zhpe_mr_reg_int(struct zhpe_domain *domain, const void *buf, size_t len,
		    uint64_t access, struct fid_mr **mr);
int zhpe_mr_reg_int_oneshot(struct zhpe_domain *domain, struct zhpe_iov *ziov,
			    size_t len, uint64_t access);
int zhpe_mr_close(struct fid *fid);
int zhpe_mr_close_oneshot(struct zhpe_iov *ziov, uint32_t count, bool revoke);

#define likely(x)		__builtin_expect((x), 1)
#define unlikely(x)		__builtin_expect((x), 0)

#define ZHPE_CONTEXT_IGNORE	((uintptr_t)1)
#define ZHPE_CONTEXT_IGNORE_PTR	((void *)ZHPE_CONTEXT_IGNORE)

int __zhpe_conn_pull(struct zhpe_conn *conn);

static inline void
zhpe_conn_pull(struct zhpe_conn *conn)
{
	int			rc;
	uint32_t		*shadowp = &conn->rx_remote.shadow;
	uint32_t		*currentp = &conn->rx_remote.tail;
	uint32_t		threshold;

	/* Check if we want to pull; 1/4 is pulled out of the air. */
	threshold = (conn->rx_remote.cmn.mask + 1) / 4;
	if ((atomic_load_lazy_uint32(currentp) -
	     atomic_load_lazy_uint32(shadowp)) < threshold)
		goto done;
	/* Is there a pull in progress or, given that atomic is a CPU fence,
	 * has shadow updated?
	 */
	if (__sync_fetch_and_add(&conn->rx_remote.pull_busy, 1) ||
	    (atomic_load_lazy_uint32(currentp) -
	     atomic_load_lazy_uint32(shadowp)) < threshold) {
		/* Yes. */
		__sync_fetch_and_sub(&conn->rx_remote.pull_busy, 1);
		goto done;
	}
	rc = __zhpe_conn_pull(conn);
	if (rc < 0)
		__sync_fetch_and_sub(&conn->rx_remote.pull_busy, 1);
 done:
	return;
}

static inline int64_t zhpe_tx_reserve(struct zhpe_tx *ztx, uint8_t pe_flags)
{
	int64_t			ret = -FI_EAGAIN;
	uint64_t		*blobp;
	union zhpe_free_index	old;
	union zhpe_free_index	new;

	/* Using a union this way is not in the C spec, just expected to
	 * work with most compilers/processors.
	 */
	blobp = ((pe_flags & ZHPE_PE_PROV) ?
		 &ztx->pfree.blob : &ztx->ufree.blob);
	for (old.blob = new.blob = atomic_load_lazy_uint64(blobp);;) {
		if (!new.count)
			goto done;
		new.index = ztx->pentries[new.index].pe_root.status;
		new.count--;
		new.seq++;
		new.blob = __sync_val_compare_and_swap(blobp,
						       old.blob, new.blob);
		if (old.blob == new.blob)
			break;
		old.blob = new.blob;
	}
	ret = old.index;
 done:
	return ret;
}

static inline void
zhpe_tx_release(struct zhpe_tx *ztx, uint32_t tindex, uint8_t pe_flags)
{
	uint64_t		*blobp;
	union zhpe_free_index	old;
	union zhpe_free_index	new;

	/* Using a union this way is not in the C spec, just expected to
	 * work with most compilers/processors.
	 */
	blobp = ((pe_flags & ZHPE_PE_PROV) ?
		 &ztx->pfree.blob : &ztx->ufree.blob);
	for (old.blob = new.blob = atomic_load_lazy_uint64(blobp);;) {
		ztx->pentries[tindex].pe_root.status = new.index;
		new.index = tindex;
		new.count++;
		new.seq++;
		new.blob = __sync_val_compare_and_swap(blobp,
						       old.blob, new.blob);
		if (old.blob == new.blob)
			break;
		old.blob = new.blob;
	}
}

static inline uint32_t
zhpe_rx_remote_avail(struct zhpe_rx_remote *rx_ringr)
{
	/* Can be stale, but never too large. */
	return rx_ringr->cmn.mask + 1 -
		(atomic_load_lazy_uint32(&rx_ringr->tail) -
		 atomic_load_lazy_uint32(&rx_ringr->shadow));
}

static inline size_t zhpe_ring_off(struct zhpe_conn *conn, uint32_t index)
{
	return ZHPE_RING_ENTRY_LEN * index + conn->hdr_off;
}

static inline void *
zhpe_pay_ptr(struct zhpe_conn *conn, struct zhpe_msg_hdr *zhdr,
	     size_t off, size_t alignment)
{
	off += fi_get_aligned_sz(conn->hdr_off + sizeof(*zhdr), sizeof(int));
	off = fi_get_aligned_sz(off, alignment);

	return (char *)zhdr + off - conn->hdr_off;
}

#define zhpe_tx_reserve_vars(_ret, _handler, _conn, _context,		\
			     _tindex, _pe_entry, _zhdr, _lzaddr, _err,	\
			     _pe_flags)					\
do {									\
	struct zhpe_tx		*_ztx = (_conn)->ztx;			\
	size_t			_off;					\
									\
	(_ret) = 0;							\
	if (!zhpe_rx_remote_avail(&(_conn)->rx_remote))			\
		(_ret) = -FI_EAGAIN;					\
	if ((_ret) >= 0)						\
		(_ret) = zhpe_tx_reserve(_ztx, (_pe_flags));		\
	if ((_ret) >= 0) {						\
		(_tindex) = (_ret);					\
		_off = zhpe_ring_off(conn, tindex);			\
		(_lzaddr) = _ztx->lz_zentries + _off;			\
		(_zhdr) = (void *)(_ztx->zentries + _off);		\
		(_pe_entry) = &_ztx->pentries[tindex];			\
		(_pe_entry)->pe_root.flags = 0;				\
	} else if ((_pe_flags) & ZHPE_PE_RETRY) {			\
		if ((_ret) != -FI_EAGAIN)				\
			goto _err; 					\
		(_ret) = -FI_ENOMEM;					\
		(_pe_entry) = malloc(sizeof(*(_pe_entry)) +		\
				     ZHPE_RING_ENTRY_LEN);		\
		if (!(_pe_entry))					\
			goto _err;					\
		(_zhdr) = (void *)((char *)((_pe_entry) + 1) +		\
				   (_conn)->hdr_off);			\
		(_pe_entry)->pe_root.flags = ZHPE_PE_RETRY;		\
	} else								\
		goto _err;						\
	(_pe_entry)->pe_root.handler = (_handler);			\
	(_pe_entry)->pe_root.conn = (_conn);				\
	(_pe_entry)->pe_root.context = (_context);			\
	(_pe_entry)->pe_root.status = 0;				\
	(_pe_entry)->pe_root.completions = 1;				\
	(_pe_entry)->pe_root.flags |= ((_pe_flags) & ~ZHPE_PE_RETRY);	\
	(_pe_entry)->zstate.cnt = 0;					\
} while (0)

static inline int64_t
zhpe_rx_remote_reserve(struct zhpe_conn *conn, struct zhpe_msg_hdr *hdr)
{
	int64_t			ret = -FI_EAGAIN;
	struct zhpe_rx_remote   *rx_ringr = &conn->rx_remote;
	uint32_t		tail;
	uint32_t		new;
	uint32_t		avail;

	for (tail = atomic_load_lazy_uint32(&rx_ringr->tail);;) {
		avail = (rx_ringr->cmn.mask + 1 -
			 (tail - atomic_load_lazy_uint32(&rx_ringr->shadow)));
		if (!avail)
			goto done;
		new = __sync_val_compare_and_swap(&rx_ringr->tail,
						  tail, tail + 1);
		if (new == tail)
			break;
		tail = new;
	}
	if (tail & (rx_ringr->cmn.mask + 1))
	    hdr->flags &= ~ZHPE_MSG_VALID_TOGGLE;
	else
	    hdr->flags |= ZHPE_MSG_VALID_TOGGLE;
	ret = (tail & rx_ringr->cmn.mask);
 done:
	return ret;
}

static inline uint32_t
zhpe_rx_scoreboard(struct zhpe_rx_common *rx_cmn, uint32_t rindex,
		   uint32_t completed)
{
	const uint32_t		bits = sizeof(*rx_cmn->scoreboard) * CHAR_BIT;
	const uint32_t		shift_mask = bits - 1;
	uint32_t		sindex;
	uint64_t		smask;

	/* Update scoreboard bitmask for completed op; only updated and
	 * checked from the progress thread.
	 */
	smask = (1UL << (rindex & shift_mask));
	sindex = rindex / bits;
	rx_cmn->scoreboard[sindex] |= smask;
	/* Try to advance completed. */
	for (;; completed++) {
		rindex = (completed & rx_cmn->mask);
		smask = (1UL << (rindex & shift_mask));
		sindex = rindex / bits;
		if (!(rx_cmn->scoreboard[sindex] & smask))
			break;
		rx_cmn->scoreboard[sindex] &= ~smask;
	}

	return completed;
}

static inline void
zhpe_rx_remote_release(struct zhpe_conn *conn, uint32_t rindex)
{
	/* Caller responsible for making sure rindex valid. */
	conn->rx_remote.completed =
		zhpe_rx_scoreboard(&conn->rx_remote.cmn, rindex,
				   conn->rx_remote.completed);
}

static inline void
zhpe_rx_local_release(struct zhpe_conn *conn, uint32_t rindex)
{
	uint32_t		completed;

	completed = ntohl(conn->rx_local.peer_visible->completed);
	completed = zhpe_rx_scoreboard(&conn->rx_local.cmn, rindex, completed);
	atomic_store_lazy_uint32(&conn->rx_local.peer_visible->completed,
				 htonl(completed));
}

static inline bool
zhpe_rx_match_entry(struct zhpe_rx_entry *rx_entry, fi_addr_t addr,
		    uint64_t tag,uint64_t ignore, uint64_t flags)
{

	struct zhpe_av		*av;

	if ((rx_entry->flags & FI_TAGGED) != (flags & FI_TAGGED))
		return false;
	if ((rx_entry->tag & ~ignore) != (tag & ~ignore))
		return false;
	if (rx_entry->addr == FI_ADDR_UNSPEC || addr == FI_ADDR_UNSPEC ||
	    rx_entry->addr == addr)
		return true;
	av = rx_entry->pe_root.conn->rx_ctx->av;
	return (av && !zhpe_av_compare_addr(av, rx_entry->addr, addr));
}

static inline void *zhpe_iov_entry(const void *viov,
				   enum zhpe_iov_type type, size_t idx)
{
	size_t			size;

	switch (type) {

	case ZHPE_IOV_IOVEC:
		size = sizeof(struct iovec);
		break;

	case ZHPE_IOV_ZIOV:
		size = sizeof(struct zhpe_iov);
		break;

	default:
		abort();;
	}

	return ((char *)viov + size * idx);
}

static inline void *zhpe_iov_base(const void *viov,
				  enum zhpe_iov_type type, size_t idx)
{
	void			*ret;
	size_t			size;
	struct iovec		*iov;
	struct zhpe_iov		*ziov;

	switch (type) {

	case ZHPE_IOV_IOVEC:
		size = sizeof(*iov);
		iov = (void *)((char *)viov + size * idx);
		ret = iov->iov_base;
		break;

	case ZHPE_IOV_ZIOV:
		size = sizeof(*iov);
		ziov = (void *)((char *)viov + size * idx);
		ret = ziov->iov_base;
		break;

	default:
		abort();
	}

	return ret;
}

static inline uint64_t zhpe_iov_len(const void *viov,
				    enum zhpe_iov_type type, size_t idx)
{
	uint64_t		ret;
	size_t			size;
	struct iovec		*iov;
	struct zhpe_iov		*ziov;

	switch (type) {

	case ZHPE_IOV_IOVEC:
		size = sizeof(*iov);
		iov = (void *)((char *)viov + size * idx);
		ret = iov->iov_len;
		break;

	case ZHPE_IOV_ZIOV:
		size = sizeof(*ziov);
		ziov = (void *)((char *)viov + size * idx);
		ret = ziov->iov_len;
		break;

	default:
		abort();
	}

	return ret;
}

static inline void *zhpe_iov_state_entry(const struct zhpe_iov_state *state,
					 enum zhpe_iov_type type)
{
	return zhpe_iov_entry(state->viov, type, state->idx);
}

static inline void *zhpe_iov_state_ptr(const struct zhpe_iov_state *state,
				       enum zhpe_iov_type type)
{
	return ((char *)zhpe_iov_base(state->viov, type, state->idx) +
		state->off);
}

static inline uint64_t zhpe_iov_state_len(const struct zhpe_iov_state *state,
					  enum zhpe_iov_type type)
{
	return (zhpe_iov_len(state->viov, type, state->idx) - state->off);
}

static inline uint64_t zhpe_iov_state_adv(struct zhpe_iov_state *state,
					  enum zhpe_iov_type type,
					  uint64_t incr)
{
	uint64_t		slen;

	slen = zhpe_iov_len(state->viov, type, state->idx);
	state->off += incr;
	if (state->off == slen) {
		state->idx++;
		state->off = 0;
	}

	return (state->idx >= state->cnt);
}

static inline uint64_t zhpe_iov_state_used(const struct zhpe_iov_state *state,
					   enum zhpe_iov_type type,
					   uint64_t *total_out)
{
	uint64_t		ret = 0;
	uint64_t		total = 0;
	size_t			i;

	for (i = 0; i < state->idx; i++) {
		total += zhpe_iov_len(state->viov, type, i);
	}
	ret = total + state->off;
	for (; i < state->cnt; i++)
		total += zhpe_iov_len(state->viov, type, i);
	*total_out = total;

	return ret;
}

static inline int zhpe_iov_state_empty(const struct zhpe_iov_state *state)
{
	return (state->idx >= state->cnt);
}

static inline uint64_t zhpe_iov_state_avail(const struct zhpe_iov_state *state,
					    enum zhpe_iov_type type)
{
	uint64_t		ret = 0;
	size_t			i;

	if (!zhpe_iov_state_empty(state)) {
		i = state->idx;
		ret += zhpe_iov_len(state->viov, type, i++);
		for (; i < state->idx; i++) {
			ret += zhpe_iov_len(state->viov, type, i);
		}
	}

	return ret;
}

static inline void zhpe_iov_state_reset(struct zhpe_iov_state *state)
{
	state->off = 0;
	state->idx = 0;
}

static inline void *zhpe_ziov_state_entry(const struct zhpe_iov_state *state)
{
	return zhpe_iov_state_entry(state, ZHPE_IOV_ZIOV);
}

static inline void *zhpe_ziov_state_ptr(const struct zhpe_iov_state *state)
{
	return zhpe_iov_state_ptr(state, ZHPE_IOV_ZIOV);
}

static inline uint64_t zhpe_ziov_state_len(const struct zhpe_iov_state *state)
{
	return zhpe_iov_state_len(state, ZHPE_IOV_ZIOV);
}

static inline uint64_t zhpe_ziov_zaddr(const struct zhpe_iov *ziov, size_t idx)
{
	return ziov[idx].iov_zaddr;
}

static inline uint64_t
zhpe_ziov_state_zaddr(const struct zhpe_iov_state *state)
{

	return (zhpe_ziov_zaddr(state->viov, state->idx) + state->off);
}

static inline struct zhpe_mr *zhpe_ziov_desc(const struct zhpe_iov *ziov,
					     size_t idx)
{
	return ziov[idx].iov_desc;
}

static inline struct zhpe_mr *
zhpe_ziov_state_desc(const struct zhpe_iov_state *state)
{

	return zhpe_ziov_desc(state->viov, state->idx);
}

static inline uint64_t zhpe_ziov_key(const struct zhpe_iov *ziov, size_t idx)
{
	return ziov[idx].iov_key;
}

static inline uint64_t zhpe_ziov_state_key(const struct zhpe_iov_state *state)
{

	return zhpe_ziov_key(state->viov, state->idx);
}

static inline uint64_t zhpe_ziov_state_adv(struct zhpe_iov_state *state,
					  uint64_t incr)
{
	return zhpe_iov_state_adv(state, ZHPE_IOV_ZIOV, incr);
}

static inline uint64_t zhpe_ziov_state_used(struct zhpe_iov_state *state,
					   uint64_t *total_out)
{
	return zhpe_iov_state_used(state, ZHPE_IOV_ZIOV, total_out);
}

static inline int zhpe_ziov_state_empty(struct zhpe_iov_state *state)
{
	return (state->idx >= state->cnt);
}

static inline uint64_t zhpe_ziov_state_avail(struct zhpe_iov_state *state)
{
	return zhpe_iov_state_avail(state, ZHPE_IOV_ZIOV);
}

static inline void zhpe_ziov_state_reset(struct zhpe_iov_state *state)
{
	state->off = 0;
	state->idx = 0;
}

static inline size_t copy_iov(struct zhpe_iov_state *dstate,
			      enum zhpe_iov_type dtype,
			      struct zhpe_iov_state *sstate,
			      enum zhpe_iov_type stype, size_t n)
{
	size_t			ret = 0;
	size_t			len;
	size_t			slen;
	size_t			dlen;
	char			*sptr;
	char			*dptr;

	while (n > 0 &&
	       !zhpe_iov_state_empty(sstate) &&
	       !zhpe_iov_state_empty(dstate)) {
		slen = zhpe_iov_state_len(sstate, stype);
		sptr = zhpe_iov_state_ptr(sstate, stype);
		dlen = zhpe_iov_state_len(dstate, dtype);
		dptr = zhpe_iov_state_ptr(dstate, dtype);

		len = slen;
		if (len > dlen)
			len = dlen;
		memcpy(dptr, sptr, len);

		ret += len;
		n -= len;
		zhpe_iov_state_adv(sstate, ZHPE_IOV_ZIOV, len);
		zhpe_iov_state_adv(dstate, ZHPE_IOV_ZIOV, len);
	}

	return ret;
}

static inline size_t copy_iov_to_mem(void *dst, struct zhpe_iov_state *sstate,
				     enum zhpe_iov_type stype, size_t n)
{
	struct iovec		diov = { .iov_base = dst, .iov_len = n };
	struct zhpe_iov_state	dstate = { .viov = &diov, .cnt = 1 };

	return copy_iov(&dstate, ZHPE_IOV_IOVEC, sstate, stype, n);
}

static inline size_t copy_mem_to_iov(struct zhpe_iov_state *dstate,
				     enum zhpe_iov_type dtype,
				     const void *src, size_t n)
{
	struct iovec		siov = {
		.iov_base = (void *)src,
		.iov_len = n,
	};
	struct zhpe_iov_state	sstate = { .viov = &siov, .cnt = 1 };

	return copy_iov(dstate, dtype, &sstate, ZHPE_IOV_IOVEC, n);
}

static inline void zhpe_pe_retry_insert(struct zhpe_conn *conn,
					struct zhpe_pe_retry *pe_retry)
{
	struct zhpe_ep_attr	*ep_attr = conn->ep_attr;

	fastlock_acquire(&ep_attr->pe_retry_lock);
	dlist_insert_tail(&pe_retry->lentry, &conn->ep_attr->pe_retry_list);
	fastlock_release(&ep_attr->pe_retry_lock);
}

static inline int zhpe_pe_retry(struct zhpe_conn *conn,
				zhpe_pe_retry_handler handler, void *data)
{
	struct zhpe_pe_retry	*pe_retry = malloc(sizeof(*pe_retry));

	if (!pe_retry)
		return -FI_ENOMEM;
	pe_retry->handler = handler;
	pe_retry->data = data;
	zhpe_pe_retry_insert(conn, pe_retry);

	return 0;
}

void zhpe_pe_retry_tx_ring1(struct zhpe_pe_retry *pe_retry);
void zhpe_pe_retry_tx_ring2(struct zhpe_pe_retry *pe_retry);

#define ZHPE_MASK_COMPLETE \
	(FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE)

static inline uint64_t zhpe_tx_fixup_completion(uint64_t flags)
{
	if (flags & FI_DELIVERY_COMPLETE)
		flags &= ~(FI_INJECT_COMPLETE | FI_TRANSMIT_COMPLETE);
	else if (flags & FI_TRANSMIT_COMPLETE)
		flags &= ~FI_INJECT_COMPLETE;

	return flags;
}

void _zhpe_pe_tx_report_complete(const struct zhpe_pe_entry *pe_entry);

static inline void zhpe_pe_tx_report_complete(struct zhpe_pe_entry *pe_entry,
					      uint64_t flags)
{
	if (flags & pe_entry->flags)
		_zhpe_pe_tx_report_complete(pe_entry);
}

static inline int zhpe_pe_tx_ring(struct zhpe_pe_entry *pe_entry,
				  struct zhpe_msg_hdr *zhdr, uintptr_t zbuf,
				  size_t len)
{
	int64_t			ret = -EINVAL;
	struct zhpe_pe_root	*pe_root = &pe_entry->pe_root;
	struct zhpe_conn	*conn = pe_root->conn;
	struct zhpe_tx		*ztx = conn->ztx;
	int64_t			zindex = -1;
	int64_t			rindex = -1;
	uint64_t		rzaddr;

	if (unlikely(pe_root->flags & ZHPE_PE_RETRY)) {
		ret = zhpe_pe_retry(conn, zhpe_pe_retry_tx_ring1, pe_root);
		goto done;
	}

	ret = zhpeq_reserve(ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;
	ret = zhpe_rx_remote_reserve(conn, zhdr);
	if (ret < 0)
		goto done;
	pe_root->rindex = rindex = ret;
	rzaddr = conn->rx_remote.rz_zentries + zhpe_ring_off(conn, rindex);

	if (len <= ZHPEQ_IMM_MAX)
		ret = zhpeq_puti(ztx->zq, zindex, false, zhdr, len,
				 rzaddr, pe_root);
	else if (len <= ZHPE_RING_ENTRY_LEN)
		ret = zhpeq_put(ztx->zq, zindex, false, zbuf, len,
				rzaddr, pe_root);
	else
		ret = -FI_EINVAL;
	if (ret < 0)
		goto done;
	ret = zhpeq_commit(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
	zhpe_pe_signal(conn->ep_attr->domain->pe);
 done:
	if (likely(ret >= 0))
		zhpe_pe_tx_report_complete(pe_entry, FI_INJECT_COMPLETE);
	else {
		zhpe_tx_free_res(conn, -1, zindex, rindex, pe_root->flags);
		if (ret == -FI_EAGAIN && (pe_root->flags & ZHPE_PE_PROV))
			ret = zhpe_pe_retry(conn, zhpe_pe_retry_tx_ring2,
					    pe_entry);
	}
	/* Must be done after zhpeq_commit() to prevent deadlock. */
	zhpe_conn_pull(conn);

	return ret;
}

static inline int zhpe_tx_op(struct zhpe_conn *conn, struct zhpe_msg_hdr ohdr,
			     uint8_t pe_flags, void *pay, size_t pay_len,
			     void *context)
{
	int			ret;
	int64_t			tindex = -1;
	uint64_t		lzaddr = 0;
	struct zhpe_pe_entry	*pe_entry;
	struct zhpe_msg_hdr	*zhdr;
	union zhpe_msg_payload	*zpay;
	size_t			cmd_len;

	zhpe_tx_reserve_vars(ret, zhpe_pe_tx_handle_entry, conn, context,
			     tindex, pe_entry, zhdr, lzaddr, done, pe_flags);
	*zhdr = ohdr;
	if (!(pe_flags & ZHPE_PE_PROV))
		zhdr->pe_entry_id = tindex;
	zhdr->flags = 0;
	zpay = zhpe_pay_ptr(conn, zhdr, 0, alignof(*zpay));
	memcpy(zpay, pay, pay_len);
	cmd_len = ((char *)zpay - (char *)zhdr) + pay_len;
	zhdr->inline_len = cmd_len;
	ret = zhpe_pe_tx_ring(pe_entry, zhdr, lzaddr, cmd_len);
 done:
 	if (ret < 0 && (pe_flags & ZHPE_PE_RETRY)) {
		_ZHPE_LOG_ERROR(FI_LOG_CORE,
				"Failed to send provider op %d\n", ret);
		abort();
	}

	return ret;
}

static inline int zhpe_prov_op(struct zhpe_conn *conn,
			       struct zhpe_msg_hdr ohdr, uint8_t pe_flags,
			       void *pay, size_t pay_len)
{
	pe_flags |= ZHPE_PE_PROV;
	return zhpe_tx_op(conn, ohdr, pe_flags, pay, pay_len, NULL);
}

void zhpe_tx_free(struct zhpe_tx *ztx);

static inline void zhpe_tx_put(struct zhpe_tx *ztx)
{
	int32_t			old;

	if (!ztx)
		return;
	old = __sync_fetch_and_sub(&ztx->use_count, 1);
	assert(old > 0);
	if (old > 1)
		return;

	zhpe_tx_free(ztx);
}

struct zhpe_rkey_data *zhpe_conn_rkey_get(struct zhpe_conn *conn,
					  uint64_t rkey);

static inline void zhpe_rkey_put(struct zhpe_rkey_data *rkey)
{
	int32_t			old;

	if (!rkey)
		return;
	old = __sync_fetch_and_sub(&rkey->use_count, 1);
	assert(old > 0);
	if (old > 1)
		return;

	zhpeq_zmmu_free(rkey->ztx->zq, rkey->kdata);
	zhpe_tx_put(rkey->ztx);
	free(rkey);
}

int zhpe_conn_rkey_revoke(struct zhpe_conn *conn, uint64_t key);

static inline void zhpe_kexp_put(struct zhpe_kexp_data *kexp)
{
	int32_t			old;
	struct zhpe_domain	*domain;

	if (!kexp)
		return;
	old = __sync_fetch_and_sub(&kexp->use_count, 1);
	assert(old > 0);
	if (old > 1)
		return;

	if (!dlist_empty(&kexp->lentry)) {
		domain = kexp->conn->ep_attr->domain;
		fastlock_acquire(&domain->lock);
		dlist_remove(&kexp->lentry);
		fastlock_release(&domain->lock);
	}
	free(kexp);
}

struct zhpe_mr *zhpe_mr_get(struct zhpe_domain *domain, uint64_t key);

static inline void zhpe_mr_put(struct zhpe_mr *zmr)
{
	int32_t			old;

	if (!zmr)
		return;
	old = __sync_fetch_and_sub(&zmr->use_count, 1);
	assert(old > 0);
	if (old > 1)
		return;

	zhpeq_mr_free(zmr->domain->zdom, zmr->kdata);
	free(zmr);
}

static inline bool zhpe_mr_key_int(uint64_t key)
{
	return (key > (uint64_t)UINT32_MAX);
}

int zhpe_conn_key_export(struct zhpe_conn *conn, struct zhpe_mr *zmr,
			 bool response, struct zhpe_msg_hdr ohdr);
int zhpe_conn_rkey_import(struct zhpe_conn *conn, const void *blob,
			  size_t blob_len, struct zhpe_rkey_data **rkey_out);

int zhpe_send_blob(int sock_fd, const void *blob, size_t blob_len);
int zhpe_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len);

const char *zhpe_ntop(const union sockaddr_in46 *sin46, char *buf, size_t len);
void zhpe_getaddrinfo_hints_init(struct addrinfo *hints, uint32_t addr_format);
int zhpe_getaddrinfo(const char *node, const char *service,
		     struct addrinfo *hints, struct addrinfo **res);
struct addrinfo *zhpe_findaddrinfo(struct addrinfo *res, int family);
int zhpe_gethostaddr(uint32_t fi_addr_format, union sockaddr_in46 *addr);

static inline uint32_t zhpe_convert_access(uint64_t access) {
	uint32_t		ret = ZHPEQ_MR_KEY_VALID;

	if (access & (FI_READ | FI_RECV))
		ret |= ZHPEQ_MR_GET;
	if (access & (FI_WRITE | FI_SEND))
		ret |= ZHPEQ_MR_PUT;
	if (access & (FI_REMOTE_READ | FI_SEND))
		ret |= ZHPEQ_MR_GET_REMOTE;
	if (access & FI_REMOTE_WRITE)
		ret |= ZHPEQ_MR_PUT_REMOTE;
	if (access & ZHPE_MR_KEY_ONESHOT)
		ret |= ZHPEQ_MR_KEY_ONESHOT;
	return ret;
}

static inline struct zhpe_rx_entry *
zhpe_rx_new_entry(struct zhpe_rx_ctx *rx_ctx)
{
	struct zhpe_rx_entry	*ret;

	/* rx_ctx->lock assumed to be locked. */
	ret = util_buf_alloc(rx_ctx->rx_entry_pool);
	if (!ret)
		goto done;
	_ZHPE_LOG_DBG(FI_LOG_EP_DATA,
		      "New rx_entry: %p, ctx: %p\n", ret, rx_ctx);
	ret->pe_root.status = 0;
	ret->buffered = ZHPE_RX_BUF_USER;
	ret->flags = FI_MSG | FI_RECV;
	ret->lstate.viov = ret->liov;
	ret->lstate.off = 0;
	ret->lstate.idx = 0;
	zhpe_ziov_state_reset(&ret->lstate);
 done:
	return ret;
}

static inline void zhpe_rx_release_entry(struct zhpe_rx_ctx *rx_ctx,
					 struct zhpe_rx_entry *rx_entry)
{
	struct zhpe_iov		*liov;

	/* rx_ctx->lock assumed to be locked. */
	if (!rx_entry)
		return;
	if (rx_entry->buffered == ZHPE_RX_BUF_EAGER) {
		liov = rx_entry->liov;
		zhpe_slab_free(&rx_ctx->eager, liov->iov_base);
		__sync_fetch_and_sub(&rx_ctx->buffered_len, liov->iov_len);
	}
	_ZHPE_LOG_DBG(FI_LOG_EP_DATA, "Releasing rx_entry: %p\n", rx_entry);
	util_buf_release(rx_ctx->rx_entry_pool, rx_entry);
}

static inline void abort_if_nonzero(int ret, const char *func, uint line)
{
	if (!ret)
		return;

	_ZHPE_LOG_ERROR(FI_LOG_CORE, "Unexpected error %d\n", ret);
	abort();
}

static inline int abort_trylock(int ret, const char *func, uint line)
{
	if (!ret)
		return 0;
	if (ret == EBUSY)
		return -FI_EBUSY;

	_ZHPE_LOG_ERROR(FI_LOG_CORE, "Unexpected error %d\n", ret);
	abort();
}

static inline int abort_timedwait(int ret, const char *func, uint line)
{
	if (!ret)
		return 0;
	if (ret == ETIMEDOUT)
		return -FI_ETIMEDOUT;

	_ZHPE_LOG_ERROR(FI_LOG_CORE, "Unexpected error %d\n", ret);
	abort();
}

#define mutex_init(...) \
    abort_if_nonzero(pthread_mutex_init(__VA_ARGS__), __func__, __LINE__)

#define mutex_destroy(...) \
    abort_if_nonzero(pthread_mutex_destroy(__VA_ARGS__), \
		     __func__, __LINE__)

#define mutex_acquire(...) \
    abort_if_nonzero(pthread_mutex_lock(__VA_ARGS__), __func__, __LINE__)

#define mutex_release(...) \
    abort_if_nonzero(pthread_mutex_unlock(__VA_ARGS__), __func__, __LINE__)

#define mutex_trylock(...) \
    abort_trylock(pthread_mutex_trylock(__VA_ARGS__), __func__, __LINE__)

#define cond_init(...) \
    abort_if_nonzero(pthread_cond_init(__VA_ARGS__), __func__, __LINE__)

#define cond_destroy(...) \
    abort_if_nonzero(pthread_cond_destroy(__VA_ARGS__),  __func__, __LINE__)

#define cond_signal(...) \
	abort_if_nonzero(pthread_cond_signal(__VA_ARGS__),  __func__, __LINE__)

#define cond_broadcast(...) \
    abort_if_nonzero(pthread_cond_broadcast(__VA_ARGS__), __func__, __LINE__)

#define cond_wait(...) \
    abort_if_nonzero(pthread_cond_wait(__VA_ARGS__), __func__, __LINE__)

#define cond_timedwait(...) \
    abort_timedwait(pthread_cond_timedwait(__VA_ARGS__), __func__, __LINE__)

static inline uint8_t zhpe_get_rx_id(struct zhpe_tx_ctx *tx_ctx,
				     fi_addr_t fiaddr)
{
	uint8_t			ret = 0;
	struct zhpe_av		*av = tx_ctx->av;

	if (av && av->rx_ctx_bits)
		ret = ((uint64_t)fiaddr) >> (64 - av->rx_ctx_bits);

	return ret;

}

#endif /* _ZHPE_H_ */
