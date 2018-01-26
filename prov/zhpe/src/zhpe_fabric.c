/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_FABRIC, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_FABRIC, __VA_ARGS__)

int zhpe_pe_waittime = ZHPE_PE_WAITTIME;
const char zhpe_fab_name[] = "zhpe";
const char zhpe_dom_name[] = "zhpe";
const char zhpe_prov_name[] = "zhpe";
int zhpe_conn_retry = ZHPE_CM_DEF_RETRY;
int zhpe_cm_def_map_sz = ZHPE_CMAP_DEF_SZ;
int zhpe_av_def_sz = ZHPE_AV_DEF_SZ;
int zhpe_cq_def_sz = ZHPE_CQ_DEF_SZ;
int zhpe_eq_def_sz = ZHPE_EQ_DEF_SZ;
char *zhpe_pe_affinity_str = NULL;
int zhpe_ep_max_eager_sz = ZHPE_EP_MAX_EAGER_SZ;

const struct fi_fabric_attr zhpe_fabric_attr = {
	.fabric = NULL,
	.name = NULL,
	.prov_name = NULL,
	.prov_version = FI_VERSION(ZHPE_MAJOR_VERSION, ZHPE_MINOR_VERSION),
};

static struct dlist_entry zhpe_fab_list;
static struct dlist_entry zhpe_dom_list;
static fastlock_t zhpe_list_lock;
static int read_default_params;

void zhpe_dom_add_to_list(struct zhpe_domain *domain)
{
	fastlock_acquire(&zhpe_list_lock);
	dlist_insert_tail(&domain->dom_lentry, &zhpe_dom_list);
	fastlock_release(&zhpe_list_lock);
}

static inline int zhpe_dom_check_list_internal(struct zhpe_domain *domain)
{
	struct zhpe_domain	*dom_entry;

	dlist_foreach_container(&zhpe_dom_list, struct zhpe_domain, dom_entry,
				dom_lentry) {
		if (dom_entry == domain)
			return 1;
	}
	return 0;
}

int zhpe_dom_check_list(struct zhpe_domain *domain)
{
	int found;
	fastlock_acquire(&zhpe_list_lock);
	found = zhpe_dom_check_list_internal(domain);
	fastlock_release(&zhpe_list_lock);
	return found;
}

void zhpe_dom_remove_from_list(struct zhpe_domain *domain)
{
	fastlock_acquire(&zhpe_list_lock);
	if (zhpe_dom_check_list_internal(domain))
		dlist_remove(&domain->dom_lentry);

	fastlock_release(&zhpe_list_lock);
}

struct zhpe_domain *zhpe_dom_list_head(void)
{
	struct zhpe_domain *domain;
	fastlock_acquire(&zhpe_list_lock);
	if (dlist_empty(&zhpe_dom_list)) {
		domain = NULL;
	} else {
		domain = container_of(zhpe_dom_list.next,
				      struct zhpe_domain, dom_lentry);
	}
	fastlock_release(&zhpe_list_lock);
	return domain;
}

int zhpe_dom_check_manual_progress(struct zhpe_fabric *fabric)
{
	struct zhpe_domain	*dom_entry;

	dlist_foreach_container(&zhpe_dom_list, struct zhpe_domain, dom_entry,
				dom_lentry) {
		if (dom_entry->fab == fabric &&
		    dom_entry->progress_mode == FI_PROGRESS_MANUAL)
			return 1;
	}
	return 0;
}

void zhpe_fab_add_to_list(struct zhpe_fabric *fabric)
{
	fastlock_acquire(&zhpe_list_lock);
	dlist_insert_tail(&fabric->fab_lentry, &zhpe_fab_list);
	fastlock_release(&zhpe_list_lock);
}

static inline int zhpe_fab_check_list_internal(struct zhpe_fabric *fabric)
{
	struct zhpe_fabric	*fab_entry;

	dlist_foreach_container(&zhpe_fab_list, struct zhpe_fabric, fab_entry,
				fab_lentry) {
		if (fab_entry == fabric)
			return 1;
	}
	return 0;
}

int zhpe_fab_check_list(struct zhpe_fabric *fabric)
{
	int found;
	fastlock_acquire(&zhpe_list_lock);
	found = zhpe_fab_check_list_internal(fabric);
	fastlock_release(&zhpe_list_lock);
	return found;
}

void zhpe_fab_remove_from_list(struct zhpe_fabric *fabric)
{
	fastlock_acquire(&zhpe_list_lock);
	if (zhpe_fab_check_list_internal(fabric))
		dlist_remove(&fabric->fab_lentry);

	fastlock_release(&zhpe_list_lock);
}

struct zhpe_fabric *zhpe_fab_list_head(void)
{
	struct zhpe_fabric *fabric;
	fastlock_acquire(&zhpe_list_lock);
	if (dlist_empty(&zhpe_fab_list))
		fabric = NULL;
	else
		fabric = container_of(zhpe_fab_list.next,
				      struct zhpe_fabric, fab_lentry);
	fastlock_release(&zhpe_list_lock);
	return fabric;
}

int zhpe_verify_fabric_attr(struct fi_fabric_attr *attr)
{
	if (!attr)
		return 0;

	if (attr->prov_version) {
		if (attr->prov_version !=
		   FI_VERSION(ZHPE_MAJOR_VERSION, ZHPE_MINOR_VERSION))
			return -FI_ENODATA;
	}

	return 0;
}

int zhpe_verify_info(uint32_t version, const struct fi_info *hints,
		     uint64_t flags)
{
	int			ret = 0;
	uint64_t		caps;
	enum fi_ep_type		ep_type;
	struct zhpe_domain	*domain;
	struct zhpe_fabric	*fabric;
	struct addrinfo		ai;
	struct addrinfo		*rai;

	if (!hints)
		return 0;

	ep_type = hints->ep_attr ? hints->ep_attr->type : FI_EP_UNSPEC;
	switch (ep_type) {

	/* FIXME: Debug FI_EP_MSG */
	case FI_EP_MSG:
		return -FI_ENODATA;
#if 0
		caps = ZHPE_EP_MSG_CAP;
		ret = zhpe_msg_verify_ep_attr(hints->ep_attr,
					      hints->tx_attr,
					      hints->rx_attr);
#endif
		break;

	case FI_EP_UNSPEC:
		/* UNSPEC => RDM, for now. */
	case FI_EP_RDM:
		caps = ZHPE_EP_RDM_CAP;
		ret = zhpe_rdm_verify_ep_attr(hints->ep_attr,
					      hints->tx_attr,
					      hints->rx_attr);
		break;

	default:
		ret = -FI_ENODATA;
		break;

	}
	if (ret < 0)
		return ret;

	if ((caps | hints->caps) != caps) {
		ZHPE_LOG_DBG("Unsupported capabilities\n");
		return -FI_ENODATA;
	}

	switch (hints->addr_format) {

	case FI_FORMAT_UNSPEC:

	case FI_SOCKADDR:
		/* FIXME: Think about FI_SOCKADDR vs IPV6 some more. */
	case FI_SOCKADDR_IN:
		break;

	case FI_SOCKADDR_IN6:
		/* Are IPV6 addresses configured? */
		zhpe_getaddrinfo_hints_init(&ai, FI_SOCKADDR_IN6);
		ai.ai_flags |= AI_PASSIVE;
		ret = zhpe_getaddrinfo(NULL, "0", &ai, &rai);
		if (ret < 0)
			/* No. */
			return -FI_ENODATA;
		freeaddrinfo(rai);
		break;

	default:
		ZHPE_LOG_DBG("Unsupported address format\n");
		return -FI_ENODATA;
	}

	if (hints->domain_attr && hints->domain_attr->domain) {
		domain = container_of(hints->domain_attr->domain,
				      struct zhpe_domain, dom_fid);
		if (!zhpe_dom_check_list(domain)) {
			ZHPE_LOG_DBG("no matching domain\n");
			return -FI_ENODATA;
		}
	}
	ret = zhpe_verify_domain_attr(version, hints);
	if (ret < 0)
		return ret;

	if (hints->fabric_attr && hints->fabric_attr->fabric) {
		fabric = container_of(hints->fabric_attr->fabric,
				      struct zhpe_fabric, fab_fid);
		if (!zhpe_fab_check_list(fabric)) {
			ZHPE_LOG_DBG("no matching fabric\n");
			return -FI_ENODATA;
		}
	}
	ret = zhpe_verify_fabric_attr(hints->fabric_attr);
	if (ret < 0)
		return ret;

	return 0;
}

static int zhpe_trywait(struct fid_fabric *fabric, struct fid **fids, int count)
{
	/* we're always ready to wait! */
	return 0;
}

static struct fi_ops_fabric zhpe_fab_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = zhpe_domain,
	.passive_ep = zhpe_msg_passive_ep,
	.eq_open = zhpe_eq_open,
	.wait_open = zhpe_wait_open,
	.trywait = zhpe_trywait
};

static int zhpe_fabric_close(fid_t fid)
{
	struct zhpe_fabric *fab;
	fab = container_of(fid, struct zhpe_fabric, fab_fid);
	if (ofi_atomic_get32(&fab->ref))
		return -FI_EBUSY;

	zhpe_fab_remove_from_list(fab);
	fastlock_destroy(&fab->lock);
	free(fab);
	return 0;
}

static struct fi_ops zhpe_fab_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static void zhpe_read_default_params()
{
	if (!read_default_params) {
		fi_param_get_int(&zhpe_prov, "pe_waittime", &zhpe_pe_waittime);
		fi_param_get_int(&zhpe_prov, "max_conn_retry",
				 &zhpe_conn_retry);
		fi_param_get_int(&zhpe_prov, "def_conn_map_sz",
				 &zhpe_cm_def_map_sz);
		fi_param_get_int(&zhpe_prov, "def_av_sz", &zhpe_av_def_sz);
		fi_param_get_int(&zhpe_prov, "def_cq_sz", &zhpe_cq_def_sz);
		fi_param_get_int(&zhpe_prov, "def_eq_sz", &zhpe_eq_def_sz);
		if (fi_param_get_str(&zhpe_prov, "pe_affinity",
				     &zhpe_pe_affinity_str) != FI_SUCCESS)
			zhpe_pe_affinity_str = NULL;
		fi_param_get_int(&zhpe_prov, "ep_max_eager_sz",
				 &zhpe_ep_max_eager_sz);

		read_default_params = 1;
	}
}

static int zhpe_fabric(struct fi_fabric_attr *attr,
		       struct fid_fabric **fabric, void *context)
{
	struct zhpe_fabric *fab;

	fab = calloc(1, sizeof(*fab));
	if (!fab)
		return -FI_ENOMEM;

	zhpe_read_default_params();

	fastlock_init(&fab->lock);
	dlist_init(&fab->service_list);

	fab->fab_fid.fid.fclass = FI_CLASS_FABRIC;
	fab->fab_fid.fid.context = context;
	fab->fab_fid.fid.ops = &zhpe_fab_fi_ops;
	fab->fab_fid.ops = &zhpe_fab_ops;
	*fabric = &fab->fab_fid;
	ofi_atomic_initialize32(&fab->ref, 0);
	zhpe_fab_add_to_list(fab);
	return 0;
}

static int zhpe_fi_checkinfo(struct fi_info *info, const struct fi_info *hints)
{
	if (hints && hints->domain_attr && hints->domain_attr->name &&
             strcmp(info->domain_attr->name, hints->domain_attr->name))
		return -FI_ENODATA;

	if (hints && hints->fabric_attr && hints->fabric_attr->name &&
             strcmp(info->fabric_attr->name, hints->fabric_attr->name))
		return -FI_ENODATA;

	return 0;
}

static bool hints_addr_valid(const struct fi_info *hints,
			     const void *addr, size_t addr_len)
{
	const union sockaddr_in46 *sa = addr;

	if (hints->addr_format == FI_SOCKADDR_IN6) {
		if (sa->sa_family != AF_INET6)
			return false;
	} else if (sa->sa_family != AF_INET)
		return false;

	return sockaddr_valid(addr, addr_len, true);
}

static int zhpe_ep_getinfo(uint32_t version, const char *node,
			   const char *service, uint64_t flags,
			   const struct fi_info *hints,
			   enum fi_ep_type ep_type, struct fi_info **info)
{
	int			ret = 0;
	struct addrinfo		*rai = NULL;
	union sockaddr_in46	*src_addr = NULL;
	union sockaddr_in46	*dest_addr = NULL;
	struct addrinfo		ai;
#if ENABLE_DEBUG
	char			ntop[INET6_ADDRSTRLEN];
#endif

	zhpe_getaddrinfo_hints_init(&ai,
				    (hints ? hints->addr_format :
				     FI_FORMAT_UNSPEC));

	if (flags & FI_NUMERICHOST)
		ai.ai_flags |= AI_NUMERICHOST;

	if (flags & FI_SOURCE) {
		if (node || service) {
			ai.ai_flags |= AI_PASSIVE;
			ret = zhpe_getaddrinfo(node, service, &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			src_addr = (void *)rai->ai_addr;
		}
	} else {
		if (hints && hints->src_addr) {
			if (!hints_addr_valid(hints, hints->src_addr,
					      hints->src_addrlen))
				return -FI_ENODATA;
			src_addr = hints->src_addr;
		}

		if (node || service) {
			ret = zhpe_getaddrinfo(node, service, &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			dest_addr = (void *)rai->ai_addr;
		} else  if (hints && hints->dest_addr) {
			if (!hints_addr_valid(hints, hints->dest_addr,
					      hints->dest_addrlen))
				return -FI_ENODATA;
			dest_addr = hints->dest_addr;
		}
		if (dest_addr && !src_addr) {
			ai.ai_flags |= AI_PASSIVE;
			ret = zhpe_getaddrinfo(NULL, "0", &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			src_addr = (void *)rai->ai_addr;
		}
	}

	if (src_addr)
		ZHPE_LOG_DBG("src_addr: %s\n",
			     sockaddr_ntop(src_addr, ntop, sizeof(ntop)));
	if (dest_addr)
		ZHPE_LOG_DBG("dest_addr: %s\n",
			     sockaddr_ntop(dest_addr, ntop, sizeof(ntop)));

	switch (ep_type) {
	case FI_EP_MSG:
		ret = zhpe_msg_fi_info(version, src_addr, dest_addr,
				       hints, info);
		break;
	case FI_EP_RDM:
		ret = zhpe_rdm_fi_info(version, src_addr, dest_addr,
				       hints, info);
		break;
	default:
		ret = -FI_ENODATA;
		break;
	}

	if (rai)
		freeaddrinfo(rai);

	if (ret == 0)
		return zhpe_fi_checkinfo(*info, hints);

	return ret;
}

static inline int do_ep_getinfo(uint32_t version, const char *node,
				const char *service, uint64_t flags,
				const struct fi_info *hints,
				struct fi_info **info, struct fi_info **tail,
				enum fi_ep_type ep_type)
{
	int			ret;
	struct fi_info		*cur;

	ret = zhpe_ep_getinfo(version, node, service, flags,
			      hints, ep_type,  &cur);
	if (ret < 0)
		goto done;
	if (!*info)
		*info = cur;
	else
		(*tail)->next = cur;
	for (*tail = cur; (*tail)->next; *tail = (*tail)->next)
		;
 done:
	return ret;
}

static int zhpe_node_getinfo(uint32_t version, const char *node,
			     const char *service,
			     uint64_t flags, const struct fi_info *hints,
			     struct fi_info **info, struct fi_info **tail)
{
	int			ret;
	enum fi_ep_type		ep_type;

	if (hints && hints->ep_attr) {
		ep_type = hints->ep_attr->type;

		switch (ep_type) {

		case FI_EP_RDM:
		case FI_EP_MSG:
			ret = do_ep_getinfo(version, node, service, flags,
					    hints, info, tail, ep_type);
			goto done;

		case FI_EP_UNSPEC:
			break;

		default:
			ret = -FI_ENODATA;
			goto done;
		}
	}
	for (ep_type = FI_EP_MSG; ep_type <= FI_EP_RDM; ep_type++) {
		ret = do_ep_getinfo(version, node, service, flags,
				    hints, info, tail, ep_type);
		if (ret < 0) {
			if (ret == -FI_ENODATA)
				continue;
			goto done;
		}
	}
 done:
	if (ret < 0) {
		fi_freeinfo(*info);
		*info = NULL;
	}

	return ret;
}

static int zhpe_getinfo(uint32_t version, const char *node,
			const char *service,
			uint64_t flags, const struct fi_info *hints,
			struct fi_info **info)
{
	int			ret = 0;
	struct fi_info		*tail;

	ret = zhpeq_init(ZHPEQ_API_VERSION);
	if (ret < 0) {
		ZHPE_LOG_ERROR("zhpeq_init() returned error:%s\n",
			       strerror(-ret));
		return -FI_ENODATA;
	}

	*info = tail = NULL;

	ret = zhpe_verify_info(version, hints, flags);
	if (ret < 0)
		return ret;

	if (!(node ||
	      (!(flags & FI_SOURCE) && hints && 
	       (hints->src_addr || hints->dest_addr)))) {
		flags |= FI_SOURCE;
		if (!service)
			service = "0";
	}

	return zhpe_node_getinfo(version, node, service, flags, hints,
				 info, &tail);
}

static void fi_zhpe_fini(void)
{
	fastlock_destroy(&zhpe_list_lock);
}

struct fi_provider zhpe_prov = {
	.name = zhpe_prov_name,
	.version = FI_VERSION(ZHPE_MAJOR_VERSION, ZHPE_MINOR_VERSION),
	.fi_version = FI_VERSION(1, 5),
	.getinfo = zhpe_getinfo,
	.fabric = zhpe_fabric,
	.cleanup = fi_zhpe_fini
};

ZHPE_INI
{
	fi_param_define(&zhpe_prov, "pe_waittime", FI_PARAM_INT,
			"How many milliseconds to spin while waiting for progress");

	fi_param_define(&zhpe_prov, "max_conn_retry", FI_PARAM_INT,
			"Number of connection retries before reporting as failure");

	fi_param_define(&zhpe_prov, "def_conn_map_sz", FI_PARAM_INT,
			"Default connection map size");

	fi_param_define(&zhpe_prov, "def_av_sz", FI_PARAM_INT,
			"Default address vector size");

	fi_param_define(&zhpe_prov, "def_cq_sz", FI_PARAM_INT,
			"Default completion queue size");

	fi_param_define(&zhpe_prov, "def_eq_sz", FI_PARAM_INT,
			"Default event queue size");

	fi_param_define(&zhpe_prov, "pe_affinity", FI_PARAM_STRING,
			"If specified, bind the progress thread to the indicated range(s) of Linux virtual processor ID(s). "
			"This option is currently not supported on OS X. Usage: id_start[-id_end[:stride]][,]");

	fastlock_init(&zhpe_list_lock);
	dlist_init(&zhpe_fab_list);
	dlist_init(&zhpe_dom_list);

	return &zhpe_prov;
}
