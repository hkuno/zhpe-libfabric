/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016, Cisco Systems, Inc. All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_AV, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_AV, __VA_ARGS__)

#define ZHPE_AV_TABLE_SZ(count, av_name)				\
	(sizeof(struct zhpe_av_table_hdr) +				\
	 (ZHPE_IS_SHARED_AV(av_name) * count * sizeof(uint64_t) +	\
	  count * sizeof(struct zhpe_av_addr)))
#define ZHPE_IS_SHARED_AV(av_name) ((av_name) ? 1 : 0)

int zhpe_av_get_addr_index(struct zhpe_av *av, const union sockaddr_in46 *addr)
{
	size_t			i;
	struct zhpe_av_addr	*av_addr;

	for (i = 0; i < av->table_hdr->size; i++) {
		av_addr = &av->table[i];
		if (!av_addr->addr.sa_family)
			continue;

		if (!sockaddr_cmp(addr, &av_addr->addr))
			return i;
	}
	ZHPE_LOG_DBG("failed to get index in AV\n");

	return -1;
}

int zhpe_av_compare_addr(struct zhpe_av *av,
			 fi_addr_t addr1, fi_addr_t addr2)
{
	int			ret = 0;
	uint64_t		index1;
	uint64_t		index2;
	struct zhpe_av_addr	*av_addr1;
	struct zhpe_av_addr	*av_addr2;

	index1 = ((uint64_t)addr1 & av->mask);
	index2 = ((uint64_t)addr2 & av->mask);

	if (index1 >= av->table_hdr->size) {
		ZHPE_LOG_DBG("0x%Lx not in table\n", (ullong)addr1);
		ret = -1;
	}
	if (index2 >= av->table_hdr->size) {
		ZHPE_LOG_DBG("0x%Lx not in table\n", (ullong)addr2);
		ret = -1;
	}
	if (ret)
		return ret;

	av_addr1 = &av->table[index1];
	av_addr2 = &av->table[index2];

	if (!av_addr1->addr.sa_family) {
		ZHPE_LOG_DBG("0x%Lx not valid\n", (ullong)addr1);
		ret = -1;
	}
	if (!av_addr2->addr.sa_family) {
		ZHPE_LOG_DBG("0x%Lx not valid\n", (ullong)addr2);
		ret = -1;
	}
	if (ret)
		return ret;

	return sockaddr_cmp(&av_addr1->addr, &av_addr2->addr);
}

static inline void zhpe_av_report_success(struct zhpe_av *av, void *context,
					  int num_done, uint64_t flags)
{
	struct fi_eq_entry eq_entry;

	if (!av->eq)
		return;

	eq_entry.fid = &av->av_fid.fid;
	eq_entry.context = context;
	eq_entry.data = num_done;
	zhpe_eq_report_event(av->eq, FI_AV_COMPLETE,
			     &eq_entry, sizeof(eq_entry), flags);
}

static inline void zhpe_av_report_error(struct zhpe_av *av,
					void *context, int index, int err)
{
	if (!av->eq)
		return;

	zhpe_eq_report_error(av->eq, &av->av_fid.fid,
			     context, index, err, -err, NULL, 0);
}

static void zhpe_update_av_table(struct zhpe_av *_av, size_t count)
{
	_av->table = (struct zhpe_av_addr *)
		((char *)_av->table_hdr +
		ZHPE_IS_SHARED_AV(_av->attr.name) * count * sizeof(uint64_t) +
		sizeof(struct zhpe_av_table_hdr));
}

static int zhpe_resize_av_table(struct zhpe_av *av)
{
	void *new_addr;
	size_t new_count, table_sz, old_sz;

	new_count = av->table_hdr->size * 2;
	table_sz = ZHPE_AV_TABLE_SZ(new_count, av->attr.name);
	old_sz = ZHPE_AV_TABLE_SZ(av->table_hdr->size, av->attr.name);

	if (av->attr.name) {
		new_addr = zhpe_mremap(av->table_hdr, old_sz, table_sz);
		if (new_addr == MAP_FAILED)
			return -1;

		av->idx_arr[av->table_hdr->stored] = av->table_hdr->stored;
	} else {
		new_addr = realloc(av->table_hdr, table_sz);
		if (!new_addr)
			return -1;
	}

	av->table_hdr = new_addr;
	av->table_hdr->size = new_count;
	zhpe_update_av_table(av, new_count);

	return 0;
}

static int zhpe_av_get_next_index(struct zhpe_av *av)
{
	uint64_t i;

	for (i = 0; i < av->table_hdr->size; i++) {
		if (!av->table[i].addr.sa_family != AF_UNSPEC)
			return i;
	}

	return -1;
}

static int zhpe_check_table_in(struct zhpe_av *_av, const void *vaddr,
			       fi_addr_t *fi_addr, int count, uint64_t flags,
			       void *context)
{
	int			ret = 0;
	int			i;
	uint64_t		j;
	char			sa_ip[INET6_ADDRSTRLEN];
	struct zhpe_av_addr	*av_addr;
	int			index;
	const union sockaddr_in46 *addr;
	size_t			addr_len;
	int			family;

	if ((_av->attr.flags & FI_EVENT) && !_av->eq)
		return -FI_ENOEQ;

	if (_av->domain->info.addr_format == FI_SOCKADDR_IN6) {
		family = AF_INET6;
		addr_len = sizeof(addr->addr6);
	} else {
		family = AF_INET;
		addr_len = sizeof(addr->addr4);
	}

	if (_av->attr.flags & FI_READ) {
		for (i = 0; i < count; i++) {
			addr = (void *)((char *)vaddr + addr_len * i);
			for (j = 0; j < _av->table_hdr->size; j++) {
				if (addr->sa_family == family) {
					if (fi_addr)
						fi_addr[i] = FI_ADDR_NOTAVAIL;
					zhpe_av_report_error(_av, context, i,
								FI_EINVAL);
					continue;
				}

				av_addr = &_av->table[j];
				if (!sockaddr_cmp(&av_addr->addr, addr)) {
					ZHPE_LOG_DBG("Found addr in shared"
						     " av\n");
					if (fi_addr)
						fi_addr[i] = (fi_addr_t)j;
					ret++;
				}
			}
		}
		zhpe_av_report_success(_av, context, ret, flags);
		return (_av->attr.flags & FI_EVENT) ? 0 : ret;
	}

	for (i = 0, ret = 0; i < count; i++) {
		addr = (void *)((char *)vaddr + addr_len * i);
		if (addr->sa_family != family) {
			if (fi_addr)
				fi_addr[i] = FI_ADDR_NOTAVAIL;
			zhpe_av_report_error(_av, context, i, FI_EINVAL);
			continue;
		}
		if (_av->table_hdr->stored == _av->table_hdr->size) {
			index = zhpe_av_get_next_index(_av);
			if (index < 0) {
				if (zhpe_resize_av_table(_av)) {
					if (fi_addr)
						fi_addr[i] = FI_ADDR_NOTAVAIL;
					zhpe_av_report_error(_av, context, i,
							     FI_ENOMEM);
					continue;
				}
				index = _av->table_hdr->stored++;
			}
		} else {
			index = _av->table_hdr->stored++;
		}

		av_addr = &_av->table[index];
		sockaddr_ntop(addr, sa_ip, sizeof(sa_ip));
		ZHPE_LOG_DBG("AV-INSERT: dst_addr family: %d, IP %s,"
			     " port: %d\n", addr->sa_family, sa_ip,
			     ntohs(addr->sin_port));

		sockaddr_cpy(&av_addr->addr, addr);
		if (fi_addr)
			fi_addr[i] = (fi_addr_t)index;

		ret++;
	}
	zhpe_av_report_success(_av, context, ret, flags);
	return (_av->attr.flags & FI_EVENT) ? 0 : ret;
}

static int zhpe_av_insert(struct fid_av *av, const void *addr, size_t count,
			  fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	struct zhpe_av *_av;
	_av = container_of(av, struct zhpe_av, av_fid);
	return zhpe_check_table_in(_av, addr,
				   fi_addr, count, flags, context);
}

static int zhpe_av_lookup(struct fid_av *av, fi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	int index;
	struct zhpe_av *_av;
	struct zhpe_av_addr *av_addr;

	_av = container_of(av, struct zhpe_av, av_fid);
	index = ((uint64_t)fi_addr & _av->mask);
	if (index >= (int)_av->table_hdr->size || index < 0) {
		ZHPE_LOG_ERROR("requested address not inserted\n");
		return -EINVAL;
	}

	av_addr = &_av->table[index];
	memcpy(addr, &av_addr->addr, MIN(*addrlen, (size_t)_av->addrlen));
	*addrlen = _av->addrlen;
	return 0;
}

static int _zhpe_av_insertsvc(struct fid_av *av, const char *node,
			      const char *service, fi_addr_t *fi_addr,
			      uint64_t flags, void *context)
{
	int			ret;
	struct addrinfo		hints;
	struct addrinfo		*result = NULL;
	struct zhpe_av		*_av;

	_av = container_of(av, struct zhpe_av, av_fid);

	zhpe_getaddrinfo_hints_init(&hints, _av->domain->info.addr_format);
	ret = zhpe_getaddrinfo(node, service, &hints, &result);
	if (ret < 0) {
		if (_av->eq) {
			zhpe_av_report_error(_av, context, 0, FI_EINVAL);
			zhpe_av_report_success(_av, context, 0, flags);
		}
		return ret;
	}

	ret = zhpe_check_table_in(_av, result->ai_addr,
				  fi_addr, 1, flags, context);

	freeaddrinfo(result);
	return ret;
}

static int zhpe_av_insertsvc(struct fid_av *av, const char *node,
			     const char *service, fi_addr_t *fi_addr,
			     uint64_t flags, void *context)
{
	if (!service) {
		ZHPE_LOG_ERROR("Port not provided\n");
		return -FI_EINVAL;
	}

	return _zhpe_av_insertsvc(av, node, service, fi_addr, flags, context);
}

static int zhpe_av_insertsym(struct fid_av *av, const char *node,
			     size_t nodecnt,  const char *service,
			     size_t svccnt, fi_addr_t *fi_addr,
			     uint64_t flags, void *context)
{
	int ret = 0, success = 0, err_code = 0, len1, len2;
	int var_port, var_host;
	char base_host[FI_NAME_MAX] = {0};
	char tmp_host[FI_NAME_MAX] = {0};
	char tmp_port[FI_NAME_MAX] = {0};
	int hostlen, offset = 0, fmt;
	size_t i, j;

	if (!node || !service || node[0] == '\0') {
		ZHPE_LOG_ERROR("Node/service not provided\n");
		return -FI_EINVAL;
	}

	hostlen = strlen(node);
	while (isdigit(*(node + hostlen - (offset + 1))))
		offset++;

	if (*(node + hostlen - offset) == '.')
		fmt = 0;
	else
		fmt = offset;

	assert((hostlen-offset) < FI_NAME_MAX);
	strncpy(base_host, node, hostlen - (offset));
	var_port = atoi(service);
	var_host = atoi(node + hostlen - offset);

	for (i = 0; i < nodecnt; i++) {
		for (j = 0; j < svccnt; j++) {
			len1 = snprintf(tmp_host, FI_NAME_MAX, "%s%0*d",
					base_host, fmt, var_host + (int)i);
			len2 = snprintf(tmp_port, FI_NAME_MAX,  "%d",
					var_port + (int)j);
			if (len1 > 0 && len1 < FI_NAME_MAX && len2 > 0 && len2 < FI_NAME_MAX) {
				ret = _zhpe_av_insertsvc(av, tmp_host, tmp_port, fi_addr, flags, context);
				if (ret == 1)
					success++;
				else
					err_code = ret;
			} else {
				ZHPE_LOG_ERROR("Node/service value is not valid\n");
				err_code = FI_ETOOSMALL;
			}
		}
	}
	return success > 0 ? success : err_code;
}


static int zhpe_av_remove(struct fid_av *av, fi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	size_t i;
	struct zhpe_av *_av;
	struct zhpe_av_addr *av_addr;
	struct dlist_entry *item;
	struct fid_list_entry *fid_entry;
	struct zhpe_ep *zhpe_ep;
	struct zhpe_conn *conn;
	uint16_t idx;

	_av = container_of(av, struct zhpe_av, av_fid);
	fastlock_acquire(&_av->list_lock);
	dlist_foreach(&_av->ep_list, item) {
		fid_entry = container_of(item, struct fid_list_entry, entry);
		zhpe_ep = container_of(fid_entry->fid, struct zhpe_ep, ep.fid);
		mutex_acquire(&zhpe_ep->attr->cmap.mutex);
		for (i = 0; i < count; i++) {
        		idx = fi_addr[i] & zhpe_ep->attr->av->mask;
			conn = ofi_idm_lookup(&zhpe_ep->attr->av_idm, idx);
			if (conn)
				zhpe_conn_release_entry(zhpe_ep->attr, conn);
		}
		mutex_release(&zhpe_ep->attr->cmap.mutex);
	}
	fastlock_release(&_av->list_lock);

	for (i = 0; i < count; i++) {
		av_addr = &_av->table[fi_addr[i]];
		av_addr->addr.sa_family = AF_UNSPEC;
	}

	return 0;
}

static const char *zhpe_av_straddr(struct fid_av *av, const void *addr,
				   char *buf, size_t *len)
{
	int			size = -1;
	const union sockaddr_in46 *sa = addr;
	char			ntop[INET6_ADDRSTRLEN];

	if (sockaddr_valid(addr, 0, false) &&
	    sockaddr_ntop(sa, ntop, sizeof(ntop)))
		size = snprintf(buf, *len, "%s:%d", ntop, ntohs(sa->sin_port));
	if (size < 0)
		*len = 0;
	else
		*len = size + 1;

	return buf;
}

static int zhpe_av_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct zhpe_av *av;
	struct zhpe_eq *eq;

	if (bfid->fclass != FI_CLASS_EQ)
		return -FI_EINVAL;

	av = container_of(fid, struct zhpe_av, av_fid.fid);
	eq = container_of(bfid, struct zhpe_eq, eq.fid);
	av->eq = eq;
	return 0;
}

static int zhpe_av_close(struct fid *fid)
{
	struct zhpe_av *av;
	int ret = 0;
	av = container_of(fid, struct zhpe_av, av_fid.fid);
	if (ofi_atomic_get32(&av->ref))
		return -FI_EBUSY;

	if (!av->shared)
		free(av->table_hdr);
	else {
		ret = ofi_shm_unmap(&av->shm);
		if (ret)
			ZHPE_LOG_ERROR("unmap failed: %s\n", strerror(errno));
	}

	ofi_atomic_dec32(&av->domain->ref);
	fastlock_destroy(&av->list_lock);
	free(av);
	return 0;
}

static struct fi_ops zhpe_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_av_close,
	.bind = zhpe_av_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_av zhpe_am_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = zhpe_av_insert,
	.insertsvc = zhpe_av_insertsvc,
	.insertsym = zhpe_av_insertsym,
	.remove = zhpe_av_remove,
	.lookup = zhpe_av_lookup,
	.straddr = zhpe_av_straddr
};

static struct fi_ops_av zhpe_at_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = zhpe_av_insert,
	.insertsvc = zhpe_av_insertsvc,
	.insertsym = zhpe_av_insertsym,
	.remove = zhpe_av_remove,
	.lookup = zhpe_av_lookup,
	.straddr = zhpe_av_straddr
};

static int zhpe_verify_av_attr(struct fi_av_attr *attr)
{
	switch (attr->type) {
	case FI_AV_MAP:
	case FI_AV_TABLE:
	case FI_AV_UNSPEC:
		break;
	default:
		return -FI_EINVAL;
	}

	if (attr->flags & FI_READ && !attr->name)
		return -FI_EINVAL;

	if (attr->rx_ctx_bits > ZHPE_EP_MAX_CTX_BITS) {
		ZHPE_LOG_ERROR("Invalid rx_ctx_bits\n");
		return -FI_EINVAL;
	}
	return 0;
}

int zhpe_av_open(struct fid_domain *domain, struct fi_av_attr *attr,
		 struct fid_av **av, void *context)
{
	int ret = 0;
	struct zhpe_domain *dom;
	struct zhpe_av *_av;
	size_t table_sz;

	if (!attr || zhpe_verify_av_attr(attr))
		return -FI_EINVAL;

	if (attr->type == FI_AV_UNSPEC)
		attr->type = FI_AV_TABLE;

	dom = container_of(domain, struct zhpe_domain, dom_fid);
	if (dom->attr.av_type != FI_AV_UNSPEC &&
	    dom->attr.av_type != attr->type)
		return -FI_EINVAL;

	_av = calloc(1, sizeof(*_av));
	if (!_av)
		return -FI_ENOMEM;

	_av->attr = *attr;
	_av->attr.count = (attr->count) ? attr->count : zhpe_av_def_sz;
	table_sz = ZHPE_AV_TABLE_SZ(_av->attr.count, attr->name);

	if (attr->name) {
		ret = ofi_shm_map(&_av->shm, attr->name, table_sz,
				attr->flags & FI_READ, (void**)&_av->table_hdr);

		if (ret || _av->table_hdr == MAP_FAILED) {
			ZHPE_LOG_ERROR("map failed\n");
			ret = -FI_EINVAL;
			goto err;
		}

		_av->idx_arr = (uint64_t *)(_av->table_hdr + 1);
		_av->attr.map_addr = _av->idx_arr;
		attr->map_addr = _av->attr.map_addr;
		ZHPE_LOG_DBG("Updating map_addr: %p\n", _av->attr.map_addr);

		if (attr->flags & FI_READ) {
			if (_av->table_hdr->size != _av->attr.count) {
				ret = -FI_EINVAL;
				goto err2;
			}
		} else {
			_av->table_hdr->size = _av->attr.count;
			_av->table_hdr->stored = 0;
		}
		_av->shared = 1;
	} else {
		_av->table_hdr = calloc(1, table_sz);
		if (!_av->table_hdr) {
			ret = -FI_ENOMEM;
			goto err;
		}
		_av->table_hdr->size = _av->attr.count;
	}
	zhpe_update_av_table(_av, _av->attr.count);

	_av->av_fid.fid.fclass = FI_CLASS_AV;
	_av->av_fid.fid.context = context;
	_av->av_fid.fid.ops = &zhpe_av_fi_ops;

	switch (attr->type) {
	case FI_AV_MAP:
		_av->av_fid.ops = &zhpe_am_ops;
		break;
	case FI_AV_TABLE:
		_av->av_fid.ops = &zhpe_at_ops;
		break;
	default:
		ret = -FI_EINVAL;
		goto err2;
	}

	ofi_atomic_initialize32(&_av->ref, 0);
	ofi_atomic_inc32(&dom->ref);
	_av->domain = dom;
	switch (dom->info.addr_format) {

	case FI_SOCKADDR_IN:
		_av->addrlen = sizeof(struct sockaddr_in);
		break;

	case FI_SOCKADDR_IN6:
		_av->addrlen = sizeof(struct sockaddr_in6);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid address format\n");
		ret = -FI_EINVAL;
		goto err2;
	}
	dlist_init(&_av->ep_list);
	fastlock_init(&_av->list_lock);
	_av->rx_ctx_bits = attr->rx_ctx_bits;
	_av->mask = attr->rx_ctx_bits ?
		((uint64_t)1 << (64 - attr->rx_ctx_bits)) - 1 : ~0;
	*av = &_av->av_fid;
	return 0;

err2:
	if(attr->name) {
		ofi_shm_unmap(&_av->shm);
	} else {
		if(_av->table_hdr != MAP_FAILED)
			free(_av->table_hdr);
	}
err:
	free(_av);
	return ret;
}
