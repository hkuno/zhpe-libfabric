/*
 * Copyright (c) 2014-2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016-2017, Cisco Systems, Inc. All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_AV, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_AV, __VA_ARGS__)

fi_addr_t zhpe_av_get_fi_addr(struct util_av *av, const void *addr)
{
	return ofi_av_lookup_fi_addr(av, addr);
}

static int zhpe_av_valid_addr(struct util_av *av, const void *addr)
{
	const union sockaddr_in46 *sa = addr;

	switch (sa->sa_family) {

	case AF_ZHPE:
		return (sa->zhpe.sz_queue != ZHPE_WILDCARD &&
			sa->zhpe.sz_queue != ZHPE_QINVAL &&
			!uuid_is_null(sz->sz_uuid));

	default:
		return 0;

	}
}

static int zhpe_av_insert_addr(struct util_av *av, const void *addr,
			       fi_addr_t *fi_addr, void *context)
{
	int			ret;
	fi_addr_t		fi_addr_ret;

	if (zhpe_av_valid_addr(av, addr)) {
		fastlock_acquire(&av->lock);
		ret = ofi_av_insert_addr(av, addr, &fi_addr_ret);
		fastlock_release(&av->lock);
	} else {
		ret = -FI_EADDRNOTAVAIL;
		FI_WARN(av->prov, FI_LOG_AV, "invalid address\n");
	}

	if (fi_addr)
		*fi_addr = !ret ? fi_addr_ret : FI_ADDR_NOTAVAIL;

	_zhpe_straddr_dbg(av->prov, FI_LOG_AV, "av_insert addr", addr);
	if (fi_addr)
		FI_DBG(av->prov, FI_LOG_AV, "av_insert fi_addr: %" PRIu64 "\n",
		       *fi_addr);

	return ret;
}

static int zhpe_av_insertv(struct util_av *av, const void *addr, size_t addrlen,
			   size_t count, fi_addr_t *fi_addr, void *context)
{
	int			ret;
	int			success_cnt = 0;
	size_t			i;

	FI_DBG(av->prov, FI_LOG_AV, "inserting %zu addresses\n", count);
	for (i = 0; i < count; i++) {
		ret = zhpe_av_insert_addr(av, (const char *) addr + i * addrlen,
					  fi_addr ? &fi_addr[i] : NULL,
					  context);
		if (!ret)
			success_cnt++;
		else if (av->eq)
			ofi_av_write_event(av, i, -ret, context);
	}

	FI_DBG(av->prov, FI_LOG_AV, "%d addresses successful\n", success_cnt);
	if (av->eq) {
		ofi_av_write_event(av, success_cnt, 0, context);
		ret = 0;
	} else {
		ret = success_cnt;
	}

	return ret;
}

static int zhpe_av_insert(struct fid_av *av_fid, const void *addr,
			  size_t count, fi_addr_t *fi_addr, uint64_t flags,
			  void *context)
{
	int			ret;
	struct util_av		*av;

	av = container_of(av_fid, struct util_av, av_fid);
	ret = ofi_verify_av_insert(av, flags);
	if (ret < 0)
		return ret;

	return zhpe_av_insertv(av, addr, ofi_sizeofaddr(addr),
			       count, fi_addr, context);
}

/* Caller should free *addr */
static int zhpe_av_nodesym_getaddr(struct util_av *av, const char *node,
				   size_t nodecnt, const char *service,
				   size_t svccnt, void **addr, size_t *addrlen)
{
	int			ret = 0;
	size_t			count = nodecnt * svccnt;
	char			name[FI_NAME_MAX];
	char			svc[FI_NAME_MAX];
	char			*addr_temp;
	size_t			name_len;
	size_t			n;
	size_t			s;
	size_t			name_index;
	size_t			svc_index;
	char			*e;

	memset(&hints, 0, sizeof hints);

	*addrlen = sizeof(struct sockaddr_zhpe);
	*addr = calloc(nodecnt * svccnt, *addrlen);
	if (!*addr) {
		ret = -FI_ENOMEM;
		goto done;
	}

	addr_temp = *addr;

	for (name_len = strlen(node); isdigit(node[name_len - 1]); )
		name_len--;

	memcpy(name, node, name_len);
	ret = -FI_EINVAL;
	errno = 0;
	name_index = strtoul(node + name_len, &e, 0);
	if (errno != 0) {
                ret = -errno;
                goto done;
	}
	if (*e != '\0')
                goto done;
	svc_index = strtoul(service, &e, 0);
	if (errno != 0) {
                ret = -errno;
                goto done;
	}
	if (*e != '\0')
                goto done;

	for (n = 0; n < nodecnt; n++) {
		if (nodecnt == 1) {
			strncpy(name, node, sizeof(name) - 1);
			name[FI_NAME_MAX - 1] = '\0';
		} else {
			snprintf(name + name_len, sizeof(name) - name_len - 1,
				 "%zu", name_index + n);
		}

		for (s = 0; s < svccnt; s++) {
			if (svccnt == 1) {
				strncpy(svc, service, sizeof(svc) - 1);
				svc[FI_NAME_MAX - 1] = '\0';
			} else {
				snprintf(svc, sizeof(svc) - 1,
					 "%zu", svc_index + s);
			}
			FI_INFO(av->prov, FI_LOG_AV, "resolving %s:%s for AV "
				"insert\n", node, service);

			ret = zhpeu_getzaddr(node, service, addr_temp);
			if (ret < 0)
				goto done;
			addr_temp += *addrlen;
		}
	}
	ret = count;
done:
	if (ret < 0) {
		free(*addr);
		*addr = NULL;
	}

	return ret;
}

/* Caller should free *addr */
int zhpe_av_sym_getaddr(struct util_av *av, const char *node,
			size_t nodecnt, const char *service,
			size_t svccnt, void **addr, size_t *addrlen)
{
	int			ret;
	union sockaddr_in46	&sa;

	if (strlen(node) >= FI_NAME_MAX || strlen(service) >= FI_NAME_MAX) {
		FI_WARN(av->prov, FI_LOG_AV,
			"node or service name is too long\n");
		return -FI_ENOSYS;
	}

	FI_INFO(av->prov, FI_LOG_AV, "insert symmetric host names\n");
	return zhpe_av_nodesym_getaddr(av, node, nodecnt, service,
				       svccnt, addr, addrlen);
}

static int zhpe_av_insertsym(struct fid_av *av_fid, const char *node,
			     size_t nodecnt, const char *service, size_t svccnt,
			     fi_addr_t *fi_addr, uint64_t flags, void *context)
{
	int			ret;
	struct util_av		*av;
	void			*addr;
	size_t			addrlen;
	int			count;

	av = container_of(av_fid, struct util_av, av_fid);
	ret = ofi_verify_av_insert(av, flags);
	if (ret < 0)
		return ret;

	count = zhpe_av_sym_getaddr(av, node, nodecnt, service,
				    svccnt, &addr, &addrlen);
	if (count <= 0)
		return count;

	ret = zhpe_av_insertv(av, addr, addrlen, count,	fi_addr, context);
	free(addr);

	return ret;
}

static int zhpe_av_insertsvc(struct fid_av *av_fid, const char *node,
			     const char *service, fi_addr_t *fi_addr,
			     uint64_t flags, void *context)
{
	return zhpe_av_insertsym(av_fid, node, 1, service, 1, fi_addr, flags,
				 context);
}

int ofi_ip_av_remove(struct fid_av *av_fid, fi_addr_t *fi_addr,
		     size_t count, uint64_t flags)
{
	struct util_av *av;
	int i, ret;

	av = container_of(av_fid, struct util_av, av_fid);
	if (flags) {
		FI_WARN(av->prov, FI_LOG_AV, "invalid flags\n");
		return -FI_EINVAL;
	}

	/*
	 * It's more efficient to remove addresses from high to low index.
	 * We assume that addresses are removed in the same order that they were
	 * added -- i.e. fi_addr passed in here was also passed into insert.
	 * Thus, we walk through the array backwards.
	 */
	for (i = count - 1; i >= 0; i--) {
		fastlock_acquire(&av->lock);
		ret = ofi_av_remove_addr(av, fi_addr[i]);
		fastlock_release(&av->lock);
		if (ret) {
			FI_WARN(av->prov, FI_LOG_AV,
				"removal of fi_addr %"PRIu64" failed\n",
				fi_addr[i]);
		}
	}
	return 0;
}

int zhpe_av_lookup(struct fid_av *av_fid, fi_addr_t fi_addr,
		   void *addr, size_t *addrlen)
{
	int			ret = -FI_EINVAL;
	struct util_av		*av =
		container_of(av_fid, struct util_av, av_fid);
	struct util_av_entry	*av_entry;
	size_t			outlen;

	if (!av_fid || !addr || !addrlen)
		goto done;

	outlen = MIN(*addrlen, av->addrlen);
	*addrlen = av->addrlen;
	fastlock_acquire(&av->lock);
	av_entry = ofi_bufpool_get_ibuf(av->av_entry_pool, fi_addr);
	if (av_entry)
		memcpy(addr, av_entry, outlen);
	fastlock_release(&av->lock);
	if (!av_entry) {
		ret = -FI_ENOENT;
		goto done;
	}
	ret = 0;
 done:

	retiurn ret;
}

const char *zhpe_av_straddr(struct fid_av *av, const void *addr,
			    char *buf, size_t *len)
{
	return zhpe_straddr(buf, len, FI_FORMAT_UNSPEC, addr);
}

static struct fi_ops_av zhpe_av_ops = {
	.size = sizeof(struct fi_ops_av),
	.insert = zhpe_av_insert,
	.insertsvc = zhpe_av_insertsvc,
	.insertsym = zhpe_av_insertsym,
	.remove = ofi_ip_av_remove,	/* Should "just work" */
	.lookup = zhpe_av_lookup,
	.straddr = zhpe_av_straddr,
};

static int zhpe_av_close(struct fid *av_fid)
{
	int			ret = -FI_EINVAL;
	struct util_av		*av =
		container_of(av_fid, struct util_av, av_fid);

	if (!av_fid)
		goto done;
	ret = ofi_av_close(av);
	if (ret < 0)
		goto done;
	free(av);
 done:
	return ret;
}

static struct fi_ops zhpe_av_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_av_close,
	.bind = ofi_av_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

int zhpe_av_create_flags(struct fid_domain *domain_fid, struct fi_av_attr *attr,
			 struct fid_av **av, void *context, int flags)
{
	int			ret = -FI_EINVAL;
	struct util_domain	*domain =
		container_of(domain_fid, struct util_domain, domain_fid);
	struct util_av_attr	util_attr = {
		.addrlen	= sizeof(struct sockaddr_zhpe),
		.flags		= flags,
	};
	struct fi_av_attr	av_attr;
	struct zjp_av		*util_av;

	if (!domain_fid || !attr || !av)
		goto done;

	av_attr = *attr;
	if (av_attr->type == FI_AV_UNSPEC)
		av_attr->type = FI_AV_TABLE;

	util_av = calloc(1, sizeof(*util_av));
	if (!util_av) {
		ret = -FI_ENOMEM;
		goto done;
	}

	ret = ofi_av_init(domain, attr, &util_attr, util_av, context);
	if (ret < 0)
		goto done;

	*av = &util_av->av_fid;
	(*av)->fid.ops = &zhpe_av_fi_ops;
	(*av)->ops = &zhpe_av_ops;
 done:
	if (ret < 0)
		free(util_av);

	return ret;
}
