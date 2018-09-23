/*
 * Copyright (c) 2017 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You m"ay choose to be licensed under the terms of the GNU
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

#ifdef HAVE_LINUX_UMMUNOTIFY_H

#include <sys/ioctl.h>

#include <linux/ummunotify.h>

#endif

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_DOMAIN, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_DOMAIN, __VA_ARGS__)

static int zhpe_mr_reg_int_cached(struct zhpe_domain *domain, const void *buf,
				  size_t len, uint64_t access, uint32_t qaccess,
				  struct fid_mr **mr)
{
	int			ret;
	struct iovec		iov = {
		.iov_base	= (void *)buf,
		.iov_len	= len,
	};
	struct fi_mr_attr	attr = {
		.mr_iov		= &iov,
		.iov_count	= 1,
		.access		= access,
	};
	struct ofi_mr_entry	*entry;
	struct  zhpe_mr		*zmr;

	assert(!qaccess);
	fastlock_acquire(&domain->cache_lock);
	ret = ofi_mr_cache_search(&domain->cache, &attr, &entry);
	fastlock_release(&domain->cache_lock);
	if (OFI_LIKELY(ret >= 0)) {
		*mr = *(struct fid_mr **)entry->data;
		zmr = container_of(*mr, struct zhpe_mr, mr_fid);
		zhpe_mr_get(zmr);
	} else
		*mr = NULL;

	return ret;
}

#ifdef HAVE_LINUX_UMMUNOTIFY_H

#include <sys/ioctl.h>

#include <linux/ummunotify.h>

static int zhpe_mr_cache_add_region(struct ofi_mr_cache *cache,
				    struct ofi_mr_entry *entry)
{
	int			ret;
	struct zhpe_domain	*domain =
		container_of(cache->domain, struct zhpe_domain, util_domain);
	uint64_t		access =
		(FI_READ | FI_WRITE | FI_REMOTE_READ | FI_REMOTE_WRITE |
		 FI_SEND | FI_RECV);
	struct fid_mr		**mr = (void *)entry->data;

	ret = zhpe_mr_reg_int_uncached(domain, entry->iov.iov_base,
				      entry->iov.iov_len, access,
				      ZHPEQ_MR_KEY_ZERO_OFF, mr);
	if (ret < 0)
		ZHPE_LOG_ERROR("Failed to register memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)entry->iov.iov_base,
			       ((uintptr_t)entry->iov.iov_base +
				entry->iov.iov_len - 1),
			       ret, fi_strerror(-ret));

	return ret;
}

static void zhpe_mr_cache_delete_region(struct ofi_mr_cache *cache,
					struct ofi_mr_entry *entry)
{
	struct fid_mr		*mr = *(struct fid_mr **)entry->data;
	int			rc;

	rc = zhpe_mr_put(container_of(mr, struct zhpe_mr, mr_fid));
	if (rc < 0)
		ZHPE_LOG_ERROR("Failed to unregister memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)entry->iov.iov_base,
			       ((uintptr_t)entry->iov.iov_base +
				entry->iov.iov_len - 1),
			       rc, fi_strerror(-rc));
}

static int zhpe_monitor_subscribe(struct ofi_mem_monitor *monitor,
				  void *addr, size_t len,
				  struct ofi_subscription *subscription)
{
	int			ret;
	struct zhpe_domain	*domain =
		container_of(monitor, struct zhpe_domain, monitor);
	struct ummunotify_register_ioctl reg = {
		.start		= (uintptr_t)addr,
		.end		= (uintptr_t)addr + len - 1,
		.user_cookie	= (uintptr_t)subscription,
	};

	ret = ioctl(domain->monitor_fd, UMMUNOTIFY_REGISTER_REGION, &reg);
	if (ret == -1) {
		ret = -errno;
		ZHPE_LOG_ERROR("Failed to monitor region 0x%Lx-0x%Lx,"
			       " error %d:%s\n",
			       (ullong)reg.start, (ullong)reg.end,
			       ret, strerror(-ret));
	}

	return ret;
}

static void zhpe_monitor_unsubscribe(struct ofi_mem_monitor *monitor,
				     void *addr, size_t len,
				     struct ofi_subscription *subscription)
{
	struct zhpe_domain	*domain =
		container_of(monitor, struct zhpe_domain, monitor);
	uint64_t		unreg = (uintptr_t)subscription;
	int			rc;

	rc = ioctl(domain->monitor_fd, UMMUNOTIFY_UNREGISTER_REGION, unreg);
	if (rc == -1) {
		rc = -errno;
		ZHPE_LOG_ERROR("Failed to unregister region 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)addr, (uintptr_t)addr + len - 1,
			       rc, strerror(-rc));
	}
}

static struct ofi_subscription *
zhpe_monitor_get_event(struct ofi_mem_monitor *monitor)
{
	struct ofi_subscription	*ret = NULL;
	struct zhpe_domain	*domain =
		container_of(monitor, struct zhpe_domain, monitor);
	ssize_t			rc;
	struct ummunotify_event	evt;

	for (;;) {
		rc = read(domain->monitor_fd, &evt, sizeof(evt));
		if (rc == -1) {
			rc = -errno;
			if (rc == -EAGAIN)
				break;
			ZHPE_LOG_ERROR("Failed to read event, error %ld:%s\n",
				       rc, strerror(-rc));
			break;
		}
		if (rc != sizeof(evt)) {
			ZHPE_LOG_ERROR("read %ld, expected %lu\n",
				       rc, sizeof(evt));
			break;
		}
		if (evt.type == UMMUNOTIFY_EVENT_TYPE_INVAL) {
			ret = (void *)(uintptr_t)evt.user_cookie_counter;
			break;
		}
	}

	return ret;
}

#endif

void zhpe_mr_cache_destroy(struct zhpe_domain *domain)
{
	if (domain->cache_inited) {
		fastlock_destroy(&domain->cache_lock);
		ofi_mr_cache_cleanup(&domain->cache);
		domain->cache_inited = false;
	}
	if (domain->monitor_fd != -1) {
		close(domain->monitor_fd);
		domain->monitor_fd = -1;
		ofi_monitor_cleanup(&domain->monitor);
	}
}

int zhpe_mr_cache_init(struct zhpe_domain *domain)
{
	int			ret = 0;
	const char		*dev_name = "/dev/ummunotify";

	if (!zhpe_mr_cache_enable)
		goto done;
#ifdef HAVE_LINUX_UMMUNOTIFY_H
	domain->monitor_fd = open(dev_name, O_RDONLY | O_NONBLOCK);
	if (domain->monitor_fd == -1) {
		if (errno == ENOENT) {
			ZHPE_LOG_DBG("%s not present, mr_cache disabled\n",
				     dev_name);
			goto done;
		}
		ret = -errno;
		ZHPE_LOG_ERROR("Failed to open %s, error %d:%s\n",
			       dev_name, ret, strerror(-ret));
		goto done;
	}
	/* FIXME: need to change over to using util_xxx structs?
	 * The ofi_mr_cache uses the util_domain only for ref counting
	 * and the prov point for debugging output. Too much work for full
	 * conversion; just init those for now.
	 */
	ofi_atomic_initialize32(&domain->util_domain.ref, 0);
	domain->util_domain.prov = &zhpe_prov;

	domain->monitor.subscribe = zhpe_monitor_subscribe;
	domain->monitor.unsubscribe = zhpe_monitor_unsubscribe;
	domain->monitor.get_event = zhpe_monitor_get_event;
	ofi_monitor_init(&domain->monitor);

	domain->cache.max_cached_cnt = zhpe_mr_cache_max_cnt;
	domain->cache.max_cached_size = zhpe_mr_cache_max_size;
	domain->cache.merge_regions = zhpe_mr_cache_merge_regions;
	domain->cache.entry_data_size = sizeof(struct fid_mr *);
	domain->cache.add_region = zhpe_mr_cache_add_region;
	domain->cache.delete_region = zhpe_mr_cache_delete_region;
	ret = ofi_mr_cache_init(&domain->util_domain, &domain->monitor,
				&domain->cache);
	if (ret < 0)
		goto done;
	fastlock_init(&domain->cache_lock);
	domain->reg_int = zhpe_mr_reg_int_cached;
	domain->cache_inited = true;
#else
	ZHPE_LOG_DBG("%s support not configured, mr_cache disabled\n",
		     dev_name);
	goto done;
#endif

 done:
	if (ret < 0)
		zhpe_mr_cache_destroy(domain);

	return ret;
}
