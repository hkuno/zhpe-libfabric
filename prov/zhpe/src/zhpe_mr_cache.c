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

static inline struct zhpe_mr_cached **entry_data(struct ofi_mr_entry *entry)
{
	return (void *)entry->data;
}

static void zhpe_zmr_free_cached(void *ptr)
{
	struct zhpe_mr		*zmr = ptr;
	struct zhpe_mr_cached	*zmc =
		container_of(zmr, struct zhpe_mr_cached, zmr);

	free(zmc);
}

static int zhpe_zmr_put_cached(struct zhpe_mr *zmr)
{
	struct zhpe_domain	*domain = zmr->domain;
	struct zhpe_mr_cached	*zmc =
		container_of(zmr, struct zhpe_mr_cached, zmr);

	if (!zmr)
		return 0;

	fastlock_acquire(&domain->cache_lock);
	/* If the entry is NULL, it has been freed from the cache,
	 * but someone else might have a hold on the zmr.
	 */
	if (zmc->entry)
		ofi_mr_cache_delete(&zmr->domain->cache, zmc->entry);
	else
		zhpe_zmr_put_uncached(&zmc->zmr);
	fastlock_release(&domain->cache_lock);

	return 0;
}

static struct zhpe_mr_ops zmr_ops_cached = {
	.fi_ops = {
		.size		= sizeof(struct fi_ops),
		.close		= zhpe_mr_close,
		.bind		= fi_no_bind,
		.control	= fi_no_control,
		.ops_open	= fi_no_ops_open,
	},
	.freeme			= zhpe_zmr_free_cached,
	.put			= zhpe_zmr_put_cached,
};

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
	struct  zhpe_mr_cached	*zmc;

	assert(!qaccess);
	fastlock_acquire(&domain->cache_lock);
	ret = ofi_mr_cache_search(&domain->cache, &attr, &entry);
	fastlock_release(&domain->cache_lock);
	if (OFI_LIKELY(ret >= 0)) {
		zmc = *entry_data(entry);
		*mr = &zmc->zmr.mr_fid;
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
	void			*buf = entry->iov.iov_base;
	size_t			len = entry->iov.iov_len;
	uint32_t		qaccess =
		(ZHPEQ_MR_GET | ZHPEQ_MR_PUT | ZHPEQ_MR_GET_REMOTE |
		 ZHPEQ_MR_PUT_REMOTE | ZHPEQ_MR_SEND | ZHPEQ_MR_RECV |
		 ZHPEQ_MR_KEY_ZERO_OFF | ZHPE_MR_KEY_INT);
	struct zhpe_mr_cached	*zmc;

	zmc = malloc(sizeof(*zmc));
	*entry_data(entry) = zmc;
	if (!zmc) {
		ret = -FI_ENOMEM;
		goto done;
	}
	zmc->entry = entry;

	ret = zhpe_zmr_reg(domain, buf, len, qaccess,
			   atm_inc(&domain->mr_zhpe_key),
			   &zmc->zmr, &zmr_ops_cached);
	if (ret < 0) {
		free(zmc);
		*entry_data(entry) = NULL;
		ZHPE_LOG_ERROR("Failed to register memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)buf, (uintptr_t)buf + len - 1,
			       ret, fi_strerror(-ret));
	}
 done:
	return ret;
}

static void zhpe_mr_cache_delete_region(struct ofi_mr_cache *cache,
					struct ofi_mr_entry *entry)
{
	struct zhpe_mr_cached	*zmc = *entry_data(entry);
	void			*buf = entry->iov.iov_base;
	size_t			len = entry->iov.iov_len;
	int			rc;

	/* domain->cache_lock is held */
	zmc->entry = NULL;
	rc = zhpe_zmr_put_uncached(&zmc->zmr);
	if (rc < 0)
		ZHPE_LOG_ERROR("Failed to unregister memory 0x%lx-0x%lx,"
			       " error %d:%s\n",
			       (uintptr_t)buf, (uintptr_t)buf + len - 1,
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

	rc = ioctl(domain->monitor_fd, UMMUNOTIFY_UNREGISTER_REGION, &unreg);
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
	uint64_t		events;

	events = atm_load_rlx(domain->monitor_eventsp);
	if (events == domain->monitor_events)
		goto done;

	for (;;) {
		rc = read(domain->monitor_fd, &evt, sizeof(evt));
		if (rc == -1) {
			rc = -errno;
			if (rc == -EAGAIN) {
				/* We've caught up */
				domain->monitor_events = events;
				break;
			}
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
 done:
	return ret;
}

#endif

void zhpe_mr_cache_destroy(struct zhpe_domain *domain)
{
	if (domain->monitor_fd != -1) {
		if (domain->cache_inited) {
			fastlock_destroy(&domain->cache_lock);
			ofi_mr_cache_cleanup(&domain->cache);
			domain->cache_inited = false;
		}
		close(domain->monitor_fd);
		domain->monitor_fd = -1;
		if (domain->monitor_eventsp)
			munmap(domain->monitor_eventsp,
			       sizeof(*domain->monitor_eventsp));
		domain->monitor_eventsp = NULL;
		ofi_monitor_cleanup(&domain->monitor);
	}
}

int zhpe_mr_cache_init(struct zhpe_domain *domain)
{
	int			ret = 0;
	const char		*dev_name = "/dev/ummunotify";
	int			rc;

	if (!zhpe_mr_cache_enable)
		goto done;
#ifdef HAVE_LINUX_UMMUNOTIFY_H
	domain->monitor_fd = open(dev_name, O_RDONLY | O_NONBLOCK);
	if (domain->monitor_fd == -1) {
		rc = errno;
		ZHPE_LOG_ERROR("Failed to open %s, error %d:%s,"
			       " mr_cache disabled\n",
			       dev_name, rc, strerror(rc));
		goto done;
	}
	domain->monitor_eventsp = mmap(NULL, sizeof(*domain->monitor_eventsp),
				       PROT_READ, MAP_SHARED,
				       domain->monitor_fd, 0);
	if (domain->monitor_eventsp == MAP_FAILED) {
		domain->monitor_eventsp = NULL;
		rc = errno;
		ZHPE_LOG_ERROR("Failed to mmap %s, error %d:%s,"
			       " mr_cache disabled\n",
			       dev_name, rc, strerror(rc));
		goto done;
	}
	domain->monitor_events = 0;
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
	domain->cache.entry_data_size = sizeof(struct zhpe_mr);
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
