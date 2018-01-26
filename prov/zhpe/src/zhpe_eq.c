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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EQ, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EQ, __VA_ARGS__)

static void zhpe_eq_clean_err_data_list(struct zhpe_eq *eq, int free_all)
{
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;
	struct zhpe_eq_err_data_entry *err_data_entry;

	dlist_foreach_safe(&eq->err_data_list, dentry, dnext) {
		err_data_entry = container_of(
			dentry, struct zhpe_eq_err_data_entry, lentry);
		if (free_all || err_data_entry->do_free) {
			dlist_remove(dentry);
			free(err_data_entry);
		}
	}
}

static ssize_t zhpe_eq_sread(struct fid_eq *eq, uint32_t *event, void *buf,
				size_t len, int timeout, uint64_t flags)
{
	int ret;
	struct zhpe_eq *zhpe_eq;
	struct dlist_entry *list;
	struct zhpe_eq_entry *entry;

	zhpe_eq = container_of(eq, struct zhpe_eq, eq);
	zhpe_eq_clean_err_data_list(zhpe_eq, 0);
	if (!dlistfd_empty(&zhpe_eq->err_list))
		return -FI_EAVAIL;

	if (dlistfd_empty(&zhpe_eq->list)) {
		if (!timeout) {
			ZHPE_LOG_DBG("Nothing to read from eq!\n");
			return -FI_EAGAIN;
		}
		ret = dlistfd_wait_avail(&zhpe_eq->list, timeout);
		if (!dlistfd_empty(&zhpe_eq->err_list))
			return -FI_EAVAIL;

		if (ret <= 0)
			return (ret == 0 || ret == -FI_ETIMEDOUT) ?
				-FI_EAGAIN : ret;
	}

	fastlock_acquire(&zhpe_eq->lock);
	list = zhpe_eq->list.list.next;
	entry = container_of(list, struct zhpe_eq_entry, lentry);

	if (entry->len > len) {
		ret = -FI_ETOOSMALL;
		goto out;
	}

	ret = entry->len;
	*event = entry->type;
	memcpy(buf, entry->event, entry->len);

	if (!(flags & FI_PEEK)) {
		dlistfd_remove(list, &zhpe_eq->list);
		free(entry);
	}

out:
	fastlock_release(&zhpe_eq->lock);
	return (ret == 0 || ret == -FI_ETIMEDOUT) ? -FI_EAGAIN : ret;
}


static ssize_t zhpe_eq_read(struct fid_eq *eq, uint32_t *event, void *buf,
				size_t len, uint64_t flags)
{
	return zhpe_eq_sread(eq, event, buf, len, 0, flags);
}

static ssize_t zhpe_eq_readerr(struct fid_eq *eq, struct fi_eq_err_entry *buf,
			uint64_t flags)
{
	int ret;
	struct zhpe_eq *zhpe_eq;
	struct dlist_entry *list;
	struct zhpe_eq_entry *entry;
	struct fi_eq_err_entry *err_entry;
	struct zhpe_eq_err_data_entry *err_data_entry;
	void *err_data = NULL;
	size_t err_data_size = 0;
	uint32_t api_version;

	zhpe_eq = container_of(eq, struct zhpe_eq, eq);
	fastlock_acquire(&zhpe_eq->lock);
	if (dlistfd_empty(&zhpe_eq->err_list)) {
		ret = -FI_EAGAIN;
		goto out;
	}

	api_version = zhpe_eq->zhpe_fab->fab_fid.api_version;

	list = zhpe_eq->err_list.list.next;
	entry = container_of(list, struct zhpe_eq_entry, lentry);
	err_entry = (struct fi_eq_err_entry *) entry->event;

	ret = entry->len;

	if ((FI_VERSION_GE(api_version, FI_VERSION(1, 5)))
		&& buf->err_data && buf->err_data_size) {
		err_data = buf->err_data;
		err_data_size = buf->err_data_size;
 		*buf = *err_entry;
		buf->err_data = err_data;

		/* Fill provided user's buffer */
 		buf->err_data_size = MIN(err_entry->err_data_size, err_data_size);
 		memcpy(buf->err_data, err_entry->err_data, buf->err_data_size);
	} else {
	    	*buf = *err_entry;
	}

	if (!(flags & FI_PEEK)) {
		if (err_entry->err_data) {
			err_data_entry = container_of(
				err_entry->err_data,
				struct zhpe_eq_err_data_entry, err_data);
			err_data_entry->do_free = 1;
		}

		dlistfd_remove(list, &zhpe_eq->err_list);
		dlistfd_reset(&zhpe_eq->list);
		free(entry);
	}

out:
	fastlock_release(&zhpe_eq->lock);
	return (ret == 0) ? -FI_EAGAIN : ret;
}

ssize_t zhpe_eq_report_event(struct zhpe_eq *zhpe_eq, uint32_t event,
			     const void *buf, size_t len, uint64_t flags)
{
	struct zhpe_eq_entry *entry;

	entry = calloc(1, len + sizeof(*entry));
	if (!entry)
		return -FI_ENOMEM;

	entry->type = event;
	entry->len = len;
	entry->flags = flags;
	memcpy(entry->event, buf, len);

	fastlock_acquire(&zhpe_eq->lock);
	dlistfd_insert_tail(&entry->lentry, &zhpe_eq->list);
	if (zhpe_eq->signal)
		zhpe_wait_signal(zhpe_eq->waitset);
	fastlock_release(&zhpe_eq->lock);
	return 0;
}

ssize_t zhpe_eq_report_error(struct zhpe_eq *zhpe_eq, fid_t fid, void *context,
			     uint64_t data, int err, int prov_errno,
			     void *err_data, size_t err_data_size)
{
	struct fi_eq_err_entry *err_entry;
	struct zhpe_eq_entry *entry;
	struct zhpe_eq_err_data_entry *err_data_entry;

	entry = calloc(1, sizeof(*err_entry) + sizeof(*entry));
	if (!entry)
		return -FI_ENOMEM;

	err_entry = (struct fi_eq_err_entry *) entry->event;
	err_entry->fid = fid;
	err_entry->context = context;
	err_entry->data = data;
	err_entry->err = err;
	err_entry->prov_errno = prov_errno;
	err_entry->err_data = err_data;
	err_entry->err_data_size = err_data_size;
	entry->len = sizeof(*err_entry);

	if (err_data) {
		err_data_entry = (struct zhpe_eq_err_data_entry *)
			calloc(1, sizeof(*err_data_entry) + err_data_size);
		if (!err_data_entry) {
			free(entry);
			return -FI_ENOMEM;
		}

		err_data_entry->do_free = 0;
		memcpy(err_data_entry->err_data, err_data, err_data_size);
		err_entry->err_data = err_data_entry->err_data;
		dlist_insert_tail(&err_data_entry->lentry,
				  &zhpe_eq->err_data_list);
	}

	fastlock_acquire(&zhpe_eq->lock);
	dlistfd_insert_tail(&entry->lentry, &zhpe_eq->err_list);
	dlistfd_signal(&zhpe_eq->list);
	if (zhpe_eq->signal)
		zhpe_wait_signal(zhpe_eq->waitset);
	fastlock_release(&zhpe_eq->lock);
	return 0;
}

static ssize_t zhpe_eq_write(struct fid_eq *eq, uint32_t event,
			     const void *buf, size_t len, uint64_t flags)
{
	struct zhpe_eq *zhpe_eq;
	int ret;

	zhpe_eq = container_of(eq, struct zhpe_eq, eq);
	if (!(zhpe_eq->attr.flags & FI_WRITE))
		return -FI_EINVAL;

	ret = zhpe_eq_report_event(zhpe_eq, event, buf, len, flags);
	return ret ? ret : len;

}

static const char *zhpe_eq_strerror(struct fid_eq *eq, int prov_errno,
			      const void *err_data, char *buf, size_t len)
{
	if (buf && len)
		return strncpy(buf, fi_strerror(-prov_errno), len);
	return fi_strerror(-prov_errno);
}

static struct fi_ops_eq zhpe_eq_ops = {
	.size = sizeof(struct fi_ops_eq),
	.read = zhpe_eq_read,
	.readerr = zhpe_eq_readerr,
	.write = zhpe_eq_write,
	.sread = zhpe_eq_sread,
	.strerror = zhpe_eq_strerror,
};

static int zhpe_eq_fi_close(struct fid *fid)
{
	struct zhpe_eq *zhpe_eq;

	zhpe_eq = container_of(fid, struct zhpe_eq, eq);
	zhpe_eq_clean_err_data_list(zhpe_eq, 1);

	dlistfd_head_free(&zhpe_eq->list);
	dlistfd_head_free(&zhpe_eq->err_list);
	fastlock_destroy(&zhpe_eq->lock);
	ofi_atomic_dec32(&zhpe_eq->zhpe_fab->ref);

	if (zhpe_eq->signal && zhpe_eq->attr.wait_obj == FI_WAIT_MUTEX_COND)
		zhpe_wait_close(&zhpe_eq->waitset->fid);

	free(zhpe_eq);
	return 0;
}

static int zhpe_eq_control(struct fid *fid, int command, void *arg)
{
	int ret = 0;
	struct zhpe_eq *eq;

	eq = container_of(fid, struct zhpe_eq, eq.fid);
	switch (command) {
	case FI_GETWAIT:
		switch (eq->attr.wait_obj) {
		case FI_WAIT_NONE:
		case FI_WAIT_UNSPEC:
		case FI_WAIT_FD:
			memcpy(arg, &eq->list.signal.fd[FI_READ_FD], sizeof(int));
			break;
		case FI_WAIT_SET:
		case FI_WAIT_MUTEX_COND:
			zhpe_wait_get_obj(eq->waitset, arg);
			break;
		default:
			ret = -FI_EINVAL;
			break;
		}
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static struct fi_ops zhpe_eq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_eq_fi_close,
	.bind = fi_no_bind,
	.control = zhpe_eq_control,
	.ops_open = fi_no_ops_open,
};

static int _zhpe_eq_verify_attr(struct fi_eq_attr *attr)
{
	if (!attr)
		return 0;

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_FD:
	case FI_WAIT_SET:
	case FI_WAIT_MUTEX_COND:
		break;
	case FI_WAIT_UNSPEC:
		attr->wait_obj = FI_WAIT_FD;
		break;
	default:
		return -FI_ENOSYS;
	}

	return 0;
}

static struct fi_eq_attr _zhpe_eq_def_attr = {
	.size = ZHPE_EQ_DEF_SZ,
	.flags = 0,
	.wait_obj = FI_WAIT_FD,
	.signaling_vector = 0,
	.wait_set = NULL,
};

int zhpe_eq_open(struct fid_fabric *fabric, struct fi_eq_attr *attr,
		 struct fid_eq **eq, void *context)
{
	int ret;
	struct zhpe_eq *zhpe_eq;
	struct fi_wait_attr wait_attr;

	ret = _zhpe_eq_verify_attr(attr);
	if (ret)
		return ret;

	zhpe_eq = calloc(1, sizeof(*zhpe_eq));
	if (!zhpe_eq)
		return -FI_ENOMEM;

	zhpe_eq->zhpe_fab = container_of(fabric, struct zhpe_fabric, fab_fid);
	zhpe_eq->eq.fid.fclass = FI_CLASS_EQ;
	zhpe_eq->eq.fid.context = context;
	zhpe_eq->eq.fid.ops = &zhpe_eq_fi_ops;
	zhpe_eq->eq.ops = &zhpe_eq_ops;

	if (attr == NULL)
		memcpy(&zhpe_eq->attr, &_zhpe_eq_def_attr,
		       sizeof(struct fi_eq_attr));
	else
		memcpy(&zhpe_eq->attr, attr, sizeof(struct fi_eq_attr));

	dlist_init(&zhpe_eq->err_data_list);
	ret = dlistfd_head_init(&zhpe_eq->list);
	if (ret)
		goto err1;

	ret = dlistfd_head_init(&zhpe_eq->err_list);
	if (ret)
		goto err2;

	fastlock_init(&zhpe_eq->lock);
	ofi_atomic_inc32(&zhpe_eq->zhpe_fab->ref);

	switch (zhpe_eq->attr.wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
		zhpe_eq->signal = 0;
		break;
	case FI_WAIT_FD:
		zhpe_eq->signal = 0;
		break;
	case FI_WAIT_MUTEX_COND:
		wait_attr.flags = 0;
		wait_attr.wait_obj = FI_WAIT_MUTEX_COND;
		ret = zhpe_wait_open(fabric, &wait_attr, &zhpe_eq->waitset);
		if (ret)
			goto err2;
		zhpe_eq->signal = 1;
		break;
	case FI_WAIT_SET:
		if (!attr) {
			ret = -FI_EINVAL;
			goto err2;
		}
		zhpe_eq->waitset = attr->wait_set;
		zhpe_eq->signal = 1;
		break;
	default:
		break;
	}

	zhpe_eq->wait_fd = -1;
	*eq = &zhpe_eq->eq;
	return 0;

err2:
	dlistfd_head_free(&zhpe_eq->list);
err1:
	free(zhpe_eq);
	return ret;
}
