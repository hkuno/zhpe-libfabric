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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_CORE, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_CORE, __VA_ARGS__)

enum {
	WAIT_READ_FD = 0,
	WAIT_WRITE_FD,
};

int zhpe_wait_get_obj(struct fid_wait *fid, void *arg)
{
#ifndef _WIN32 /* there is no support of wait objects on windows */
	struct fi_mutex_cond mut_cond;
#endif /* _WIN32 */
	struct zhpe_wait *wait;

	wait = container_of(fid, struct zhpe_wait, wait_fid.fid);
	if (zhpe_dom_check_manual_progress(wait->fab))
		return -FI_ENOSYS;

	switch (wait->type) {
#ifndef _WIN32
	case FI_WAIT_FD:
		memcpy(arg, &wait->wobj.fd[WAIT_READ_FD], sizeof(int));
		break;

	case FI_WAIT_MUTEX_COND:
		mut_cond.mutex = &wait->wobj.mutex_cond.mutex;
		mut_cond.cond  = &wait->wobj.mutex_cond.cond;
		memcpy(arg, &mut_cond, sizeof(mut_cond));
		break;
#endif /* _WIN32 */
	default:
		ZHPE_LOG_ERROR("Invalid wait obj type\n");
		return -FI_EINVAL;
	}

	return 0;
}

static int zhpe_wait_init(struct zhpe_wait *wait, enum fi_wait_obj type)
{
	int ret;

	wait->type = type;

	switch (type) {
	case FI_WAIT_FD:
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, wait->wobj.fd))
			return -errno;

		ret = fi_fd_nonblock(wait->wobj.fd[WAIT_READ_FD]);
		if (ret) {
			ofi_close_socket(wait->wobj.fd[WAIT_READ_FD]);
			ofi_close_socket(wait->wobj.fd[WAIT_WRITE_FD]);
			return ret;
		}
		break;

	case FI_WAIT_MUTEX_COND:
		mutex_init(&wait->wobj.mutex_cond.mutex, NULL);
		cond_init(&wait->wobj.mutex_cond.cond, NULL);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid wait object type\n");
		return -FI_EINVAL;
	}
	return 0;
}

static int zhpe_wait_wait(struct fid_wait *wait_fid, int timeout)
{
	int err = 0, ret;
	struct zhpe_cq *cq;
	struct zhpe_cntr *cntr;
	struct timeval now;
	struct zhpe_wait *wait;
	double start_ms = 0.0, end_ms = 0.0;
	struct zhpe_fid_list *list_item;
	char c;

	wait = container_of(wait_fid, struct zhpe_wait, wait_fid);
	if (timeout > 0) {
		gettimeofday(&now, NULL);
		start_ms = (double)now.tv_sec * 1000.0 +
			(double)now.tv_usec / 1000.0;
	}

	dlist_foreach_container(&wait->fid_list, struct zhpe_fid_list,
				list_item, lentry) {
		switch (list_item->fid->fclass) {
		case FI_CLASS_CQ:
			cq = container_of(list_item->fid,
					  struct zhpe_cq, cq_fid);
			zhpe_cq_progress(cq);
			if (ofi_rbused(&cq->cqerr_rb))
				return 1;
			break;

		case FI_CLASS_CNTR:
			cntr = container_of(list_item->fid,
					    struct zhpe_cntr, cntr_fid);
			zhpe_cntr_progress(cntr);
			break;
		}
	}
	if (timeout > 0) {
		gettimeofday(&now, NULL);
		end_ms = (double)now.tv_sec * 1000.0 +
			(double)now.tv_usec / 1000.0;
		timeout -=  (end_ms - start_ms);
		timeout = timeout < 0 ? 0 : timeout;
	}

	switch (wait->type) {
	case FI_WAIT_FD:
		err = fi_poll_fd(wait->wobj.fd[WAIT_READ_FD], timeout);
		if (err == 0) {
			err = -FI_ETIMEDOUT;
		} else {
			while (err > 0) {
				ret = ofi_read_socket(wait->wobj.fd[WAIT_READ_FD], &c, 1);
				if (ret != 1) {
					ZHPE_LOG_ERROR("failed to read wait_fd\n");
					err = 0;
					break;
				} else
					err--;
			}
		}
		break;

	case FI_WAIT_MUTEX_COND:
		err = fi_wait_cond(&wait->wobj.mutex_cond.cond,
				   &wait->wobj.mutex_cond.mutex, timeout);
		break;

	default:
		ZHPE_LOG_ERROR("Invalid wait object type\n");
		return -FI_EINVAL;
	}
	return err;
}

void zhpe_wait_signal(struct fid_wait *wait_fid)
{
	struct zhpe_wait *wait;
	static char c = 'a';
	int ret;

	wait = container_of(wait_fid, struct zhpe_wait, wait_fid);

	switch (wait->type) {
	case FI_WAIT_FD:
		ret = ofi_write_socket(wait->wobj.fd[WAIT_WRITE_FD], &c, 1);
		if (ret != 1)
			ZHPE_LOG_ERROR("failed to signal\n");
		break;

	case FI_WAIT_MUTEX_COND:
		cond_signal(&wait->wobj.mutex_cond.cond);
		break;
	default:
		ZHPE_LOG_ERROR("Invalid wait object type\n");
		return;
	}
}

static struct fi_ops_wait zhpe_wait_ops = {
	.size = sizeof(struct fi_ops_wait),
	.wait = zhpe_wait_wait,
};

static int zhpe_wait_control(struct fid *fid, int command, void *arg)
{
	struct zhpe_wait *wait;
	int ret = 0;

	wait = container_of(fid, struct zhpe_wait, wait_fid.fid);
	switch (command) {
	case FI_GETWAIT:
		ret = zhpe_wait_get_obj(&wait->wait_fid, arg);
		break;
	default:
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

int zhpe_wait_close(fid_t fid)
{
	struct zhpe_fid_list *list_item;
	struct zhpe_wait *wait;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;

	wait = container_of(fid, struct zhpe_wait, wait_fid.fid);

	dlist_foreach_safe(&wait->fid_list, dentry, dnext) {
		list_item = container_of(dentry, struct zhpe_fid_list, lentry);
		dlist_remove(&list_item->lentry);
		free(list_item);
	}

	if (wait->type == FI_WAIT_FD) {
		ofi_close_socket(wait->wobj.fd[WAIT_READ_FD]);
		ofi_close_socket(wait->wobj.fd[WAIT_WRITE_FD]);
	}

	ofi_atomic_dec32(&wait->fab->ref);
	free(wait);
	return 0;
}

static struct fi_ops zhpe_wait_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_wait_close,
	.bind = fi_no_bind,
	.control = zhpe_wait_control,
	.ops_open = fi_no_ops_open,
};

static int zhpe_verify_wait_attr(struct fi_wait_attr *attr)
{
	switch (attr->wait_obj) {
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
	case FI_WAIT_MUTEX_COND:
		break;

	default:
		ZHPE_LOG_ERROR("Invalid wait object type\n");
		return -FI_EINVAL;
	}
	if (attr->flags)
		return -FI_EINVAL;
	return 0;
}

int zhpe_wait_open(struct fid_fabric *fabric, struct fi_wait_attr *attr,
		   struct fid_wait **waitset)
{
	int err;
	struct zhpe_wait *wait;
	struct zhpe_fabric *fab;
	enum fi_wait_obj wait_obj_type;

	if (attr && zhpe_verify_wait_attr(attr))
		return -FI_EINVAL;

	fab = container_of(fabric, struct zhpe_fabric, fab_fid);
	if (!attr || attr->wait_obj == FI_WAIT_UNSPEC)
		wait_obj_type = FI_WAIT_FD;
	else
		wait_obj_type = attr->wait_obj;

	wait = calloc(1, sizeof(*wait));
	if (!wait)
		return -FI_ENOMEM;

	err = zhpe_wait_init(wait, wait_obj_type);
	if (err) {
		free(wait);
		return err;
	}

	wait->wait_fid.fid.fclass = FI_CLASS_WAIT;
	wait->wait_fid.fid.context = 0;
	wait->wait_fid.fid.ops = &zhpe_wait_fi_ops;
	wait->wait_fid.ops = &zhpe_wait_ops;
	wait->fab = fab;
	wait->type = wait_obj_type;
	ofi_atomic_inc32(&fab->ref);
	dlist_init(&wait->fid_list);

	*waitset = &wait->wait_fid;
	return 0;
}
