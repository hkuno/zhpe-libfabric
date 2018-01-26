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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

const struct fi_cntr_attr zhpe_cntr_attr = {
	.events = FI_CNTR_EVENTS_COMP,
	.wait_obj = FI_WAIT_MUTEX_COND,
	.wait_set = NULL,
	.flags = 0,
};

void zhpe_cntr_add_tx_ctx(struct zhpe_cntr *cntr, struct zhpe_tx_ctx *tx_ctx)
{
	int ret;
	struct fid *fid = &tx_ctx->fid.ctx.fid;
	ret = fid_list_insert(&cntr->tx_list, &cntr->list_lock, fid);
	if (ret)
		ZHPE_LOG_ERROR("Error in adding ctx to progress list\n");
	else
		ofi_atomic_inc32(&cntr->ref);
}

void zhpe_cntr_remove_tx_ctx(struct zhpe_cntr *cntr, struct zhpe_tx_ctx *tx_ctx)
{
	struct fid *fid = &tx_ctx->fid.ctx.fid;
	fid_list_remove(&cntr->tx_list, &cntr->list_lock, fid);
	ofi_atomic_dec32(&cntr->ref);
}

void zhpe_cntr_add_rx_ctx(struct zhpe_cntr *cntr, struct zhpe_rx_ctx *rx_ctx)
{
	int ret;
	struct fid *fid = &rx_ctx->ctx.fid;
	ret = fid_list_insert(&cntr->rx_list, &cntr->list_lock, fid);
	if (ret)
		ZHPE_LOG_ERROR("Error in adding ctx to progress list\n");
	else
		ofi_atomic_inc32(&cntr->ref);
}

void zhpe_cntr_remove_rx_ctx(struct zhpe_cntr *cntr, struct zhpe_rx_ctx *rx_ctx)
{
	struct fid *fid = &rx_ctx->ctx.fid;
	fid_list_remove(&cntr->rx_list, &cntr->list_lock, fid);
	ofi_atomic_dec32(&cntr->ref);
}

int zhpe_cntr_progress(struct zhpe_cntr *cntr)
{
	struct zhpe_tx_ctx *tx_ctx;
	struct zhpe_rx_ctx *rx_ctx;

	struct fid_list_entry *fid_entry;

	if (cntr->domain->progress_mode == FI_PROGRESS_AUTO)
		return 0;

	fastlock_acquire(&cntr->list_lock);
	dlist_foreach_container(&cntr->tx_list, struct fid_list_entry,
				fid_entry, entry) {
		tx_ctx = container_of(fid_entry->fid, struct zhpe_tx_ctx,
				      fid.ctx.fid);
		if (tx_ctx->use_shared)
			zhpe_pe_progress_tx_ctx(cntr->domain->pe,
						tx_ctx->stx_ctx);
		else
			zhpe_pe_progress_tx_ctx(cntr->domain->pe, tx_ctx);
	}

	dlist_foreach_container(&cntr->rx_list, struct fid_list_entry,
				fid_entry, entry) {
		rx_ctx = container_of(fid_entry->fid, struct zhpe_rx_ctx,
				      ctx.fid);
		if (rx_ctx->use_shared)
			zhpe_pe_progress_rx_ctx(cntr->domain->pe,
						rx_ctx->srx_ctx);
		else
			zhpe_pe_progress_rx_ctx(cntr->domain->pe, rx_ctx);
	}

	fastlock_release(&cntr->list_lock);
	return 0;
}

void zhpe_cntr_check_trigger_list(struct zhpe_cntr *cntr)
{
	struct fi_deferred_work *work;
	struct zhpe_trigger *trigger;
	struct dlist_entry	*dentry;
	struct dlist_entry	*dnext;
	int ret = 0;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_foreach_safe(&cntr->trigger_list, dentry, dnext) {
		trigger = container_of(dentry, struct zhpe_trigger, lentry);
		if (ofi_atomic_get32(&cntr->value) <
		    (int)trigger->threshold)
			continue;

		switch (trigger->op_type) {
		case FI_OP_SEND:
			ret = zhpe_do_sendmsg(trigger->ep,
					      &trigger->op.msg.msg,
					      trigger->flags, false);
			break;
		case FI_OP_RECV:
			ret = zhpe_do_recvmsg(trigger->ep,
					      &trigger->op.msg.msg,
					      trigger->flags, false);
			break;
		case FI_OP_TSEND:
			ret = zhpe_do_sendmsg(trigger->ep,
					      &trigger->op.tmsg.msg,
					      trigger->flags, true);
			break;
		case FI_OP_TRECV:
			ret = zhpe_do_recvmsg(trigger->ep,
					      &trigger->op.tmsg.msg,
					      trigger->flags, true);
			break;
		case FI_OP_WRITE:
			ret = zhpe_do_rma_msg(trigger->ep,
					      &trigger->op.rma.msg,
					      trigger->flags);
			break;
		case FI_OP_READ:
			ret = zhpe_do_rma_msg(trigger->ep,
					      &trigger->op.rma.msg,
					      trigger->flags);
			break;

		case FI_OP_ATOMIC:
		case FI_OP_FETCH_ATOMIC:
		case FI_OP_COMPARE_ATOMIC:
			ret = zhpe_do_tx_atomic(
				trigger->ep, &trigger->op.atomic.msg,
				trigger->op.atomic.comparev, NULL,
				trigger->op.atomic.compare_count,
				trigger->op.atomic.resultv, NULL,
				trigger->op.atomic.result_count,
				trigger->flags);
			break;

		case FI_OP_CNTR_SET:
			work = container_of(trigger->context,
					    struct fi_deferred_work, context);
			fi_cntr_set(work->op.cntr->cntr, work->op.cntr->value);
			ret = 0;
			break;
		case FI_OP_CNTR_ADD:
			work = container_of(trigger->context,
					    struct fi_deferred_work, context);
			fi_cntr_add(work->op.cntr->cntr, work->op.cntr->value);
			ret = 0;
			break;
		default:
			ZHPE_LOG_ERROR("unsupported op\n");
			ret = 0;
			break;
		}

		if (ret != -FI_EAGAIN) {
			dlist_remove(&trigger->lentry);
			free(trigger);
		} else {
			break;
		}
	}
	fastlock_release(&cntr->trigger_lock);
}

static uint64_t zhpe_cntr_read(struct fid_cntr *fid_cntr)
{
	struct zhpe_cntr *cntr;
	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);
	zhpe_cntr_progress(cntr);
	return ofi_atomic_get32(&cntr->value);
}

void zhpe_cntr_inc(struct zhpe_cntr *cntr)
{
	mutex_acquire(&cntr->mut);
	ofi_atomic_inc32(&cntr->value);
	if (ofi_atomic_get32(&cntr->num_waiting))
		cond_broadcast(&cntr->cond);
	if (cntr->signal)
		zhpe_wait_signal(cntr->waitset);
	mutex_release(&cntr->mut);

	zhpe_cntr_check_trigger_list(cntr);
}

static int zhpe_cntr_add(struct fid_cntr *fid_cntr, uint64_t value)
{
	uint64_t new_val;
	struct zhpe_cntr *cntr;
	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);

	mutex_acquire(&cntr->mut);
	new_val = ofi_atomic_add32(&cntr->value, value);
	ofi_atomic_set32(&cntr->last_read_val, new_val);
	if (ofi_atomic_get32(&cntr->num_waiting))
		cond_broadcast(&cntr->cond);
	if (cntr->signal)
		zhpe_wait_signal(cntr->waitset);
	mutex_release(&cntr->mut);

	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

static int zhpe_cntr_set(struct fid_cntr *fid_cntr, uint64_t value)
{
	uint64_t new_val;
	struct zhpe_cntr *cntr;
	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);

	mutex_acquire(&cntr->mut);
	new_val = ofi_atomic_set32(&cntr->value, value);
	ofi_atomic_set32(&cntr->last_read_val, new_val);
	if (ofi_atomic_get32(&cntr->num_waiting))
		cond_broadcast(&cntr->cond);
	if (cntr->signal)
		zhpe_wait_signal(cntr->waitset);
	mutex_release(&cntr->mut);

	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

static int zhpe_cntr_adderr(struct fid_cntr *fid_cntr, uint64_t value)
{
	struct zhpe_cntr *cntr;
	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);

	mutex_acquire(&cntr->mut);
	ofi_atomic_add32(&cntr->err_cnt, value);
	if (!cntr->err_flag)
		cntr->err_flag = 1;
	cond_signal(&cntr->cond);
	if (cntr->signal)
		zhpe_wait_signal(cntr->waitset);
	mutex_release(&cntr->mut);

	return 0;
}

static int zhpe_cntr_seterr(struct fid_cntr *fid_cntr, uint64_t value)
{
	struct zhpe_cntr *cntr;

	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);
	mutex_acquire(&cntr->mut);
	ofi_atomic_set32(&cntr->err_cnt, value);
	if (!cntr->err_flag)
		cntr->err_flag = 1;
	cond_signal(&cntr->cond);
	if (cntr->signal)
		zhpe_wait_signal(cntr->waitset);
	mutex_release(&cntr->mut);

	return 0;

}

static int zhpe_cntr_wait(struct fid_cntr *fid_cntr, uint64_t threshold,
			  int timeout)
{
	int last_read, ret = 0;
	uint64_t start_ms = 0, end_ms = 0, remaining_ms = 0;
	struct zhpe_cntr *cntr;
	cntr = container_of(fid_cntr, struct zhpe_cntr, cntr_fid);

	mutex_acquire(&cntr->mut);
	if (cntr->err_flag) {
		ret = -FI_EAVAIL;
		goto out;
	}

	if (ofi_atomic_get32(&cntr->value) >= (int)threshold) {
		ret = 0;
		goto out;
	}

	ofi_atomic_inc32(&cntr->num_waiting);

	if (timeout >= 0) {
		start_ms = fi_gettime_ms();
		end_ms = start_ms + timeout;
	}

	last_read = ofi_atomic_get32(&cntr->value);
	remaining_ms = timeout;

	while (!ret && last_read < (int)threshold) {
		if (cntr->domain->progress_mode == FI_PROGRESS_MANUAL) {
			mutex_release(&cntr->mut);
			ret = zhpe_cntr_progress(cntr);
			mutex_acquire(&cntr->mut);
		} else {
			ret = fi_wait_cond(&cntr->cond, &cntr->mut, remaining_ms);
		}

		uint64_t curr_ms = fi_gettime_ms();
		if (timeout >= 0) {
			if (curr_ms >= end_ms) {
				ret = -FI_ETIMEDOUT;
				break;
			} else {
				remaining_ms = end_ms - curr_ms;
			}
		}

		last_read = ofi_atomic_get32(&cntr->value);
	}

	ofi_atomic_set32(&cntr->last_read_val, last_read);
	ofi_atomic_dec32(&cntr->num_waiting);
	mutex_release(&cntr->mut);

	zhpe_cntr_check_trigger_list(cntr);
	return (cntr->err_flag) ? -FI_EAVAIL : ret;

out:
	mutex_release(&cntr->mut);
	return ret;
}

static int zhpe_cntr_control(struct fid *fid, int command, void *arg)
{
	int ret = 0;
	struct zhpe_cntr *cntr;

	cntr = container_of(fid, struct zhpe_cntr, cntr_fid);

	switch (command) {
	case FI_GETWAIT:
		if (cntr->domain->progress_mode == FI_PROGRESS_MANUAL)
			return -FI_ENOSYS;

		switch (cntr->attr.wait_obj) {
		case FI_WAIT_NONE:
		case FI_WAIT_UNSPEC:
		case FI_WAIT_MUTEX_COND:
			memcpy(arg, &cntr->mut, sizeof(cntr->mut));
			memcpy((char *)arg + sizeof(cntr->mut), &cntr->cond,
			       sizeof(cntr->cond));
			break;

		case FI_WAIT_SET:
		case FI_WAIT_FD:
			zhpe_wait_get_obj(cntr->waitset, arg);
			break;

		default:
			ret = -FI_EINVAL;
			break;
		}
		break;

	case FI_GETOPSFLAG:
		memcpy(arg, &cntr->attr.flags, sizeof(uint64_t));
		break;

	case FI_SETOPSFLAG:
		memcpy(&cntr->attr.flags, arg, sizeof(uint64_t));
		break;

	default:
		ret = -FI_EINVAL;
		break;
	}
	return ret;
}

static int zhpe_cntr_close(struct fid *fid)
{
	struct zhpe_cntr *cntr;

	cntr = container_of(fid, struct zhpe_cntr, cntr_fid.fid);
	if (ofi_atomic_get32(&cntr->ref))
		return -FI_EBUSY;

	if (cntr->signal && cntr->attr.wait_obj == FI_WAIT_FD)
		zhpe_wait_close(&cntr->waitset->fid);

	mutex_destroy(&cntr->mut);
	fastlock_destroy(&cntr->list_lock);
	fastlock_destroy(&cntr->trigger_lock);

	cond_destroy(&cntr->cond);
	ofi_atomic_dec32(&cntr->domain->ref);
	free(cntr);
	return 0;
}

static uint64_t zhpe_cntr_readerr(struct fid_cntr *cntr)
{
	struct zhpe_cntr *_cntr;
	_cntr = container_of(cntr, struct zhpe_cntr, cntr_fid);
	if (_cntr->domain->progress_mode == FI_PROGRESS_MANUAL)
		zhpe_cntr_progress(_cntr);
	if (_cntr->err_flag)
		_cntr->err_flag = 0;
	return ofi_atomic_get32(&_cntr->err_cnt);
}

static struct fi_ops_cntr zhpe_cntr_ops = {
	.size = sizeof(struct fi_ops_cntr),
	.readerr = zhpe_cntr_readerr,
	.read = zhpe_cntr_read,
	.add = zhpe_cntr_add,
	.set = zhpe_cntr_set,
	.wait = zhpe_cntr_wait,
	.adderr = zhpe_cntr_adderr,
	.seterr = zhpe_cntr_seterr,
};

static struct fi_ops zhpe_cntr_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_cntr_close,
	.bind = fi_no_bind,
	.control = zhpe_cntr_control,
	.ops_open = fi_no_ops_open,
};

static int zhpe_cntr_verify_attr(struct fi_cntr_attr *attr)
{
	switch (attr->events) {
	case FI_CNTR_EVENTS_COMP:
		break;
	default:
		return -FI_ENOSYS;
	}

	switch (attr->wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
	case FI_WAIT_MUTEX_COND:
	case FI_WAIT_SET:
	case FI_WAIT_FD:
		break;
	default:
		return -FI_ENOSYS;
	}
	if (attr->flags)
		return -FI_EINVAL;
	return 0;
}

int zhpe_cntr_open(struct fid_domain *domain, struct fi_cntr_attr *attr,
		   struct fid_cntr **cntr, void *context)
{
	int ret;
	struct zhpe_domain *dom;
	struct zhpe_cntr *_cntr;
	struct fi_wait_attr wait_attr;
	struct zhpe_fid_list *list_entry;
	struct zhpe_wait *wait;

	dom = container_of(domain, struct zhpe_domain, dom_fid);
	if (attr && zhpe_cntr_verify_attr(attr))
		return -FI_ENOSYS;

	_cntr = calloc(1, sizeof(*_cntr));
	if (!_cntr)
		return -FI_ENOMEM;

	cond_init(&_cntr->cond, NULL);

	if (attr == NULL)
		memcpy(&_cntr->attr, &zhpe_cntr_add, sizeof(zhpe_cntr_attr));
	else
		memcpy(&_cntr->attr, attr, sizeof(zhpe_cntr_attr));

	switch (_cntr->attr.wait_obj) {

	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
	case FI_WAIT_MUTEX_COND:
		_cntr->signal = 0;
		break;

	case FI_WAIT_FD:
		wait_attr.flags = 0;
		wait_attr.wait_obj = FI_WAIT_FD;
		ret = zhpe_wait_open(&dom->fab->fab_fid, &wait_attr,
				     &_cntr->waitset);
		if (ret) {
			ret = FI_EINVAL;
			goto err;
		}
		_cntr->signal = 1;
		break;

	case FI_WAIT_SET:
		if (!attr) {
			ret = FI_EINVAL;
			goto err;
		}

		_cntr->waitset = attr->wait_set;
		_cntr->signal = 1;
		wait = container_of(attr->wait_set, struct zhpe_wait, wait_fid);
		list_entry = calloc(1, sizeof(*list_entry));
		if (!list_entry) {
			ret = FI_ENOMEM;
			goto err;
		}
		dlist_init(&list_entry->lentry);
		list_entry->fid = &_cntr->cntr_fid.fid;
		dlist_insert_after(&list_entry->lentry, &wait->fid_list);
		break;

	default:
		break;
	}

	mutex_init(&_cntr->mut, NULL);
	fastlock_init(&_cntr->list_lock);

	ofi_atomic_initialize32(&_cntr->ref, 0);
	ofi_atomic_initialize32(&_cntr->err_cnt, 0);

	ofi_atomic_initialize32(&_cntr->value, 0);
	ofi_atomic_initialize32(&_cntr->last_read_val, 0);
	ofi_atomic_initialize32(&_cntr->num_waiting, 0);

	dlist_init(&_cntr->tx_list);
	dlist_init(&_cntr->rx_list);

	dlist_init(&_cntr->trigger_list);
	fastlock_init(&_cntr->trigger_lock);

	_cntr->cntr_fid.fid.fclass = FI_CLASS_CNTR;
	_cntr->cntr_fid.fid.context = context;
	_cntr->cntr_fid.fid.ops = &zhpe_cntr_fi_ops;
	_cntr->cntr_fid.ops = &zhpe_cntr_ops;

	ofi_atomic_inc32(&dom->ref);
	_cntr->domain = dom;
	*cntr = &_cntr->cntr_fid;
	return 0;

err:
	free(_cntr);
	return -ret;
}

