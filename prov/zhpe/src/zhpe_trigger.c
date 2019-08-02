/*
 * Copyright (c) 2014-2015 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

ssize_t zhpe_queue_rma_op(struct fid_ep *ep, const struct fi_msg_rma *msg,
			  uint64_t flags, enum fi_op_type op_type)
{
	struct zhpe_cntr *cntr;
	struct zhpe_trigger *trigger;
	struct zhpe_triggered_context *trigger_context;
	struct zhpe_trigger_work *work;

	trigger_context = (struct zhpe_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context ||
	    ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) &&
	     (trigger_context->event_type != ZHPE_DEFERRED_WORK)))
		return -FI_EINVAL;

	work = &trigger_context->trigger.work;
	cntr = container_of(work->triggering_cntr, struct zhpe_cntr, cntr_fid);
	if (atm_load_rlx(&cntr->value) >= work->threshold)
		return 1;
	work->completion_cntr = NULL;
	flags = (flags & ~FI_TRIGGER) | ZHPE_TRIGGERED_OP;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->context = trigger_context;
	trigger->threshold = work->threshold;

	memcpy(&trigger->op.rma.msg, msg, sizeof(*msg));
	trigger->op.rma.msg.msg_iov = &trigger->op.rma.msg_iov[0];
	trigger->op.rma.msg.desc    = &trigger->op.rma.desc[0];
	trigger->op.rma.msg.rma_iov = &trigger->op.rma.rma_iov[0];

	memcpy(&trigger->op.rma.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.rma.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));
	memcpy(&trigger->op.rma.rma_iov[0], &msg->rma_iov[0],
	       msg->rma_iov_count * sizeof(struct fi_rma_iov));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->lentry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t zhpe_queue_msg_op(struct fid_ep *ep, const struct fi_msg *msg,
			  uint64_t flags, enum fi_op_type op_type)
{
	struct zhpe_cntr *cntr;
	struct zhpe_trigger *trigger;
	struct zhpe_triggered_context *trigger_context;
	struct zhpe_trigger_work *work;

	trigger_context = (struct zhpe_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context ||
	    ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) &&
	     (trigger_context->event_type != ZHPE_DEFERRED_WORK)))
		return -FI_EINVAL;

	work = &trigger_context->trigger.work;
	cntr = container_of(work->triggering_cntr, struct zhpe_cntr, cntr_fid);
	if (atm_load_rlx(&cntr->value) >= work->threshold)
		return 1;
	work->completion_cntr = NULL;
	flags = (flags & ~FI_TRIGGER) | ZHPE_TRIGGERED_OP;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->context = trigger_context;
	trigger->threshold = work->threshold;

	memcpy(&trigger->op.msg.msg, msg, sizeof(*msg));
	trigger->op.msg.msg.msg_iov = &trigger->op.msg.msg_iov[0];
	trigger->op.msg.msg.desc    = &trigger->op.msg.desc[0];
	memcpy((void *) &trigger->op.msg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.msg.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->lentry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t zhpe_queue_tmsg_op(struct fid_ep *ep, const struct fi_msg_tagged *msg,
			   uint64_t flags, enum fi_op_type op_type)
{
	struct zhpe_cntr *cntr;
	struct zhpe_trigger *trigger;
	struct zhpe_triggered_context *trigger_context;
	struct zhpe_trigger_work *work;

	trigger_context = (struct zhpe_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context ||
	    ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) &&
	     (trigger_context->event_type != ZHPE_DEFERRED_WORK)))
		return -FI_EINVAL;

	work = &trigger_context->trigger.work;
	cntr = container_of(work->triggering_cntr, struct zhpe_cntr, cntr_fid);
	if (atm_load_rlx(&cntr->value) >= work->threshold)
		return 1;
	work->completion_cntr = NULL;
	flags = (flags & ~FI_TRIGGER) | ZHPE_TRIGGERED_OP;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->context = trigger_context;
	trigger->threshold = work->threshold;

	memcpy(&trigger->op.tmsg.msg, msg, sizeof(*msg));
	trigger->op.tmsg.msg.msg_iov = &trigger->op.tmsg.msg_iov[0];
	trigger->op.tmsg.msg.desc    = &trigger->op.tmsg.desc[0];
	memcpy(&trigger->op.tmsg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.tmsg.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->lentry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t zhpe_queue_atomic_op(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev, size_t compare_count,
			     struct fi_ioc *resultv, size_t result_count,
			     uint64_t flags, enum fi_op_type op_type)
{
	struct zhpe_cntr *cntr;
	struct zhpe_trigger *trigger;
	struct zhpe_triggered_context *trigger_context;
	struct zhpe_trigger_work *work;

	trigger_context = (struct zhpe_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context ||
	    ((trigger_context->event_type != FI_TRIGGER_THRESHOLD) &&
	     (trigger_context->event_type != ZHPE_DEFERRED_WORK)))
		return -FI_EINVAL;

	work = &trigger_context->trigger.work;
	cntr = container_of(work->triggering_cntr, struct zhpe_cntr, cntr_fid);
	if (atm_load_rlx(&cntr->value) >= work->threshold)
		return 1;
	work->completion_cntr = NULL;
	flags = (flags & ~FI_TRIGGER) | ZHPE_TRIGGERED_OP;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->context = trigger_context;
	trigger->threshold = work->threshold;

	memcpy(&trigger->op.atomic.msg, msg, sizeof(*msg));
	trigger->op.atomic.msg.msg_iov = &trigger->op.atomic.msg_iov[0];
	trigger->op.atomic.msg.desc    = &trigger->op.rma.desc[0];
	trigger->op.atomic.msg.rma_iov = &trigger->op.atomic.rma_iov[0];

	memcpy(&trigger->op.atomic.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct fi_ioc));
	memcpy(&trigger->op.atomic.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));
	memcpy(&trigger->op.atomic.rma_iov[0], &msg->rma_iov[0],
	       msg->iov_count * sizeof(struct fi_rma_ioc));

	if (comparev) {
		memcpy(&trigger->op.atomic.comparev[0], &comparev[0],
		       compare_count * sizeof(struct fi_ioc));
		memcpy(&trigger->op.atomic.compare_desc[0], &msg->desc[0],
		       msg->iov_count * sizeof(void *));
		trigger->op.atomic.compare_count = compare_count;
	}

	if (resultv) {
		memcpy(&trigger->op.atomic.resultv[0], &resultv[0],
		       result_count * sizeof(struct fi_ioc));
		memcpy(&trigger->op.atomic.result_desc[0], &msg->desc[0],
		       msg->iov_count * sizeof(void *));
		trigger->op.atomic.result_count = result_count;
	}

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->lentry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t zhpe_queue_cntr_op(struct fi_deferred_work *work, uint64_t flags)
{
	struct zhpe_cntr *cntr;
	struct zhpe_trigger *trigger;

	cntr = container_of(work->triggering_cntr, struct zhpe_cntr, cntr_fid);
	if (atm_load_rlx(&cntr->value) >= work->threshold) {
		if (work->op_type == FI_OP_CNTR_SET)
			fi_cntr_set(work->op.cntr->cntr, work->op.cntr->value);
		else
			fi_cntr_add(work->op.cntr->cntr, work->op.cntr->value);
		return 0;
	}

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->context = (struct zhpe_triggered_context *) &work->context;
	trigger->op_type = work->op_type;
	trigger->threshold = work->threshold;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->lentry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	zhpe_cntr_check_trigger_list(cntr);
	return 0;
}
