/*
 * Copyright (c) 2014-2015 Intel Corporation, Inc.  All rights reserved.
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

static int do_trigger_init(struct fid_ep *fid_ep,
			   struct fi_triggered_context *tcontext,
			   uint64_t flags, enum fi_op_type op_type,
			   struct zhpe_trigger **trigger)
{
	if ((flags & FI_INJECT) || !tcontext ||
	    tcontext->event_type != FI_TRIGGER_THRESHOLD ||
	    !tcontext->trigger.threshold.cntr)
		return -FI_EINVAL;

	*trigger = calloc(1, sizeof(**trigger));
	if (!*trigger)
		return -FI_ENOMEM;

	(*trigger)->threshold = tcontext->trigger.threshold;
	(*trigger)->fid_ep = fid_ep;
	(*trigger)->flags = (flags & ~FI_TRIGGER) | ZHPE_TRIGGERED_OP;
	(*trigger)->op_type = op_type;

	return 0;
}

static int do_trigger_queue(struct zhpe_trigger *trigger)
{
	int			ret = 1;
	struct zhpe_cntr	*zcntr;

	zcntr = fid2zcntr(&trigger->threshold.cntr->fid);
	fastlock_acquire(&zcntr->trigger_lock);
	if (OFI_LIKELY(zhpe_cntr_read(zcntr) < trigger->threshold.threshold)) {
		dlist_insert_tail(&trigger->lentry, &zcntr->trigger_list);
		ret = 0;
	}
	fastlock_release(&zcntr->trigger_lock);
	if (OFI_UNLIKELY(ret))
		free(trigger);

	return ret;
}

ssize_t zhpe_queue_rma_op(struct fid_ep *fid_ep, const struct fi_msg_rma *msg,
			  uint64_t flags, enum fi_op_type op_type)
{
	int			rc;
	struct zhpe_trigger	*trigger;

	rc = do_trigger_init(fid_ep, msg->context, flags, op_type, &trigger);
	if (rc < 0)
		return rc;

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

	return do_trigger_queue(trigger);
}

ssize_t zhpe_queue_msg_op(struct fid_ep *fid_ep, const struct fi_msg *msg,
			  uint64_t flags, enum fi_op_type op_type)
{
	int			rc;
	struct zhpe_trigger	*trigger;

	rc = do_trigger_init(fid_ep, msg->context, flags, op_type, &trigger);
	if (rc < 0)
		return rc;

	memcpy(&trigger->op.msg.msg, msg, sizeof(*msg));
	trigger->op.msg.msg.msg_iov = &trigger->op.msg.msg_iov[0];
	trigger->op.msg.msg.desc    = &trigger->op.msg.desc[0];
	memcpy((void *) &trigger->op.msg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.msg.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));

	return do_trigger_queue(trigger);
}

ssize_t zhpe_queue_tmsg_op(struct fid_ep *fid_ep,
			   const struct fi_msg_tagged *msg,
			   uint64_t flags, enum fi_op_type op_type)
{
	int			rc;
	struct zhpe_trigger	*trigger;

	rc = do_trigger_init(fid_ep, msg->context, flags, op_type, &trigger);
	if (rc < 0)
		return rc;

	memcpy(&trigger->op.tmsg.msg, msg, sizeof(*msg));
	trigger->op.tmsg.msg.msg_iov = &trigger->op.tmsg.msg_iov[0];
	trigger->op.tmsg.msg.desc    = &trigger->op.tmsg.desc[0];
	memcpy(&trigger->op.tmsg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.tmsg.desc[0], &msg->desc[0],
	       msg->iov_count * sizeof(void *));


	return do_trigger_queue(trigger);
}

ssize_t zhpe_queue_atomic_op(struct fid_ep *fid_ep,
			     const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev,
			     size_t compare_count,
			     struct fi_ioc *resultv, size_t result_count,
			     uint64_t flags, enum fi_op_type op_type)
{
	int			rc;
	struct zhpe_trigger	*trigger;

	rc = do_trigger_init(fid_ep, msg->context, flags, op_type, &trigger);
	if (rc < 0)
		return rc;

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

	return do_trigger_queue(trigger);
}
