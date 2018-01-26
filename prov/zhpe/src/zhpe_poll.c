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

static int zhpe_poll_add(struct fid_poll *pollset, struct fid *event_fid,
			 uint64_t flags)
{
	struct zhpe_poll *poll;
	struct zhpe_fid_list *list_item;
	struct zhpe_cq *cq;
	struct zhpe_cntr *cntr;

	poll = container_of(pollset, struct zhpe_poll, poll_fid.fid);
	list_item = calloc(1, sizeof(*list_item));
	if (!list_item)
		return -FI_ENOMEM;

	list_item->fid = event_fid;
	dlist_insert_after(&list_item->lentry, &poll->fid_list);

	switch (list_item->fid->fclass) {
	case FI_CLASS_CQ:
		cq = container_of(list_item->fid, struct zhpe_cq, cq_fid);
		ofi_atomic_inc32(&cq->ref);
		break;
	case FI_CLASS_CNTR:
		cntr = container_of(list_item->fid, struct zhpe_cntr,
				    cntr_fid);
		ofi_atomic_inc32(&cntr->ref);
		break;
	default:
		ZHPE_LOG_ERROR("Invalid fid class\n");
		return -FI_EINVAL;
	}
	return 0;
}

static int zhpe_poll_del(struct fid_poll *pollset, struct fid *event_fid,
			 uint64_t flags)
{
	struct zhpe_poll *poll;
	struct zhpe_fid_list *list_item;
	struct zhpe_cq *cq;
	struct zhpe_cntr *cntr;

	poll = container_of(pollset, struct zhpe_poll, poll_fid.fid);
	dlist_foreach_container(&poll->fid_list, struct zhpe_fid_list,
				list_item, lentry) {
		if (list_item->fid == event_fid) {
			switch (list_item->fid->fclass) {
			case FI_CLASS_CQ:
				cq = container_of(list_item->fid,
						  struct zhpe_cq, cq_fid);
				ofi_atomic_dec32(&cq->ref);
				break;
			case FI_CLASS_CNTR:
				cntr = container_of(list_item->fid,
						    struct zhpe_cntr,
						    cntr_fid);
				ofi_atomic_dec32(&cntr->ref);
				break;
			default:
				ZHPE_LOG_ERROR("Invalid fid class\n");
				break;
			}
			dlist_remove(&list_item->lentry);
			free(list_item);
			break;
		}
	}
	return 0;
}

static int zhpe_poll_poll(struct fid_poll *pollset, void **context, int count)
{
	struct zhpe_poll *poll;
	struct zhpe_cq *cq;
	struct zhpe_eq *eq;
	struct zhpe_cntr *cntr;
	struct zhpe_fid_list *list_item;
	int ret_count = 0;

	poll = container_of(pollset, struct zhpe_poll, poll_fid.fid);

	dlist_foreach_container(&poll->fid_list, struct zhpe_fid_list,
				list_item, lentry) {
		switch (list_item->fid->fclass) {
		case FI_CLASS_CQ:
			cq = container_of(list_item->fid, struct zhpe_cq,
						cq_fid);
			zhpe_cq_progress(cq);
			fastlock_acquire(&cq->lock);
			if (ofi_rbfdused(&cq->cq_rbfd) ||
			    ofi_rbused(&cq->cqerr_rb)) {
				*context++ = cq->cq_fid.fid.context;
				ret_count++;
			}
			fastlock_release(&cq->lock);
			break;

		case FI_CLASS_CNTR:
			cntr = container_of(list_item->fid, struct zhpe_cntr,
						cntr_fid);
			zhpe_cntr_progress(cntr);
			mutex_acquire(&cntr->mut);
			if (ofi_atomic_get32(&cntr->value) !=
			    ofi_atomic_get32(&cntr->last_read_val)) {
				ofi_atomic_set32(&cntr->last_read_val,
					   ofi_atomic_get32(&cntr->value));
				*context++ = cntr->cntr_fid.fid.context;
				ret_count++;
			}
			mutex_release(&cntr->mut);
			break;

		case FI_CLASS_EQ:
			eq = container_of(list_item->fid, struct zhpe_eq, eq);
			fastlock_acquire(&eq->lock);
			if (!dlistfd_empty(&eq->list) ||
				!dlistfd_empty(&eq->err_list)) {
				*context++ = eq->eq.fid.context;
				ret_count++;
			}
			fastlock_release(&eq->lock);
			break;

		default:
			break;
		}
	}

	return ret_count;
}

static int zhpe_poll_close(fid_t fid)
{
	struct zhpe_poll *poll;
	struct fid_list_entry *list_item;
	struct dlist_entry *p, *head;

	poll = container_of(fid, struct zhpe_poll, poll_fid.fid);

	head = &poll->fid_list;
	while (!dlist_empty(head)) {
		p = head->next;
		list_item = container_of(p, struct fid_list_entry, entry);
		zhpe_poll_del(&poll->poll_fid, list_item->fid, 0);
	}

	ofi_atomic_dec32(&poll->domain->ref);
	free(poll);
	return 0;
}

static struct fi_ops zhpe_poll_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_poll_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = fi_no_ops_open,
};

static struct fi_ops_poll zhpe_poll_ops = {
	.size = sizeof(struct fi_ops_poll),
	.poll = zhpe_poll_poll,
	.poll_add = zhpe_poll_add,
	.poll_del = zhpe_poll_del,
};

static int zhpe_poll_verify_attr(struct fi_poll_attr *attr)
{
	if (attr->flags)
		return -FI_ENODATA;
	return 0;
}

int zhpe_poll_open(struct fid_domain *domain, struct fi_poll_attr *attr,
		   struct fid_poll **pollset)
{
	struct zhpe_domain *dom;
	struct zhpe_poll *poll;

	if (attr && zhpe_poll_verify_attr(attr))
		return -FI_EINVAL;

	dom = container_of(domain, struct zhpe_domain, dom_fid);
	poll = calloc(1, sizeof(*poll));
	if (!poll)
		return -FI_ENOMEM;

	dlist_init(&poll->fid_list);
	poll->poll_fid.fid.fclass = FI_CLASS_POLL;
	poll->poll_fid.fid.context = 0;
	poll->poll_fid.fid.ops = &zhpe_poll_fi_ops;
	poll->poll_fid.ops = &zhpe_poll_ops;
	poll->domain = dom;
	ofi_atomic_inc32(&dom->ref);

	*pollset = &poll->poll_fid;
	return 0;
}
