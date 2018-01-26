/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_CQ, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_CQ, __VA_ARGS__)

void zhpe_cq_add_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx)
{
	struct zhpe_tx_ctx	*curr_ctx;

	fastlock_acquire(&cq->list_lock);
	dlist_foreach_container(&cq->tx_list, struct zhpe_tx_ctx, curr_ctx,
				cq_lentry) {
		if (tx_ctx == curr_ctx)
			goto out;
	}
	dlist_insert_tail(&tx_ctx->cq_lentry, &cq->tx_list);
	ofi_atomic_inc32(&cq->ref);
out:
	fastlock_release(&cq->list_lock);
}

void zhpe_cq_remove_tx_ctx(struct zhpe_cq *cq, struct zhpe_tx_ctx *tx_ctx)
{
	fastlock_acquire(&cq->list_lock);
	dlist_remove(&tx_ctx->cq_lentry);
	ofi_atomic_dec32(&cq->ref);
	fastlock_release(&cq->list_lock);
}

void zhpe_cq_add_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx)
{
	struct zhpe_rx_ctx	*curr_ctx;

	fastlock_acquire(&cq->list_lock);
	dlist_foreach_container(&cq->rx_list, struct zhpe_rx_ctx, curr_ctx,
				cq_lentry) {
		if (rx_ctx == curr_ctx)
			goto out;
	}
	dlist_insert_tail(&rx_ctx->cq_lentry, &cq->rx_list);
	ofi_atomic_inc32(&cq->ref);
out:
	fastlock_release(&cq->list_lock);
}

void zhpe_cq_remove_rx_ctx(struct zhpe_cq *cq, struct zhpe_rx_ctx *rx_ctx)
{
	fastlock_acquire(&cq->list_lock);
	dlist_remove(&rx_ctx->cq_lentry);
	ofi_atomic_dec32(&cq->ref);
	fastlock_release(&cq->list_lock);
}

int zhpe_cq_progress(struct zhpe_cq *cq)
{
	struct zhpe_tx_ctx	*tx_ctx;
	struct zhpe_rx_ctx	*rx_ctx;

	if (cq->domain->progress_mode == FI_PROGRESS_AUTO)
		return 0;

	fastlock_acquire(&cq->list_lock);
	dlist_foreach_container(&cq->tx_list, struct zhpe_tx_ctx, tx_ctx,
				cq_lentry) {
		if (!tx_ctx->enabled)
			continue;

		if (tx_ctx->use_shared)
			zhpe_pe_progress_tx_ctx(cq->domain->pe,
						tx_ctx->stx_ctx);
		else
			zhpe_pe_progress_tx_ctx(cq->domain->pe, tx_ctx);
	}

	dlist_foreach_container(&cq->rx_list, struct zhpe_rx_ctx, rx_ctx,
				cq_lentry) {
		if (!rx_ctx->enabled)
			continue;

		if (rx_ctx->use_shared)
			zhpe_pe_progress_rx_ctx(cq->domain->pe,
						rx_ctx->srx_ctx);
		else
			zhpe_pe_progress_rx_ctx(cq->domain->pe, rx_ctx);
	}
	fastlock_release(&cq->list_lock);

	return 0;
}

static ssize_t zhpe_cq_entry_size(struct zhpe_cq *zhpe_cq)
{
	ssize_t size;

	switch (zhpe_cq->attr.format) {
	case FI_CQ_FORMAT_CONTEXT:
		size = sizeof(struct fi_cq_entry);
		break;

	case FI_CQ_FORMAT_MSG:
		size = sizeof(struct fi_cq_msg_entry);
		break;

	case FI_CQ_FORMAT_DATA:
		size = sizeof(struct fi_cq_data_entry);
		break;

	case FI_CQ_FORMAT_TAGGED:
		size = sizeof(struct fi_cq_tagged_entry);
		break;

	case FI_CQ_FORMAT_UNSPEC:
	default:
		size = -1;
		ZHPE_LOG_ERROR("Invalid CQ format\n");
		break;
	}
	return size;
}

static ssize_t _zhpe_cq_write(struct zhpe_cq *cq, fi_addr_t addr,
			      const void *buf, size_t len)
{
	ssize_t ret;
	struct zhpe_cq_overflow_entry_t *overflow_entry;

	fastlock_acquire(&cq->lock);
	if (ofi_rbfdavail(&cq->cq_rbfd) < len) {
		ZHPE_LOG_ERROR("Not enough space in CQ\n");
		overflow_entry = calloc(1, sizeof(*overflow_entry) + len);
		if (!overflow_entry) {
			ret = -FI_ENOSPC;
			goto out;
		}

		memcpy(&overflow_entry->cq_entry[0], buf, len);
		overflow_entry->len = len;
		overflow_entry->addr = addr;
		dlist_insert_tail(&overflow_entry->lentry, &cq->overflow_list);
		ret = len;
		goto out;
	}


	ofi_rbwrite(&cq->addr_rb, &addr, sizeof(addr));
	ofi_rbcommit(&cq->addr_rb);

	ofi_rbfdwrite(&cq->cq_rbfd, buf, len);
	if (cq->domain->progress_mode == FI_PROGRESS_MANUAL)
		ofi_rbcommit(&cq->cq_rbfd.rb);
	else
		ofi_rbfdcommit(&cq->cq_rbfd);

	ret = len;

	if (cq->signal)
		zhpe_wait_signal(cq->waitset);
out:
	fastlock_release(&cq->lock);
	return ret;
}

static int zhpe_cq_report_context(struct zhpe_cq *cq, fi_addr_t addr,
				  struct fi_cq_tagged_entry *tcqe)
{
	struct fi_cq_entry	cq_entry;

	cq_entry.op_context = tcqe->op_context;

	return _zhpe_cq_write(cq, addr, &cq_entry, sizeof(cq_entry));
}

static uint64_t zhpe_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (FI_SEND | FI_RECV | FI_RMA | FI_ATOMIC |
			 FI_MSG | FI_TAGGED | FI_READ | FI_WRITE |
			 FI_REMOTE_READ | FI_REMOTE_WRITE |
			 FI_REMOTE_CQ_DATA | FI_MULTI_RECV));
}

static int zhpe_cq_report_msg(struct zhpe_cq *cq, fi_addr_t addr,
			      struct fi_cq_tagged_entry *tcqe)
{
	struct fi_cq_msg_entry	cq_entry;

	cq_entry.op_context = tcqe->op_context;
	cq_entry.flags = zhpe_cq_sanitize_flags(tcqe->flags);
	cq_entry.len = tcqe->len;

	return _zhpe_cq_write(cq, addr, &cq_entry, sizeof(cq_entry));
}

static int zhpe_cq_report_data(struct zhpe_cq *cq, fi_addr_t addr,
			       struct fi_cq_tagged_entry *tcqe)
{
	struct fi_cq_data_entry	cq_entry;

	cq_entry.op_context = tcqe->op_context;
	cq_entry.flags = zhpe_cq_sanitize_flags(tcqe->flags);
	cq_entry.len = tcqe->len;
	cq_entry.buf = tcqe->buf;
	cq_entry.data = tcqe->data;

	return _zhpe_cq_write(cq, addr, &cq_entry, sizeof(cq_entry));
}

static int zhpe_cq_report_tagged(struct zhpe_cq *cq, fi_addr_t addr,
				 struct fi_cq_tagged_entry *tcqe)
{
	tcqe->flags = zhpe_cq_sanitize_flags(tcqe->flags);

	return _zhpe_cq_write(cq, addr, tcqe, sizeof(*tcqe));
}

static void zhpe_cq_set_report_fn(struct zhpe_cq *zhpe_cq)
{
	switch (zhpe_cq->attr.format) {
	case FI_CQ_FORMAT_CONTEXT:
		zhpe_cq->report_completion = &zhpe_cq_report_context;
		break;

	case FI_CQ_FORMAT_MSG:
		zhpe_cq->report_completion = &zhpe_cq_report_msg;
		break;

	case FI_CQ_FORMAT_DATA:
		zhpe_cq->report_completion = &zhpe_cq_report_data;
		break;

	case FI_CQ_FORMAT_TAGGED:
		zhpe_cq->report_completion = &zhpe_cq_report_tagged;
		break;

	case FI_CQ_FORMAT_UNSPEC:
	default:
		ZHPE_LOG_ERROR("Invalid CQ format\n");
		break;
	}
}

static inline void zhpe_cq_copy_overflow_list(struct zhpe_cq *cq, size_t count)
{
	size_t i;
	struct zhpe_cq_overflow_entry_t *overflow_entry;

	for (i = 0; i < count && !dlist_empty(&cq->overflow_list); i++) {
		overflow_entry = container_of(cq->overflow_list.next,
					      struct zhpe_cq_overflow_entry_t,
					      lentry);
		ofi_rbwrite(&cq->addr_rb, &overflow_entry->addr,
			    sizeof(fi_addr_t));
		ofi_rbcommit(&cq->addr_rb);

		ofi_rbfdwrite(&cq->cq_rbfd, &overflow_entry->cq_entry[0],
			      overflow_entry->len);
		if (cq->domain->progress_mode == FI_PROGRESS_MANUAL)
			ofi_rbcommit(&cq->cq_rbfd.rb);
		else
			ofi_rbfdcommit(&cq->cq_rbfd);

		dlist_remove(&overflow_entry->lentry);
		free(overflow_entry);
	}
}

static inline ssize_t zhpe_cq_rbuf_read(struct zhpe_cq *cq, void *buf,
					size_t count, fi_addr_t *src_addr,
					size_t cq_entry_len)
{
	size_t i;
	fi_addr_t addr;

	ofi_rbfdread(&cq->cq_rbfd, buf, cq_entry_len * count);
	for (i = 0; i < count; i++) {
		ofi_rbread(&cq->addr_rb, &addr, sizeof(addr));
		if (src_addr)
			src_addr[i] = addr;
	}
	zhpe_cq_copy_overflow_list(cq, count);
	return count;
}

static ssize_t zhpe_cq_sreadfrom(struct fid_cq *cq, void *buf, size_t count,
				 fi_addr_t *src_addr, const void *cond,
				 int timeout)
{
	int ret = 0;
	size_t threshold;
	struct zhpe_cq *zhpe_cq;
	uint64_t start_ms;
	ssize_t cq_entry_len, avail;

	zhpe_cq = container_of(cq, struct zhpe_cq, cq_fid);
	if (ofi_rbused(&zhpe_cq->cqerr_rb))
		return -FI_EAVAIL;

	cq_entry_len = zhpe_cq->cq_entry_size;
	if (zhpe_cq->attr.wait_cond == FI_CQ_COND_THRESHOLD)
		threshold = MIN((uintptr_t) cond, count);
	else
		threshold = count;

	start_ms = (timeout >= 0) ? fi_gettime_ms() : 0;

	if (zhpe_cq->domain->progress_mode == FI_PROGRESS_MANUAL) {
		while (1) {
			zhpe_cq_progress(zhpe_cq);
			fastlock_acquire(&zhpe_cq->lock);
			avail = ofi_rbfdused(&zhpe_cq->cq_rbfd);
			if (avail) {
				ret = zhpe_cq_rbuf_read(zhpe_cq, buf,
					MIN(threshold, (size_t)(avail / cq_entry_len)),
					src_addr, cq_entry_len);
			}
			fastlock_release(&zhpe_cq->lock);
			if (ret)
				return ret;

			if (timeout >= 0) {
				timeout -= (int) (fi_gettime_ms() - start_ms);
				if (timeout <= 0)
 					return -FI_EAGAIN;
 			}

			if (ofi_atomic_get32(&zhpe_cq->signaled)) {
				ofi_atomic_set32(&zhpe_cq->signaled, 0);
				return -FI_ECANCELED;
			}
		};
	} else {
		do {
			fastlock_acquire(&zhpe_cq->lock);
			ret = 0;
			avail = ofi_rbfdused(&zhpe_cq->cq_rbfd);
			if (avail) {
				ret = zhpe_cq_rbuf_read(zhpe_cq, buf,
					MIN(threshold, (size_t)(avail / cq_entry_len)),
					src_addr, cq_entry_len);
			} else { /* No CQ entry available, read the fd */
				ofi_rbfdreset(&zhpe_cq->cq_rbfd);
			}
			fastlock_release(&zhpe_cq->lock);
			if (ret && ret != -FI_EAGAIN)
				return ret;

			if (timeout >= 0) {
				timeout -= (int) (fi_gettime_ms() - start_ms);
				if (timeout <= 0)
					return -FI_EAGAIN;
			}

			if (ofi_atomic_get32(&zhpe_cq->signaled)) {
				ofi_atomic_set32(&zhpe_cq->signaled, 0);
				return -FI_ECANCELED;
			}
			ret = ofi_rbfdwait(&zhpe_cq->cq_rbfd, timeout);
		} while (ret > 0);
	}

	return (ret == 0 || ret == -FI_ETIMEDOUT) ? -FI_EAGAIN : ret;
}

static ssize_t zhpe_cq_sread(struct fid_cq *cq, void *buf, size_t len,
			     const void *cond, int timeout)
{
	return zhpe_cq_sreadfrom(cq, buf, len, NULL, cond, timeout);
}

static ssize_t zhpe_cq_readfrom(struct fid_cq *cq, void *buf, size_t count,
			fi_addr_t *src_addr)
{
	return zhpe_cq_sreadfrom(cq, buf, count, src_addr, NULL, 0);
}

static ssize_t zhpe_cq_read(struct fid_cq *cq, void *buf, size_t count)
{
	return zhpe_cq_readfrom(cq, buf, count, NULL);
}

static ssize_t zhpe_cq_readerr(struct fid_cq *cq, struct fi_cq_err_entry *buf,
			       uint64_t flags)
{
	struct zhpe_cq *zhpe_cq;
	ssize_t ret;
	struct fi_cq_err_entry entry;
	uint32_t api_version;
	size_t err_data_size = 0;
	void *err_data = NULL;

	zhpe_cq = container_of(cq, struct zhpe_cq, cq_fid);
	if (zhpe_cq->domain->progress_mode == FI_PROGRESS_MANUAL)
		zhpe_cq_progress(zhpe_cq);

	fastlock_acquire(&zhpe_cq->lock);
	if (ofi_rbused(&zhpe_cq->cqerr_rb) >= sizeof(struct fi_cq_err_entry)) {
		api_version = zhpe_cq->domain->fab->fab_fid.api_version;
		ofi_rbread(&zhpe_cq->cqerr_rb, &entry, sizeof(entry));

		if ((FI_VERSION_GE(api_version, FI_VERSION(1, 5)))
			&& buf->err_data && buf->err_data_size) {
			err_data = buf->err_data;
			err_data_size = buf->err_data_size;
			*buf = entry;
			buf->err_data = err_data;

			/* Fill provided user's buffer */
			buf->err_data_size =
				MIN(entry.err_data_size, err_data_size);
			memcpy(buf->err_data, entry.err_data,
			       buf->err_data_size);
		} else {
			memcpy(buf, &entry, sizeof(struct fi_cq_err_entry_1_0));
		}

		ret = 1;
	} else {
		ret = -FI_EAGAIN;
	}
	fastlock_release(&zhpe_cq->lock);
	return ret;
}

static const char *zhpe_cq_strerror(struct fid_cq *cq, int prov_errno,
			      const void *err_data, char *buf, size_t len)
{
	if (buf && len)
		return strncpy(buf, fi_strerror(prov_errno), len);
	return fi_strerror(prov_errno);
}

static int zhpe_cq_close(struct fid *fid)
{
	struct zhpe_cq *cq;

	cq = container_of(fid, struct zhpe_cq, cq_fid.fid);
	if (ofi_atomic_get32(&cq->ref))
		return -FI_EBUSY;

	if (cq->signal && cq->attr.wait_obj == FI_WAIT_MUTEX_COND)
		zhpe_wait_close(&cq->waitset->fid);

	ofi_rbfree(&cq->addr_rb);
	ofi_rbfree(&cq->cqerr_rb);
	ofi_rbfdfree(&cq->cq_rbfd);

	fastlock_destroy(&cq->lock);
	fastlock_destroy(&cq->list_lock);
	ofi_atomic_dec32(&cq->domain->ref);

	free(cq);
	return 0;
}

static int zhpe_cq_signal(struct fid_cq *cq)
{
	struct zhpe_cq *zhpe_cq;
	zhpe_cq = container_of(cq, struct zhpe_cq, cq_fid);

	ofi_atomic_set32(&zhpe_cq->signaled, 1);
	fastlock_acquire(&zhpe_cq->lock);
	ofi_rbfdsignal(&zhpe_cq->cq_rbfd);
	fastlock_release(&zhpe_cq->lock);
	return 0;
}

static struct fi_ops_cq zhpe_cq_ops = {
	.size = sizeof(struct fi_ops_cq),
	.read = zhpe_cq_read,
	.readfrom = zhpe_cq_readfrom,
	.readerr = zhpe_cq_readerr,
	.sread = zhpe_cq_sread,
	.sreadfrom = zhpe_cq_sreadfrom,
	.signal = zhpe_cq_signal,
	.strerror = zhpe_cq_strerror,
};

static int zhpe_cq_control(struct fid *fid, int command, void *arg)
{
	struct zhpe_cq *cq;
	int ret = 0;

	cq = container_of(fid, struct zhpe_cq, cq_fid);
	switch (command) {
	case FI_GETWAIT:
		if (cq->domain->progress_mode == FI_PROGRESS_MANUAL)
			return -FI_ENOSYS;

		switch (cq->attr.wait_obj) {
		case FI_WAIT_NONE:
		case FI_WAIT_FD:
		case FI_WAIT_UNSPEC:
			memcpy(arg, &cq->cq_rbfd.fd[OFI_RB_READ_FD],
			       sizeof(int));
			break;

		case FI_WAIT_SET:
		case FI_WAIT_MUTEX_COND:
			zhpe_wait_get_obj(cq->waitset, arg);
			break;

		default:
			ret = -FI_EINVAL;
			break;
		}
		break;

	default:
		ret =  -FI_EINVAL;
		break;
	}

	return ret;
}

static struct fi_ops zhpe_cq_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_cq_close,
	.bind = fi_no_bind,
	.control = zhpe_cq_control,
	.ops_open = fi_no_ops_open,
};

static int zhpe_cq_verify_attr(struct fi_cq_attr *attr)
{
	if (!attr)
		return 0;

	switch (attr->format) {
	case FI_CQ_FORMAT_CONTEXT:
	case FI_CQ_FORMAT_MSG:
	case FI_CQ_FORMAT_DATA:
	case FI_CQ_FORMAT_TAGGED:
		break;
	case FI_CQ_FORMAT_UNSPEC:
		attr->format = FI_CQ_FORMAT_CONTEXT;
		break;
	default:
		return -FI_ENOSYS;
	}

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

static struct fi_cq_attr _zhpe_cq_def_attr = {
	.size = ZHPE_CQ_DEF_SZ,
	.flags = 0,
	.format = FI_CQ_FORMAT_CONTEXT,
	.wait_obj = FI_WAIT_FD,
	.signaling_vector = 0,
	.wait_cond = FI_CQ_COND_NONE,
	.wait_set = NULL,
};

int zhpe_cq_open(struct fid_domain *domain, struct fi_cq_attr *attr,
		 struct fid_cq **cq, void *context)
{
	struct zhpe_domain *zhpe_dom;
	struct zhpe_cq *zhpe_cq;
	struct fi_wait_attr wait_attr;
	struct zhpe_fid_list *list_entry;
	struct zhpe_wait *wait;
	int ret;

	zhpe_dom = container_of(domain, struct zhpe_domain, dom_fid);
	ret = zhpe_cq_verify_attr(attr);
	if (ret)
		return ret;

	zhpe_cq = calloc(1, sizeof(*zhpe_cq));
	if (!zhpe_cq)
		return -FI_ENOMEM;

	ofi_atomic_initialize32(&zhpe_cq->ref, 0);
	ofi_atomic_initialize32(&zhpe_cq->signaled, 0);
	zhpe_cq->cq_fid.fid.fclass = FI_CLASS_CQ;
	zhpe_cq->cq_fid.fid.context = context;
	zhpe_cq->cq_fid.fid.ops = &zhpe_cq_fi_ops;
	zhpe_cq->cq_fid.ops = &zhpe_cq_ops;

	if (attr == NULL) {
		zhpe_cq->attr = _zhpe_cq_def_attr;
	} else {
		zhpe_cq->attr = *attr;
		if (attr->size == 0)
			zhpe_cq->attr.size = _zhpe_cq_def_attr.size;
	}

	zhpe_cq->domain = zhpe_dom;
	zhpe_cq->cq_entry_size = zhpe_cq_entry_size(zhpe_cq);
	zhpe_cq_set_report_fn(zhpe_cq);

	dlist_init(&zhpe_cq->tx_list);
	dlist_init(&zhpe_cq->rx_list);
	dlist_init(&zhpe_cq->ep_list);
	dlist_init(&zhpe_cq->overflow_list);

	ret = ofi_rbfdinit(&zhpe_cq->cq_rbfd, zhpe_cq->attr.size *
			zhpe_cq->cq_entry_size);
	if (ret)
		goto err1;

	ret = ofi_rbinit(&zhpe_cq->addr_rb,
			zhpe_cq->attr.size * sizeof(fi_addr_t));
	if (ret)
		goto err2;

	ret = ofi_rbinit(&zhpe_cq->cqerr_rb, zhpe_cq->attr.size *
			sizeof(struct fi_cq_err_entry));
	if (ret)
		goto err3;

	fastlock_init(&zhpe_cq->lock);

	switch (zhpe_cq->attr.wait_obj) {
	case FI_WAIT_NONE:
	case FI_WAIT_UNSPEC:
	case FI_WAIT_FD:
		break;

	case FI_WAIT_MUTEX_COND:
		wait_attr.flags = 0;
		wait_attr.wait_obj = FI_WAIT_MUTEX_COND;
		ret = zhpe_wait_open(&zhpe_dom->fab->fab_fid, &wait_attr,
				     &zhpe_cq->waitset);
		if (ret) {
			ret = -FI_EINVAL;
			goto err4;
		}
		zhpe_cq->signal = 1;
		break;

	case FI_WAIT_SET:
		if (!attr) {
			ret = -FI_EINVAL;
			goto err4;
		}

		zhpe_cq->waitset = attr->wait_set;
		zhpe_cq->signal = 1;
		wait = container_of(attr->wait_set,
				    struct zhpe_wait, wait_fid);
		list_entry = calloc(1, sizeof(*list_entry));
		if (!list_entry) {
                        ret = -FI_ENOMEM;
                        goto err4;
                }
		dlist_init(&list_entry->lentry);
		list_entry->fid = &zhpe_cq->cq_fid.fid;
		dlist_insert_after(&list_entry->lentry, &wait->fid_list);
		break;

	default:
		break;
	}

	*cq = &zhpe_cq->cq_fid;
	ofi_atomic_inc32(&zhpe_dom->ref);
	fastlock_init(&zhpe_cq->list_lock);

	return 0;

err4:
	ofi_rbfree(&zhpe_cq->cqerr_rb);
err3:
	ofi_rbfree(&zhpe_cq->addr_rb);
err2:
	ofi_rbfdfree(&zhpe_cq->cq_rbfd);
err1:
	free(zhpe_cq);
	return ret;
}

int zhpe_cq_report_error(struct zhpe_cq *cq, struct fi_cq_tagged_entry *tcqe,
			 size_t olen, int err, int prov_errno, void *err_data,
			 size_t err_data_size)
{
	int ret;
	struct fi_cq_err_entry err_entry;

	fastlock_acquire(&cq->lock);
	if (ofi_rbavail(&cq->cqerr_rb) < sizeof(err_entry)) {
		ret = -FI_ENOSPC;
		goto out;
	}

	err_entry.olen = olen;
	err_entry.err = err;
	err_entry.prov_errno = prov_errno;
	err_entry.err_data = err_data;
	err_entry.err_data_size = err_data_size;

	err_entry.op_context = tcqe->op_context;
	err_entry.flags = zhpe_cq_sanitize_flags(tcqe->flags);
	err_entry.len = tcqe->len;
	err_entry.buf = tcqe->buf;
	err_entry.data = tcqe->data;
	err_entry.tag = tcqe->tag;

	ofi_rbwrite(&cq->cqerr_rb, &err_entry, sizeof(err_entry));
	ofi_rbcommit(&cq->cqerr_rb);
	ret = 0;

	ofi_rbfdsignal(&cq->cq_rbfd);

out:
	fastlock_release(&cq->lock);
	return ret;
}
