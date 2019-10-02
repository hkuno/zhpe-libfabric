/*
 * Copyright (c) 2014 Intel Corporation. All rights reserved.
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenFabrics.org BSD license below:
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

#define ZHPE_LOG_DBG(...) _ZHPE_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_LOG_ERROR(...) _ZHPE_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

struct zhpe_rx_ctx *zhpe_rx_ctx_alloc(const struct fi_rx_attr *attr,
				      void *context, struct zhpe_domain *domain)
{
	int			rc;
	struct zhpe_rx_ctx	*rx_ctx;

	rx_ctx = calloc_cachealigned(1, sizeof(*rx_ctx));
	if (!rx_ctx)
		return NULL;

	mutex_init(&rx_ctx->mutex, NULL);
	dlist_init(&rx_ctx->pe_lentry);
	dlist_init(&rx_ctx->cq_lentry);

	dlist_init(&rx_ctx->rx_posted_list);
	dlist_init(&rx_ctx->rx_buffered_list);
	dlist_init(&rx_ctx->rx_work_list);
	rx_ctx->rx_user_free.rx_ctx = rx_ctx;
	zhpeu_atm_fifo_init(&rx_ctx->rx_user_free.rx_fifo_list);
	rx_ctx->rx_prog_free.rx_ctx = rx_ctx;
	zhpeu_atm_fifo_init(&rx_ctx->rx_prog_free.rx_fifo_list);

	rx_ctx->ctx.fid.fclass = FI_CLASS_RX_CTX;
	rx_ctx->ctx.fid.context = context;
	rx_ctx->attr = *attr;

	rx_ctx->domain = domain;
	rc = ofi_bufpool_create(&rx_ctx->rx_user_free.rx_entry_pool,
				sizeof(struct zhpe_rx_entry), L1_CACHE_BYTES,
				0, 64, 0);
	if (rc < 0) {
		rx_ctx->rx_user_free.rx_entry_pool = NULL;
		ZHPE_LOG_ERROR("ofi_bufpool_create() error %d\n", rc);
		goto err;
	}
	rc = ofi_bufpool_create(&rx_ctx->rx_prog_free.rx_entry_pool,
				sizeof(struct zhpe_rx_entry), L1_CACHE_BYTES,
				0, 64, 0);
	if (rc < 0) {
		rx_ctx->rx_prog_free.rx_entry_pool = NULL;
		ZHPE_LOG_ERROR("ofi_bufpool_create() error %d\n", rc);
		goto err;
	}
	if (attr->total_buffered_recv > 0) {
		rc = zhpe_slab_init(&rx_ctx->eager, attr->total_buffered_recv,
				    domain);
		if (rc < 0) {
			ZHPE_LOG_ERROR("zhpe_slab_init(%Lu) error %d\n",
				       (ullong)attr->total_buffered_recv, rc);
			goto err;
		}
	}

	return rx_ctx;
 err:
	if (rx_ctx)
		zhpe_rx_ctx_free(rx_ctx);
	return NULL;
}

void zhpe_rx_ctx_free(struct zhpe_rx_ctx *rx_ctx)
{
	struct zhpe_rx_entry	*rx_entry;
	struct zhpeu_atm_snatch_head rxh_list;
	struct zhpeu_atm_list_next *rxh_cur;
	struct zhpeu_atm_list_next *rxh_next;

	/* FIXME: More to do. */
	while (!dlist_empty(&rx_ctx->rx_posted_list)) {
		dlist_pop_front(&rx_ctx->rx_posted_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		dlist_init(&rx_entry->lentry);
		zhpe_rx_release_entry(rx_entry);
	}
	while (!dlist_empty(&rx_ctx->rx_buffered_list)) {
		dlist_pop_front(&rx_ctx->rx_buffered_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		dlist_init(&rx_entry->lentry);
		zhpe_rx_release_entry(rx_entry);
	}
	while (!dlist_empty(&rx_ctx->rx_work_list)) {
		dlist_pop_front(&rx_ctx->rx_work_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		dlist_init(&rx_entry->lentry);
		zhpe_rx_release_entry(rx_entry);
	}
	while ((rxh_next =
		zhpeu_atm_fifo_pop(&rx_ctx->rx_user_free.rx_fifo_list)))
	{
		rx_entry = container_of(rxh_next, struct zhpe_rx_entry,
					rx_match_next);
		ofi_buf_free(rx_entry);
	}
	while ((rxh_next =
		zhpeu_atm_fifo_pop(&rx_ctx->rx_prog_free.rx_fifo_list)))
	{
		rx_entry = container_of(rxh_next, struct zhpe_rx_entry,
					rx_match_next);
		ofi_buf_free(rx_entry);
	}
	zhpeu_atm_snatch_list(&rx_ctx->rx_match_list, &rxh_list);
	for (rxh_cur = rxh_list.head; rxh_cur; rxh_cur = rxh_next) {
		rx_entry = container_of(rxh_cur, struct zhpe_rx_entry,
					rx_match_next);
		rxh_next = atm_load_rlx(&rxh_cur->next);
		if (rxh_next == ZHPEU_ATM_LIST_END)
			rxh_next = NULL;
		ofi_buf_free(rx_entry);
	}

	ofi_bufpool_destroy(rx_ctx->rx_user_free.rx_entry_pool);
	ofi_bufpool_destroy(rx_ctx->rx_prog_free.rx_entry_pool);
	zhpe_slab_destroy(&rx_ctx->eager);
	mutex_destroy(&rx_ctx->mutex);

	free(rx_ctx);
}

static struct zhpe_tx_ctx *zhpe_tx_context_alloc(const struct fi_tx_attr *attr,
						 void *context)
{
	struct zhpe_tx_ctx	*tx_ctx;

	tx_ctx = calloc_cachealigned(1, sizeof(*tx_ctx));
	if (!tx_ctx)
		return NULL;

	mutex_init(&tx_ctx->mutex, NULL);
	dlist_init(&tx_ctx->pe_lentry);
	dlist_init(&tx_ctx->cq_lentry);

	tx_ctx->ctx.fid.fclass = FI_CLASS_TX_CTX;
	tx_ctx->ctx.fid.context = context;
	tx_ctx->attr = *attr;
	tx_ctx->attr.op_flags |= FI_TRANSMIT_COMPLETE;

	return tx_ctx;
};

struct zhpe_tx_ctx *zhpe_tx_ctx_alloc(const struct fi_tx_attr *attr,
				      void *context)
{
	return zhpe_tx_context_alloc(attr, context);
}

void zhpe_tx_ctx_free(struct zhpe_tx_ctx *tx_ctx)
{
	mutex_destroy(&tx_ctx->mutex);
	free(tx_ctx);
}

