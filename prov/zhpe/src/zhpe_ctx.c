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
				      void *context, int use_shared,
				      struct zhpe_domain *domain)
{
	int			rc;
	struct zhpe_rx_ctx *rx_ctx;

	rx_ctx = calloc(1, sizeof(*rx_ctx));
	if (!rx_ctx)
		return NULL;

	dlist_init(&rx_ctx->pe_lentry);
	dlist_init(&rx_ctx->cq_lentry);

	dlist_init(&rx_ctx->rx_posted_list);
	dlist_init(&rx_ctx->rx_buffered_list);
	dlist_init(&rx_ctx->rx_work_list);
	dlist_init(&rx_ctx->ep_list);

	fastlock_init(&rx_ctx->lock);

	rx_ctx->ctx.fid.fclass = FI_CLASS_RX_CTX;
	rx_ctx->ctx.fid.context = context;
	rx_ctx->attr = *attr;
	rx_ctx->use_shared = use_shared;

	rx_ctx->domain = domain;
	rx_ctx->rx_entry_pool =
		util_buf_pool_create(sizeof(struct zhpe_rx_entry),
				     alignof(struct zhpe_rx_entry), 0, 64);
	if (!rx_ctx->rx_entry_pool)
		goto err;
	if (attr->total_buffered_recv > 0) {
		rc = zhpe_slab_init(&rx_ctx->eager,
				    attr->total_buffered_recv,
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

	/* FIXME: More to do. */
	while (!dlist_empty(&rx_ctx->rx_posted_list)) {
		dlist_pop_front(&rx_ctx->rx_posted_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		zhpe_rx_release_entry(rx_ctx, rx_entry);
	}
	while (!dlist_empty(&rx_ctx->rx_buffered_list)) {
		dlist_pop_front(&rx_ctx->rx_buffered_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		zhpe_rx_release_entry(rx_ctx, rx_entry);
	}
	while (!dlist_empty(&rx_ctx->rx_work_list)) {
		dlist_pop_front(&rx_ctx->rx_work_list,
				struct zhpe_rx_entry, rx_entry, lentry);
		zhpe_rx_release_entry(rx_ctx, rx_entry);
	}

	util_buf_pool_destroy(rx_ctx->rx_entry_pool);
	zhpe_slab_destroy(&rx_ctx->eager);
	fastlock_destroy(&rx_ctx->lock);

	free(rx_ctx);
}

static struct zhpe_tx_ctx *zhpe_tx_context_alloc(const struct fi_tx_attr *attr,
						 void *context, int use_shared,
						 size_t fclass)
{
	struct zhpe_tx_ctx *tx_ctx;

	tx_ctx = calloc(sizeof(*tx_ctx), 1);
	if (!tx_ctx)
		return NULL;

	dlist_init(&tx_ctx->pe_lentry);
	dlist_init(&tx_ctx->cq_lentry);

	dlist_init(&tx_ctx->ep_list);

	fastlock_init(&tx_ctx->lock);

	switch (fclass) {
	case FI_CLASS_TX_CTX:
		tx_ctx->fid.ctx.fid.fclass = FI_CLASS_TX_CTX;
		tx_ctx->fid.ctx.fid.context = context;
		tx_ctx->fclass = FI_CLASS_TX_CTX;
		tx_ctx->use_shared = use_shared;
		break;
	case FI_CLASS_STX_CTX:
		tx_ctx->fid.stx.fid.fclass = FI_CLASS_STX_CTX;
		tx_ctx->fid.stx.fid.context = context;
		tx_ctx->fclass = FI_CLASS_STX_CTX;
		break;
	default:
		goto err;
	}
	tx_ctx->attr = *attr;
	tx_ctx->attr.op_flags |= FI_TRANSMIT_COMPLETE;

	return tx_ctx;

err:
	free(tx_ctx);
	return NULL;
}


struct zhpe_tx_ctx *zhpe_tx_ctx_alloc(const struct fi_tx_attr *attr,
				      void *context, int use_shared)
{
	return zhpe_tx_context_alloc(attr, context, use_shared, FI_CLASS_TX_CTX);
}

struct zhpe_tx_ctx *zhpe_stx_ctx_alloc(const struct fi_tx_attr *attr,
					void *context)
{
	return zhpe_tx_context_alloc(attr, context, 0, FI_CLASS_STX_CTX);
}

void zhpe_tx_ctx_free(struct zhpe_tx_ctx *tx_ctx)
{
	fastlock_destroy(&tx_ctx->lock);

	free(tx_ctx);
}

