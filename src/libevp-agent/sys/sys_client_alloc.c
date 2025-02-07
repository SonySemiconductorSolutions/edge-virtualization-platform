/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdlib.h>

#include <internal/chan.h>

#include "../sdk_agent.h"
#include "../sdk_impl.h"
#include "../xlog.h"
#include "sys.h"

struct SYS_client *
sys_client_alloc(struct sys_group *gr)
{
	struct EVP_client *h = sdk_handle_alloc();
	struct SYS_client *ret = NULL;
	struct chan *ch = NULL;

	if (h == NULL) {
		xlog_error("sdk_handle_alloc failed");
		goto failure;
	}

	sdk_handle_init(h, sys_prefix);

	ch = chan_alloc();

	if (ch == NULL) {
		xlog_error("chan_alloc failed");
		goto failure;
	}

	ret = malloc(sizeof(*ret));

	if (ret == NULL) {
		goto failure;
	}

	*ret = (struct SYS_client){
		.h = h,
		.ch = ch,
		.gr = gr,
	};

	h->ch = ch;
	return ret;

failure:
	sdk_handle_free(h);
	chan_dealloc(ch);
	sys_client_dealloc(ret);
	return NULL;
}
