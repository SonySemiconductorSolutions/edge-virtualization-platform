/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>

#include "blob.h"
#include "blob_type_evp.h"
#include "sdk_agent.h"

void
process_blob_rpcs(struct evp_agent_context *agent)
{
	struct blob_work *wk;

	while ((wk = sdk_dequeue_blob_rpc()) != NULL) {
		// TODO: Replace assert (programming error)
		assert(wk->type == BLOB_TYPE_EVP_EXT);
		blob_type_evp_start_rpc(agent, wk);
	}
}
