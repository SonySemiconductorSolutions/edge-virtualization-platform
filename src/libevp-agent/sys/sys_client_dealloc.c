/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/chan.h>

#include "../sdk_agent.h"
#include "../sdk_impl.h"
#include "sys.h"

void
sys_client_dealloc(struct SYS_client *cl)
{
	if (!cl) {
		return;
	}

	chan_dealloc(cl->ch);
	/* TODO: sdk_cleanup requires this flag, but it should be set when
	 * SYS_RESULT_SHOULD_EXIT is returned to the SYS_client. */
	cl->h->exiting = true;
	sdk_cleanup(cl->h);
	free(cl);
}
