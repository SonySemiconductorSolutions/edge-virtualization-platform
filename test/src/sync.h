/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "xpthread.h"

struct sync_ctxt {
	struct evp_lock lock;
	pthread_cond_t cond;
	int threads;
	int threads_max;
	int config;
};

enum sync_config_flags {
	SYNC_CONFIG_KEEP_ACTIVE = (1 << 0),
};

int
sync_init(struct sync_ctxt *ctxt)
{
	int rv;
	rv = pthread_cond_init(&ctxt->cond, NULL);
	if (rv) {
		return rv;
	}

	rv = pthread_mutex_init(&ctxt->lock.lock, NULL);
	if (rv) {
		return rv;
	}

	return 0;
}

void
sync_config(struct sync_ctxt *ctxt, int flags)
{
	xpthread_mutex_lock(&ctxt->lock);
	ctxt->config = flags;
	xpthread_mutex_unlock(&ctxt->lock);
}

void
sync_activate(struct sync_ctxt *ctxt, int threads)
{
	xpthread_mutex_lock(&ctxt->lock);
	ctxt->threads = 0;
	ctxt->threads_max = threads;
	xpthread_mutex_unlock(&ctxt->lock);
}

void
sync_join(struct sync_ctxt *ctxt)
{
	xpthread_mutex_lock(&ctxt->lock);
	if (ctxt->threads != ctxt->threads_max) {
		// First threads will wait for cond var to be fired.
		// When all expected threads called `sync_join`,
		// the cond var is fired to resume waiting threads.
		if (++ctxt->threads != ctxt->threads_max) {
			xpthread_cond_wait(&ctxt->cond, &ctxt->lock);
		} else {
			xpthread_cond_signal(&ctxt->cond);
			if (ctxt->config & SYNC_CONFIG_KEEP_ACTIVE) {
				ctxt->threads = 0;
			}
		}
	}
	xpthread_mutex_unlock(&ctxt->lock);
}
