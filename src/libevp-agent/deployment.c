/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <internal/util.h>

#include "deployment.h"
#include "module_impl.h"
#include "xlog.h"
#include "xpthread.h"

int
deployment_init(struct deployment *deployment)
{
	*deployment = (struct deployment){
		EVP_LOCK_INITIALIZER,
	};
	return 0;
}

int
deployment_acquire(struct deployment *deployment)
{
	int ret = 0;

	xpthread_mutex_lock(&deployment->mutex);
	if (deployment->locked) {
		// Lock is already acquired, do nothing.
	} else if (deployment->paused) {
		ret = EAGAIN;
		xlog_trace("User has paused deployment");
	} else {
		deployment->locked = true;
		xlog_trace("Agent acquired deployment lock");
	}
	xpthread_mutex_unlock(&deployment->mutex);

	return ret;
}

void
deployment_release(struct deployment *deployment)
{
	bool locked;
	xpthread_mutex_lock(&deployment->mutex);
	locked = deployment->locked;
	deployment->locked = false;
	xpthread_mutex_unlock(&deployment->mutex);
	if (locked) {
		xlog_trace("Agent released deployment lock");
	}
}

int
deployment_request_pause(struct deployment *deployment)
{
	int ret = 0;
	bool locked;

	xpthread_mutex_lock(&deployment->mutex);
	deployment->paused = true;
	locked = deployment->locked;
	xpthread_mutex_unlock(&deployment->mutex);

	if (locked) {
		ret = EAGAIN;
		xlog_debug("Agent owns deployment lock");
	}
	xlog_debug("User requested to pause deployment");
	return ret;
}

int
deployment_resume(struct deployment *deployment)
{
	xpthread_mutex_lock(&deployment->mutex);
	deployment->paused = false;
	xpthread_mutex_unlock(&deployment->mutex);
	xlog_debug("User requested to resume deployment");

	return 0;
}
