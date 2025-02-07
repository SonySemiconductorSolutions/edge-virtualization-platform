/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DEPLOYMENT_H
#define DEPLOYMENT_H

#include <stdbool.h>

#include "xpthread.h"

struct deployment {
	struct evp_lock mutex;
	bool locked;
	bool paused;
};

int deployment_init(struct deployment *);
int deployment_acquire(struct deployment *);
void deployment_release(struct deployment *);
int deployment_request_pause(struct deployment *);
int deployment_resume(struct deployment *);

#endif
