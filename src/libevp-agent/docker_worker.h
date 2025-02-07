/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__DOCKER_WORKER_H__)
#define __DOCKER_WORKER_H__

#include <config.h>

#include <stdbool.h>

#if defined(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_RAW_CONTAINER_SPEC)
#define RAW_CONTAINER_SPEC
#endif

#include <parson.h>

#include "docker.h"
#include "work.h"

struct docker_bind;

enum docker_op_type {
	DOCKER_OP_IMAGE_CREATE = 1,
	DOCKER_OP_CONTAINER_CREATE_AND_START = 2,
	DOCKER_OP_CONTAINER_STOP_AND_DELETE = 3,
	DOCKER_OP_IMAGE_PRUNE = 4,
	DOCKER_OP_CONTAINER_STATE = 5,
	DOCKER_OP_CONTAINER_KILLALL = 6,
};

struct docker_op {
	struct work wk;

	enum docker_op_type op;
	bool needs_completion_notification;
	bool sync_op_completed;

	int result; /* errno-style result */

	/* ---------- parameters and results ---------- */

	/*
	 * parameter for DOCKER_OP_IMAGE_CREATE and
	 * DOCKER_OP_CONTAINER_CREATE_AND_START
	 */
	const char *image;

	/*
	 * parameter for DOCKER_OP_CONTAINER_CREATE_AND_START
	 */
	unsigned int nbinds;
	const struct docker_bind *binds;
#if defined(RAW_CONTAINER_SPEC)
	const char *raw_container_name;
	JSON_Value *raw_container_spec;
#endif

	/*
	 * result for DOCKER_OP_CONTAINER_CREATE_AND_START
	 * parameter for DOCKER_OP_CONTAINER_STOP_AND_DELETE and
	 * DOCKER_OP_CONTAINER_STATE
	 */
	struct docker_container *cont;

	/*
	 * result for DOCKER_OP_CONTAINER_STATE
	 */
	enum DOCKER_CONTAINER_STATE_STATUS state_status;
	enum DOCKER_CONTAINER_STATE_HEALTH_STATUS state_health_status;
};

struct docker;

struct docker_worker {
	struct worker worker;
	struct docker *docker;
};

void docker_worker_start(struct mbedtls_ssl_config *ssl_config);
void docker_op_set_defaults(struct docker_op *op);

/*
 * docker_op_schedule: Schedule a docker operation
 *
 * Note:
 * While the current implemention uses a single worker thread to process
 * scheduled requests and thus effectively serializes them, this API
 * doesn't guarantee it.
 * It's caller's responsibility to serialize operations (probably
 * by scheduling them one by one) if the order of the operations is
 * important.
 */
void docker_op_schedule(struct docker_op *op);

int docker_op_cancel(struct docker_op *op);
void docker_op_schedule_and_wait(struct docker_op *op);
void docker_op_schedule_without_completion_notification(struct docker_op *op);

/*
 * docker_op_cancel_or_request_completion_notification:
 *
 * Try to cancel an operation scheduled with
 * docker_op_schedule_without_completion_notification.
 *
 * When it failed to cancel the operation, it enables completion
 * notification for the op. That is, when the operation is completed,
 * the main thread will be woken up.
 */
int docker_op_cancel_or_request_completion_notification(struct docker_op *op);

#endif /* !defined(__DOCKER_WORKER_H__) */
