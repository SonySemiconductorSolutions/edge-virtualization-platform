/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "docker.h"
#include "docker_worker.h"
#include "main_loop.h"
#include "xlog.h"
#include "xpthread.h"

struct docker_worker worker0;
struct workq *docker_workq;

static void
process_docker_op(struct worker *gworker, struct work *wk)
{
	struct docker_worker *worker = (void *)gworker;
	struct docker *docker = worker->docker;
	struct docker_op *op = (void *)wk;

	switch (op->op) {
	case DOCKER_OP_IMAGE_CREATE:
		/*
		 * First, check if the image is locally available.
		 */
		op->result = image_inspect(docker, op->image);
		if (op->result == 0) {
			xlog_info("The image was found locally: %s",
				  op->image);
		} else {
			/*
			 * The image doesn't seem available.
			 * Try to pull it.
			 */
			xlog_info("Pulling the image: %s", op->image);
			op->result = image_create(docker, op->image);
			if (op->result == 0) {
				/*
				 * Note: image_create returns 0 if the
				 * operation succeeded at the http level. But
				 * even if http status was 200, the Docker API
				 * can report a failure in the response body
				 * via error/errorDetails. While we can make
				 * image_create recognize it, it would involve
				 * streaming JSON implementation which we don't
				 * have right now. For now, simply issue
				 * another API call to check the existence of
				 * the image.
				 */

				op->result = image_inspect(docker, op->image);
				if (op->result == 0) {
					xlog_info("Successfully pulled the "
						  "image: %s",
						  op->image);
				} else {
					xlog_error("Failed to inspect the "
						   "image with error %d: %s",
						   op->result, op->image);
				}
			} else {
				xlog_error("Failed to pull the image with "
					   "error %d: %s",
					   op->result, op->image);
			}
		}
		break;
	case DOCKER_OP_IMAGE_PRUNE:
		op->result = image_prune(docker);
		break;
	case DOCKER_OP_CONTAINER_CREATE_AND_START:
		{
			struct docker_container *cont;
			int ret;

#if defined(RAW_CONTAINER_SPEC)
			if (op->raw_container_spec != NULL) {
				ret = container_create_raw(
					docker, op->raw_container_name,
					op->raw_container_spec, &cont);
			} else {
#endif
				ret = container_create(docker, op->image,
						       op->nbinds, op->binds,
						       &cont, NULL);
#if defined(RAW_CONTAINER_SPEC)
			}
#endif
			if (ret != 0) {
				op->result = ret;
				break;
			}
			xlog_info("created a container %s",
				  container_id(cont));
			ret = container_start(cont);

			op->result = ret;
			if (ret != 0) {
				xlog_error(
					"failed to start the container %s %d",
					container_id(cont), ret);
				ret = container_delete(cont);
				if (ret != 0) {
					/*
					 * XXX todo: Run "docker container
					 * prune" equivalent periodically to
					 * clean up this kind of leftovers?
					 */
					xlog_info("leaving a container %s",
						  container_id(cont));
				}
				container_free(cont);
				/*
				 * Explicit NULL to avoid fortify false
				 * positive
				 */
				cont = NULL;
				break;
			}
			xlog_info("started a container %s",
				  container_id(cont));
			op->cont = cont;
		}
		break;
	case DOCKER_OP_CONTAINER_STOP_AND_DELETE:
		op->result = container_stop(op->cont, 5);
		if (op->result == 0 || op->result == ENOENT) {
			/*
			 * When Container stop success or Container not found
			 */
#if defined(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_DUMP_CONTAINER_LOG)
			xlog_info("=== dumping container log ===\n");
			int ret = container_logs(op->cont);
			if (ret != 0) {
				xlog_error("container_logs failed with %d",
					   ret);
			}
			xlog_info("=== end of the dump ===");
#endif
			op->result = container_delete(op->cont);
		}
		break;
	case DOCKER_OP_CONTAINER_STATE:
		op->result = container_state(op->cont, &op->state_status,
					     &op->state_health_status);
		break;
	case DOCKER_OP_CONTAINER_KILLALL:
		op->result = container_killall(docker);
		if (op->result == 0) {
			op->result = container_deleteall(docker);
		}
		break;
	default:
		// TODO: Replace assert (programming error)
		assert(false);
	}
}

void
docker_worker_start(struct mbedtls_ssl_config *ssl_config)
{
	struct docker_worker *worker = &worker0;
	worker->worker.name = "docker worker";
	worker->worker.process_item = process_docker_op;
	worker->docker = docker_create(xgetenv("EVP_DOCKER_HOST"), ssl_config,
				       getenv("EVP_DOCKER_UNIX_SOCKET"));
	worker->worker.max_jobs = 1;
	worker_manager_start(&worker->worker);
	docker_workq = &worker->worker.q;
}

void
docker_op_set_defaults(struct docker_op *op)
{
	work_set_defaults(&op->wk);
}

void
docker_op_schedule(struct docker_op *op)
{
	work_enqueue(docker_workq, &op->wk);
}

int
docker_op_cancel(struct docker_op *op)
{
	return work_trycancel(docker_workq, &op->wk);
}

static struct evp_lock sync_op_lock = EVP_LOCK_INITIALIZER;
static pthread_cond_t
	sync_op_cv EVP_GUARDED_BY(sync_op_lock) = PTHREAD_COND_INITIALIZER;

static struct work *
sync_op_cb(struct work *wk)
{
	struct docker_op *op = (void *)wk;
	// TODO: Replace assert (programming error)
	assert(&op->wk == wk);

	xpthread_mutex_lock(&sync_op_lock);
	xpthread_cond_signal(&sync_op_cv);
	op->sync_op_completed = true;
	xpthread_mutex_unlock(&sync_op_lock);
	/*
	 * Note: At this point, docker_op_schedule_and_wait might have
	 * already returned.
	 *
	 * It's no longer safe for us (the worker thread, including
	 * this callback) to touch "wk".
	 */
	return NULL;
}

void
docker_op_schedule_and_wait(struct docker_op *op)
{
	op->sync_op_completed = false;
	op->wk.done = sync_op_cb;
	docker_op_schedule(op);
	xpthread_mutex_lock(&sync_op_lock);
	while (!op->sync_op_completed) {
		xpthread_cond_wait(&sync_op_cv, &sync_op_lock);
	}
	xpthread_mutex_unlock(&sync_op_lock);
}

struct evp_lock g_docker_op_lock = EVP_LOCK_INITIALIZER;

static struct work *
docker_op_cb(struct work *wk)
{
	bool needs_main_wakeup;

	struct docker_op *op = (void *)wk;
	// TODO: Replace assert (programming error)
	assert(&op->wk == wk);
	xpthread_mutex_lock(&g_docker_op_lock);
	needs_main_wakeup = op->needs_completion_notification;
	xpthread_mutex_unlock(&g_docker_op_lock);
	if (needs_main_wakeup) {
		main_loop_wakeup("docker_op");
	}
	return wk;
}

void
docker_op_schedule_without_completion_notification(struct docker_op *op)
{
	op->wk.done = docker_op_cb;
	op->needs_completion_notification = false;
	docker_op_schedule(op);
}

int
docker_op_cancel_or_request_completion_notification(struct docker_op *op)
{
	int ret;

	// TODO: Replace assert (programming error)
	assert(op->wk.done == docker_op_cb);
	xpthread_mutex_lock(&g_docker_op_lock);
	ret = work_trycancel(docker_workq, &op->wk);
	if (ret == EBUSY) {
		op->needs_completion_notification = true;
	}
	xpthread_mutex_unlock(&g_docker_op_lock);
	return ret;
}
