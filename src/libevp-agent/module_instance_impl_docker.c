/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include <internal/util.h>

#include "container_spec.h"
#include "docker.h"
#include "docker_worker.h"
#include "manifest.h"
#include "module_instance_impl.h"
#include "module_instance_impl_ops.h"
#include "module_instance_path.h"
#include "path_docker.h"
#include "xlog.h"

/*
 * We usually assume that dockerd can "just" share MODULE_INSTANCE_DIR
 * to containers.
 * However, it isn't always the case for some complex setups, where the
 * EVP agent and dockerd don't share the same filesytem namespace. It includes
 * the topology called Docker out of Docker. ("DooD")
 * To cover such cases, we allow it to be overridden with the environment
 * variable EVP_MODULE_INSTANCE_DIR_FOR_DOCKERD. If it's set, we use it
 * instead of MODULE_INSTANCE_DIR when telling the dockerd the location of
 * the directory.
 */

static const char *module_instance_dir_for_dockerd;

static void
free_op(struct docker_op *op)
{
	switch (op->op) {
	case DOCKER_OP_CONTAINER_CREATE_AND_START:
		// TODO: Replace assert (programming error)
		assert(op->nbinds == 1);
		free(__UNCONST(op->image));
		free(__UNCONST(op->binds[0].host_src));
		free(__UNCONST(op->binds));
#if defined(RAW_CONTAINER_SPEC)
		free(__UNCONST(op->raw_container_name));
		if (op->raw_container_spec != NULL) {
			json_value_free(op->raw_container_spec);
		}
#endif
		break;
	case DOCKER_OP_CONTAINER_STOP_AND_DELETE:
	case DOCKER_OP_CONTAINER_STATE:
		break;
	default:
		// TODO: Replace assert (programming error)
		assert(false);
	}
	free(op);
}

static int
cancel_or_complete_op(struct module_instance *m, unsigned int ours)
{
	struct docker_op *op = m->docker_op;
	if (op != NULL) {
		int ret;
		assert(op->op == DOCKER_OP_CONTAINER_CREATE_AND_START ||
		       op->op == DOCKER_OP_CONTAINER_STOP_AND_DELETE ||
		       op->op == DOCKER_OP_CONTAINER_STATE);
		// TODO: Replace assert (programming error)
		assert((m->cont == NULL) ==
		       (op->op == DOCKER_OP_CONTAINER_CREATE_AND_START));
		ret = docker_op_cancel(op);
		if (ret != 0) {
			return ret;
		}
		m->docker_op = NULL;
		if (op->wk.status == WORK_STATUS_DONE) {
			int result = op->result;
			if (result != 0) {
				if (op->op != ours) {
					/* if the failed operation is not ours,
					 * don't care. */
					result = 0;
				} else {
					if (op->op ==
					    DOCKER_OP_CONTAINER_CREATE_AND_START) {
						// TODO: Replace assert
						// (programming error)
						assert(m->cont == NULL);
					}
					/*
					 * Don't make DOCKER_OP_CONTAINER_STATE
					 * overwrite the failure of other ops.
					 * The failure of other ops are likely
					 * more important.
					 */
					if (m->failureMessage == NULL ||
					    op->op !=
						    DOCKER_OP_CONTAINER_STATE) {
						free(m->failureMessage);
						xasprintf(&m->failureMessage,
							  "docker op %ju "
							  "failed with %d",
							  (uintmax_t)op->op,
							  result);
					}
				}
				free_op(op);
				return result;
			}
			/* the operation succeeded */
			if (op->op == DOCKER_OP_CONTAINER_CREATE_AND_START) {
				// TODO: Replace assert (programming error)
				assert(m->cont == NULL);
				m->cont = op->cont;
				// TODO: Replace assert (programming error)
				assert(m->cont != NULL);
			} else if (op->op == DOCKER_OP_CONTAINER_STATE) {
				// TODO: Replace assert (programming error)
				assert(m->cont != NULL);
				m->state_status = op->state_status;
				m->state_health_status =
					op->state_health_status;
			} else {
				/* DOCKER_OP_CONTAINER_STOP_AND_DELETE */
				// TODO: Replace assert (programming error)
				assert(m->cont != NULL);
				container_free(m->cont);
				m->stopped = true;
				m->cont = NULL;
			}
		} else {
			/* canceled before picked by the worker */
		}
		free_op(op);
	}
	return 0;
}

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *module_instance_dir, void *handle)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	// TODO: Replace assert (programming error)
	assert(m->cont == NULL);

	int ret =
		cancel_or_complete_op(m, DOCKER_OP_CONTAINER_CREATE_AND_START);
	if (ret != 0) {
		return ret;
	}
	if (m->cont == NULL) {
		char *host_src;

		if (module_instance_dir_for_dockerd != NULL) {
			xasprintf(&host_src, "%s/%s",
				  module_instance_dir_for_dockerd, m->name);
		} else {
			host_src = xstrdup(module_instance_dir);
		}

		struct docker_op *op = xcalloc(1, sizeof(*op));
		m->docker_op = op;
		docker_op_set_defaults(op);
		op->op = DOCKER_OP_CONTAINER_CREATE_AND_START;
		op->image = xstrdup(handle);
		op->nbinds = 1;
		struct docker_bind *binds = xcalloc(1, sizeof(*binds));
		binds[0].host_src = host_src;
		binds[0].container_dest = EVP_SHARED_DIR;
		op->binds = binds;

#if defined(RAW_CONTAINER_SPEC)
		if (spec->rawContainerSpec != NULL) {
			op->raw_container_spec =
				json_value_deep_copy(spec->rawContainerSpec);
			if (op->raw_container_spec == NULL) {
				return ENOMEM;
			}
			ret = container_spec_extra_assign_mounts(
				op->raw_container_spec, &m->failureMessage,
				m->name, host_src);
			if (ret != 0) {
				return ret;
			}
			op->raw_container_name = xstrdup(spec->name);
		}
#endif /* RAW_CONTAINER_SPEC */

		docker_op_schedule(op);
		return EAGAIN;
	}
	return 0;
}

static int
impl_stop(struct module_instance *m)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);

	int ret =
		cancel_or_complete_op(m, DOCKER_OP_CONTAINER_STOP_AND_DELETE);
	if (ret != 0) {
		return ret;
	}
	if (m->cont != NULL) {
		struct docker_op *op = xcalloc(1, sizeof(*op));
		m->docker_op = op;
		docker_op_set_defaults(op);
		op->op = DOCKER_OP_CONTAINER_STOP_AND_DELETE;
		op->cont = m->cont;
		docker_op_schedule(op);
		return EAGAIN;
	}
	return 0;
}

static bool
impl_is_running(struct module_instance *m)
{
	return m->cont != NULL;
}

static bool
impl_has_stopped(struct module_instance *m)
{
	return m->stopped;
}

static const char *
impl_stat(struct module_instance *m)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);

	struct docker_op *op = m->docker_op;
	int ret;
	if (op != NULL) {
		// TODO: Replace assert (programming error)
		assert((m->cont == NULL) ==
		       (op->op == DOCKER_OP_CONTAINER_CREATE_AND_START));
		switch (op->op) {
		case DOCKER_OP_CONTAINER_CREATE_AND_START:
			return "starting";
		case DOCKER_OP_CONTAINER_STOP_AND_DELETE:
			return "stopping";
		case DOCKER_OP_CONTAINER_STATE:
			ret = cancel_or_complete_op(m,
						    DOCKER_OP_CONTAINER_STATE);
			if (ret == 0) {
				break;
			}
			return "status-check-backoff";
		default:
			// Exit (xlog_abort): docker error
			xlog_abort("Unexpected docker op %u is in-progress",
				   (unsigned int)op->op);
		}
	}

	if (m->cont == NULL) {
		return NULL;
	}

	/*
	 * Note: If a RAW_CONTAINER_SPEC container with AutoRemove=true
	 * exits voluntarily, it will be reported as a "docker op 5 failed with
	 * 5" error.
	 */

	const char *result;
	switch (m->state_status) {
	case DOCKER_CONTAINER_STATE_STATUS_RUNNING:
		switch (m->state_health_status) {
		case DOCKER_CONTAINER_STATE_HEALTH_STATUS_NONE:
		case DOCKER_CONTAINER_STATE_HEALTH_STATUS_HEALTHY:
			result = "ok";
			break;
		default:
			result = "unknown";
			break;
		}
		break;
	case DOCKER_CONTAINER_STATE_STATUS_EXITED:
		result = "self-exiting";
		break;
	case DOCKER_CONTAINER_STATE_STATUS_NONE:
		/*
		 * We come here when:
		 *
		 * - DOCKER_OP_CONTAINER_CREATE_AND_START has already completed
		 *   (thus not "starting" anymore)
		 *
		 * - but we haven't successfully queried the docker about
		 *   the container state yet.
		 */
		result = "started";
		break;
	default:
		result = "unknown";
	}

	op = xcalloc(1, sizeof(*op));
	m->docker_op = op;
	docker_op_set_defaults(op);
	op->op = DOCKER_OP_CONTAINER_STATE;
	op->cont = m->cont;
	/*
	 * We don't need completion events here because there is
	 * another layer of polling. (periodic_report)
	 */
	docker_op_schedule_without_completion_notification(op);

	return result;
}

static int
impl_convert_path(struct module_instance *m,
		  const char *path_in_module_instance, char **resultp)
{
	char *path;
	int error;

	path = malloc(PATH_MAX);
	if (path == NULL) {
		return ENOMEM;
	}
	error = convert_module_instance_path(m->name, path_in_module_instance,
					     path, PATH_MAX);
	if (error != 0) {
		free(path);
		return error;
	}
	*resultp = path;
	return 0;
}

static int
impl_init(void)
{
	module_instance_dir_for_dockerd =
		getenv("EVP_MODULE_INSTANCE_DIR_FOR_DOCKERD");
	if (module_instance_dir_for_dockerd != NULL) {
		xlog_info("EVP_MODULE_INSTANCE_DIR_FOR_DOCKERD=%s",
			  module_instance_dir_for_dockerd);
	}

	/*
	 * Kill all containers left from the previous run.
	 *
	 * We can't adopt them because:
	 * - The sdkrpc doesn't support reconnect
	 */

	struct docker_op op0;
	struct docker_op *op = &op0;
retry:
	docker_op_set_defaults(op);
	op->op = DOCKER_OP_CONTAINER_KILLALL;
	docker_op_schedule_and_wait(op);
	if (op->result != 0) {
		switch (op->result) {
		case ECONNREFUSED:
			/*
			 * ECONNREFUSED (MBEDTLS_ERR_NET_CONNECT_FAILED)
			 * happens when docker is not ready yet. In that case,
			 * just retry. We can't do anything useful without a
			 * working docker anyway.
			 *
			 * It also happens when docker unix socket is not ready
			 * yet. (translated from ENOENT by docker.c)
			 */
		case EAGAIN:
			xlog_info("DOCKER_OP_CONTAINER_KILLALL failed with "
				  "%d, retrying",
				  op->result);
			sleep(1);
			goto retry;
		default:
			// Exit (xlog_abort): docker error
			xlog_abort(
				"DOCKER_OP_CONTAINER_KILLALL failed with %d",
				op->result);
		}
	}
	return 0;
}

static void
impl_post_create(struct module_instance *m)
{
}

const struct module_instance_impl_ops module_instance_impl_ops_docker = {
	.name = "docker",
	.convert_path = impl_convert_path,
	.is_running = impl_is_running,
	.has_stopped = impl_has_stopped,
	.init = impl_init,
	.post_create = impl_post_create,
	.stop = impl_stop,
	.start = impl_start,
	.stat = impl_stat,
};
