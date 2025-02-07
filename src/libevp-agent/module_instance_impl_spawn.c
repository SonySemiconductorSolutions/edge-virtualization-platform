/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "manifest.h"
#include "module_instance_impl.h"
#include "module_instance_impl_noop.h"
#include "module_instance_impl_ops.h"
#include "path.h"
#include "timeutil.h"
#include "xlog.h"

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *module_instance_dir, void *handle)
{
	int ret;
	char *args[] = {NULL};
	/* Below environment variables need to be shared with modules.
	envp[0] :
	EVP_MODULE_SDK_SOCKET_PATH=/evp_data/instances/<instance_name>/sdk.sock
	envp[1] :
	EVP_MODULE_SDK_DEFAULT_WORKSPACE_PATH=/evp_data/instances/<instance_name>/default_workspace
	envp[2] : NULL (Must be terminated by a NULL pointer.) */
	char *envp[] = {NULL, NULL, NULL};

	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	// TODO: Replace assert (programming error)
	assert(m->pid == -1);

	const char *module_instance_path = path_get(MODULE_INSTANCE_PATH_ID);
	char *socket_path = NULL;
	char *workspace_path = NULL;
	ret = asprintf(&socket_path, "EVP_MODULE_SDK_SOCKET_PATH=%s/%s/%s",
		       module_instance_path, m->name, SDK_SOCKET_NAME);
	if (ret < 0) {
		xlog_error("asprintf(3) failed with: %s", strerror(errno));
		ret = errno;
		goto finish;
	}
	envp[0] = socket_path;

	ret = asprintf(&workspace_path,
		       "EVP_MODULE_SDK_DEFAULT_WORKSPACE_PATH=%s/%s/%s",
		       module_instance_path, m->name, DEFAULT_WORKSPACE_DIR);
	if (ret < 0) {
		xlog_error("asprintf(3) failed with: %s", strerror(errno));
		ret = errno;
		goto finish;
	}
	envp[1] = workspace_path;

	ret = posix_spawn(&m->pid, handle, NULL, NULL, args, envp);
	if (ret != 0) {
		free(m->failureMessage);
		xasprintf(&m->failureMessage,
			  "Module %s fail to create process with error %d",
			  spec->moduleId, ret);
		ret = EAGAIN;
		goto finish;
	}

	ret = 0;

finish:
	free(socket_path);
	free(workspace_path);
	return ret;
}

int
module_instance_impl_spawn_stop(struct module_instance *m)
{
	int ret = 0;
	int status;

	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	if (m->pid == -1) {
		goto stopped;
	}

	if (!m->stop_request_time.tv_sec && !m->stop_request_time.tv_nsec) {
		gettime(&m->stop_request_time);
	} else {
		struct timespec ts;
		gettime(&ts);
		time_t elapsed_s = ts.tv_sec - m->stop_request_time.tv_sec;
		if (elapsed_s > CONFIG_EVP_MODULE_INSTANCE_STOP_TIMEOUT) {
			kill(m->pid, SIGKILL);
		}
	}

	ret = waitpid(m->pid, &status, WNOHANG);
	if (ret == m->pid &&
	    (WIFEXITED(status) || WIFSIGNALED(status) || WIFSTOPPED(status))) {
		goto stopped;
	}
	if (ret == (pid_t)-1) {
		// Note: With WNOHANG, errno EINTR should not occur.
		xlog_abortif(errno != ECHILD,
			     "waitpid(%d) on instance %s failed with %s",
			     m->pid, m->name, strerror(errno));

		goto stopped;
	}
	return EBUSY;

stopped:
	m->stopped = true;
	return 0;
}

bool
module_instance_impl_spawn_is_running(struct module_instance *m)
{
	return m->pid != -1;
}

bool
module_instance_impl_spawn_has_stopped(struct module_instance *m)
{
	return m->stopped;
}

const char *
module_instance_impl_spawn_stat(struct module_instance *m)
{
	int module_status;
	const char *status;

	if (m->pid == -1) {
		return NULL;
	}

	pid_t ret = waitpid(m->pid, &module_status, WNOHANG);
	if (ret == 0) {
		status = "ok";
	} else if (ret > 0) {
		if (WIFEXITED(module_status) || WIFSIGNALED(module_status) ||
		    WIFSTOPPED(module_status)) {
			status = "self-exiting";
			m->pid = -1;
			m->stopped = true;
		} else {
			status = "unknown";
		}
	} else {
		if (errno == ECHILD) {
			xlog_info("module does not exist");
			status = "self-exiting";
		} else {
			status = "unknown";
		}
	}

	return status;
}

int
module_instance_impl_spawn_init(void)
{
	return 0;
}

void
module_instance_impl_spawn_post_create(struct module_instance *m)
{
}

const struct module_instance_impl_ops module_instance_impl_ops_spawn = {
	.name = "spawn",
	.convert_path = module_instance_impl_noop_convert_path,
	.is_running = module_instance_impl_spawn_is_running,
	.has_stopped = module_instance_impl_spawn_has_stopped,
	.init = module_instance_impl_spawn_init,
	.post_create = module_instance_impl_spawn_post_create,
	.stop = module_instance_impl_spawn_stop,
	.start = impl_start,
	.stat = module_instance_impl_spawn_stat,
};
