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
#include "xlog.h"

static void
free_env(char **env)
{
	if (env) {
		for (char **e = env; *e; e++) {
			free(*e);
		}
	}

	free(env);
}

static char **
setup_env(const char *socket_path, const char *workspace_path)
{
	extern char **environ;
	char **env = NULL, **e, **a;
	size_t i;

	for (e = environ, i = 0; *e; e++, i++) {
		a = realloc(env, (i + 1) * sizeof *a);

		if (!a) {
			xlog_error("realloc(3): %s\n", strerror(errno));
			goto failure;
		}

		env = a;
		env[i] = strdup(*e);

		if (!env[i]) {
			xlog_error("strdup(3): %s\n", strerror(errno));
			goto failure;
		}
	}

	a = realloc(env, (i + 3) * sizeof *a);
	if (!a) {
		xlog_error("realloc(3): %s\n", strerror(errno));
		goto failure;
	}

	env = a;
	env[i++] = strdup(socket_path);
	env[i++] = strdup(workspace_path);
	env[i++] = NULL;

	return env;

failure:
	free_env(env);
	return NULL;
}

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *module_instance_dir, void *handle)
{
	int ret;
	char *args[] = {"python", handle, NULL};
	char **envp = NULL;

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

	ret = asprintf(&workspace_path,
		       "EVP_MODULE_SDK_DEFAULT_WORKSPACE_PATH=%s/%s/%s",
		       module_instance_path, m->name, DEFAULT_WORKSPACE_DIR);
	if (ret < 0) {
		xlog_error("asprintf(3) failed with: %s", strerror(errno));
		ret = errno;
		goto finish;
	}

	/* Below environment variables need to be shared with modules.
	envp[0 .. n] :
	environ(3)
	envp[n + 1]:
	EVP_MODULE_SDK_SOCKET_PATH=/evp_data/instances/<instance_name>/sdk.sock
	envp[n + 2] :
	EVP_MODULE_SDK_DEFAULT_WORKSPACE_PATH=/evp_data/instances/<instance_name>/default_workspace
	envp[n + 3] : NULL (Must be terminated by a NULL pointer.) */
	envp = setup_env(socket_path, workspace_path);

	ret = posix_spawnp(&m->pid, "python3", NULL, NULL, args, envp);
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
	free_env(envp);
	free(socket_path);
	free(workspace_path);
	return ret;
}

int module_instance_impl_spawn_init(void);
bool module_instance_impl_spawn_is_running(struct module_instance *m);
bool module_instance_impl_spawn_has_stopped(struct module_instance *m);
int module_instance_impl_spawn_stop(struct module_instance *m);
void module_instance_impl_spawn_post_create(struct module_instance *m);
const char *module_instance_impl_spawn_stat(struct module_instance *m);

const struct module_instance_impl_ops module_instance_impl_ops_python = {
	.name = "python",
	.convert_path = module_instance_impl_noop_convert_path,
	.is_running = module_instance_impl_spawn_is_running,
	.has_stopped = module_instance_impl_spawn_has_stopped,
	.init = module_instance_impl_spawn_init,
	.post_create = module_instance_impl_spawn_post_create,
	.stop = module_instance_impl_spawn_stop,
	.start = impl_start,
	.stat = module_instance_impl_spawn_stat,
};
