/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/wait.h>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "health_check.h"
#include "manifest.h"
#include "module_impl_ops.h"
#include "module_instance_impl.h"
#include "module_instance_impl_noop.h"
#include "module_instance_impl_ops.h"
#include "sdk_agent.h"
#include "xlog.h"
#include "xpthread.h"

static struct evp_lock g_spawn_lock = EVP_LOCK_INITIALIZER;
static sem_t g_spawn_sem;
static int (*g_entry_point)(int, char **) EVP_GUARDED_BY(g_spawn_lock);

static int
_start_task(int argc, FAR char **argv)
{
	int (*entryPoint)(int, char **);

	xpthread_mutex_lock(&g_spawn_lock);
	entryPoint = g_entry_point;
	// TODO: Replace assert (programming error)
	assert(entryPoint != NULL);
	g_entry_point = NULL;
	xpthread_mutex_unlock(&g_spawn_lock);

	if (sem_post(&g_spawn_sem)) {
		xlog_error("sem_post(3) failed with %s", strerror(errno));
		return -1;
	}

	clearenv();

	return entryPoint(argc, argv);
}

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *dir, void *handle)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	// TODO: Replace assert (programming error)
	assert(m->pid == -1);
	const char *entryPointName = spec->entryPoint;
	void *entryPoint = dlsym(handle, entryPointName);
	if (entryPoint == NULL) {
		free(m->failureMessage);
		xasprintf(&m->failureMessage,
			  "Module %s has no entry point %s", spec->moduleId,
			  entryPointName);
		return EAGAIN;
	}
	/*
	 * XXX hardcoded priority and stacksize
	 *
	 * REVISIT: These parameters are inherently workload-specific.
	 * There should be a mechanism to specify these
	 * per module or module instance basis in DeploymentManifest.
	 */
	xpthread_mutex_lock(&g_spawn_lock);
	g_entry_point = entryPoint;
	m->pid = task_create(m->name, MODULE_INSTANCE_PRIORITY,
			     CONFIG_DEFAULT_TASK_STACKSIZE, _start_task, NULL);
	if (m->pid == -1) {
		// TODO: Replace assert (programming error)
		assert(errno != 0);
		int ret = errno;
		// TODO: Replace assert (programming error)
		assert(g_entry_point != NULL);
		g_entry_point = NULL;
		xpthread_mutex_unlock(&g_spawn_lock);
		free(m->failureMessage);
		xasprintf(&m->failureMessage, "task_create failed with %d",
			  ret);
		return ret;
	}
	xpthread_mutex_unlock(&g_spawn_lock);
	while (sem_wait(&g_spawn_sem)) {
		if (errno == EINTR)
			continue;
		xlog_error("sem_wait(3) failed with %s", strerror(errno));
		return errno;
	}
	sdk_handle_setpid(m->sdk_handle, m->pid);
	return 0;
}

static int
impl_stop(struct module_instance *m)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	if (m->pid == -1) {
		return 0;
	}
	pid_t ret;
	int status;
	for (;;) {
		ret = waitpid(m->pid, &status, 0);
		if (ret == m->pid &&
		    (WIFEXITED(status) || WIFSIGNALED(status))) {
			break;
		}
		if (ret == (pid_t)-1) {
			if (errno == ECHILD) {
				/*
				 * NuttX doesn't have zombie processes. If the
				 * task has exited before we called waitpid()
				 * above, it ends up with ECHILD.
				 */
				break;
			}
			if (errno == EINTR) {
				continue;
			}
			/* Abort assessment:
			 * This is likely to be due to a signal event which
			 * should cause agent to abort.
			 */
			// TODO: Review exit (xerr) (runtime error)
			//       Prefer xlog_abort[if]
			xerr(1, "waitpid failed");
		}
		if (ret == 0) {
			/* Abort assessment:
			 * Waitpid is not configured with WNOHANG flag.
			 * Therefore returning 0 should not be possible.
			 * It is an assertion and can result in aborting.*/
			// TODO: Review exit (xerr) (runtime error)
			//       Prefer xlog_abort[if]
			xerrx(1, "waitpid returned 0");
		}
	}
	if (sem_destroy(&g_spawn_sem)) {
		xlog_error("sem_destroy(3) failed with %s", strerror(errno));
		return errno;
	}
	return 0;
}

static bool
impl_is_running(struct module_instance *m)
{
	return m->pid != -1;
}

static bool
impl_has_stopped(struct module_instance *m)
{
	return m->stopped;
}

static const char *
impl_stat(struct module_instance *m)
{
	if (m->pid == -1) {
		return NULL;
	}

	/*
	 * the backdoor tasks are not our children.
	 * waitpid doesn't work for them.
	 * REVISIT: maybe we can try using kill().
	 */
	if (m->moduleId == NULL) {
		return "unknown";
	}

	const char *status;
	int health = check_pid_status(m->pid);
	switch (health) {
	case PID_STATUS_RUNNING:
		status = "ok";
		break;

	case PID_STATUS_EXITED_OK:
		m->stopped = true;
		status = "self-exiting";
		/*
		 * "self" in the sense that the termination is likely happening
		 * before any agent or hub-commanded termination
		 */
		break;

	case PID_STATUS_CHECK_BACKOFF:
		status = "status-check-backoff";
		break;
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", health);
	}
	return status;
}

static int
impl_init(void)
{
	if (sem_init(&g_spawn_sem, 0, 0)) {
		xlog_error("sem_init failed with %s", strerror(errno));
		return errno;
	}

	return 0;
}

static void
impl_post_create(struct module_instance *m)
{
}

const struct module_instance_impl_ops module_instance_impl_ops_dlfcn = {
	.name = "dlfcn",
	.convert_path = module_instance_impl_noop_convert_path,
	.is_running = impl_is_running,
	.has_stopped = impl_has_stopped,
	.init = impl_init,
	.post_create = impl_post_create,
	.stop = impl_stop,
	.start = impl_start,
	.stat = impl_stat,
};
