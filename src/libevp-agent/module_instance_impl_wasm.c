/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Overview:
 *
 * This file contains the logic to execute wasm-based EVP module.
 * (either wasm bytecode or AoT)
 *
 * A module instance is a thread created with pthread_create.
 * The thread uses wasm-micro-runtime (namely wasm_application_execute_main)
 * to execute wasm module.
 *
 * wasm_application_execute_main won't return until the module instance
 * exits.
 *
 * The wasm-micro-runtime library takes care of the module type
 * differences (wasm bytecode and AoT) automatically.
 */

#define _GNU_SOURCE

#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>
#include <wasm_export.h>

#include <internal/util.h>

#include "fsutil.h"
#include "manifest.h"
#include "module_impl.h"
#include "module_impl_ops.h"
#include "module_instance_impl.h"
#include "module_instance_impl_noop.h"
#include "module_instance_impl_ops.h"
#include "module_log_cap.h"
#include "platform.h"
#include "sdk_agent.h"
#include "sdk_impl.h"
#include "timeutil.h"
#include "xlog.h"
#include "xpthread.h"

#if defined(__NuttX__)
#include "nuttx/version.h"
#endif

#define MAX_EXIT_TIME_IN_SECONDS 5

static void
module_instance_set_status(struct module_instance *m,
			   enum module_instance_status status)
{
	xpthread_mutex_lock(&m->lock);
	m->status = status;
	xpthread_mutex_unlock(&m->lock);
	if (status == MODULE_INSTANCE_STATUS_STOPPED && sem_post(&m->sem)) {
		xlog_error("sem_post failed with errno %d", errno);
	}
}

static enum module_instance_status
module_instance_get_status(struct module_instance *m)
{
	enum module_instance_status status;
	xpthread_mutex_lock(&m->lock);
	status = m->status;
	xpthread_mutex_unlock(&m->lock);
	return status;
}

struct wasm_runner {
	wasm_module_inst_t module_inst;
	struct module_instance *m;
};

static void *
wasm_runner(void *vp)
{
	struct wasm_runner *r = vp;
	struct module_instance *m = r->m;
	wasm_module_inst_t module_inst = r->module_inst;

	bool ok = wasm_runtime_init_thread_env();
	if (!ok) {
		xlog_error("wasm_runtime_init_thread_env failed");
	}

	// TODO: Replace assert (programming error)
	assert(module_inst != NULL);
	if (!wasm_application_execute_main(module_inst, 0, NULL)) {
		const char *exc = wasm_runtime_get_exception(module_inst);
		xlog_error("wasm_application_execute_main exception: %s", exc);
		if (exc == NULL) {
			exc = "Unknown WASM exception";
		}

		/* A notification would be already published by
		 * impl_stop otherwise. */
		if (strcmp(exc, "force terminated")) {
			struct evp_agent_notification_wasm_stopped notif = {
				.name = m->name,
				.status = EVP_AGENT_WASM_STOPPED_EXCEPTION};

			if (evp_agent_notification_publish(
				    NULL, "wasm/stopped", &notif)) {
				xlog_error("evp_agent_notification_publish "
					   "failed");
			}
		}

		xpthread_mutex_lock(&m->lock);
		free(m->wasm_runner_exception);
		m->wasm_runner_exception = NULL;
		xasprintf(&m->wasm_runner_exception,
			  "wasm_application_execute_main failed: %s", exc);
		xpthread_mutex_unlock(&m->lock);
	}

	wasm_runtime_destroy_thread_env();
	module_instance_set_status(m, MODULE_INSTANCE_STATUS_STOPPED);
	free(r);
	return NULL;
}

static void
impl_post_create(struct module_instance *m)
{
	xpthread_mutex_init(&m->lock);

	if (sem_init(&m->sem, 0, 0)) {
		xlog_abort("sem_init failed with errno %d", errno);
	}

	module_instance_set_status(m, MODULE_INSTANCE_STATUS_LOADING);

	m->wasm_binary = NULL;
	m->wasm_module_inst = NULL;
}

struct instance_start {
	const char *name;
	int stdout_fd, stderr_fd;
	void *mmap_handle, *stack;
	const void *binary;
	size_t binary_size;
	wasm_module_inst_t inst;
	wasm_module_t module;
	pthread_t wasm_runner;
};

static int
set_print_error(char **error, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vasprintf(error, fmt, ap);

	if (n < 0) {
		xlog_error("vasprintf(3) failed");
		/* vasprintf(3) leaves the contents for error undefined on
		 * failure. Make sure the pointer is always well defined. */
		*error = NULL;
	} else {
		xlog_error("%s", *error);
	}

	va_end(ap);
	return n < 0;
}

static int
mmap_wasm_file(struct instance_start *s, struct module *mi, char **errormsg)
{
	int ret, error;
	const void *bin;
	size_t size;
	void *handle = plat_mod_fs_file_mmap(mi, &bin, &size, true, &error);

	if (handle == NULL || bin == NULL || size == 0) {
		if (error == ENOENT) {
			xlog_debug("Will try again to load '%s'",
				   mi->moduleId);
			ret = EAGAIN;
		} else {
			set_print_error(errormsg, "Load failed: %s: %d",
					mi->moduleId, error);
			ret = error;
		}

		goto end;
	}

	s->mmap_handle = handle;
	s->binary = bin;
	s->binary_size = size;
	ret = 0;

end:
	if (ret != 0 && handle != NULL) {
		error = plat_mod_fs_file_munmap(handle);

		if (error) {
			xlog_error("plat_mod_fs_file_munmap failed");
		}
	}

	return ret;
}

static int
setup_module(struct instance_start *s, char **error)
{
	char error_buf[128];
	/* wasm-micro-runtime is known to modify the buffer pointed to by
	 * s->binary e.g.: when relocations are made. However,
	 * wasm-micro-runtime should eventually not to do this, hence the
	 * temporary explicit cast. */
	wasm_module_t module =
		wasm_runtime_load((uint8_t *)s->binary, s->binary_size,
				  error_buf, sizeof(error_buf));

	if (module == NULL) {
		set_print_error(error, "wasm_runtime_load failed with %s",
				error_buf);
		return -1;
	}

	s->module = module;
	return 0;
}

static int
setup_fds(struct instance_start *s, const char **workspace, char **error)
{
	int ret, stdout_fd = module_log_cap_open(s->name, "stdout"),
		 stderr_fd = module_log_cap_open(s->name, "stderr");

	if (stdout_fd < 0) {
		ret = errno;
		set_print_error(error, "module_log_cap_open stdout failed: %d",
				errno);
		goto failure;
	}

	if (stderr_fd < 0) {
		ret = errno;
		set_print_error(error, "module_log_cap_open stderr failed: %d",
				errno);
		goto failure;
	}

	/*
	 * Note: wasi args seems to be used only in
	 * wasm_runtime_instantiate. A weird API.
	 */
	wasm_runtime_set_wasi_args_ex(s->module,
#if defined(__NuttX__) &&                                                     \
	!(CONFIG_VERSION_MAJOR >= 12 && CONFIG_VERSION_MINOR >= 1)
				      /*
				       * NuttX may not have
				       * O_DIRECTORY and openat family
				       */
				      NULL, 0,
#else
				      workspace, 1,
#endif
				      NULL, 0, NULL, 0, NULL, 0, -1, stdout_fd,
				      stderr_fd);

	s->stdout_fd = stdout_fd;
	s->stderr_fd = stderr_fd;
	return 0;

failure:
	if (stdout_fd >= 0) {
		module_log_cap_close(s->name, "stdout");
	}

	if (stderr_fd >= 0) {
		module_log_cap_close(s->name, "stderr");
	}

	return ret;
}

static int
instantiate(struct instance_start *s, char **error)
{
	/* REVISIT: These parameters are inherently workload-specific.
	 * There should be a mechanism to specify these
	 * per module or module instance basis in DeploymentManifest.
	 */
	uint32_t stack_size = CONFIG_EVP_MODULE_IMPL_WASM_DEFAULT_STACKSIZE;
	uint32_t heap_size = CONFIG_EVP_MODULE_IMPL_WASM_DEFAULT_HEAPSIZE;
	char error_buf[128];
	wasm_module_inst_t inst =
		wasm_runtime_instantiate(s->module, stack_size, heap_size,
					 error_buf, sizeof(error_buf));

	if (inst == NULL) {
		set_print_error(error, "wasm_runtime_instantiate failed: %s",
				error_buf);
		return -1;
	}

	s->inst = inst;
	return 0;
}

static int
setup_thread(struct instance_start *s, struct module_instance *m,
	     wasm_module_inst_t inst, char **error)
{
	/* REVISIT: This parameter is inherently workload-specific.
	 * There should be a mechanism to specify this
	 * per module or module instance basis in DeploymentManifest.
	 */
	size_t stack_size = CONFIG_EVP_MODULE_IMPL_WASM_DEFAULT_HOST_STACKSIZE;
	int ret;
	pthread_t thread;
	void *stack = NULL;
	struct wasm_runner *args = NULL;

	if (stack_size != 0) {
		stack = plat_wasm_stack_mem_alloc(stack_size);
		if (!stack) {
			ret = ENOMEM;
			set_print_error(error,
					"plat_wasm_stack_mem_alloc failed");
			goto end;
		}
	}

	args = malloc(sizeof(*args));

	if (args == NULL) {
		set_print_error(error, "malloc(3) failed: %d", errno);
		ret = errno;
		goto end;
	}

	*args = (struct wasm_runner){.m = m, .module_inst = inst};

	/* This data is required before the thread starts. */
	module_instance_set_status(m, MODULE_INSTANCE_STATUS_STARTING);
	wasm_runtime_set_custom_data(inst, m->sdk_handle);

	module_instance_set_status(m, MODULE_INSTANCE_STATUS_RUNNING);
	ret = xpthread_create_with_stack(&thread, wasm_runner, args,
					 MODULE_INSTANCE_PRIORITY, stack,
					 stack_size);

	if (ret != 0) {
		set_print_error(error, "pthread_create failed with %d", ret);
		goto end;
	}

	/* Exceptionally, do not treat this as a fatal error. Otherwise, the
	 * thread created above would have to be cancelled and joined
	 * (a difficult process), with little benefit. */
	int result = pthread_setname_np(thread, "wasm_runner");

	if (result != 0) {
		xlog_warning("pthread_setname_np failed with %d", result);
	}

	s->wasm_runner = thread;
	s->stack = stack;
	ret = 0;

end:
	if (ret != 0) {
		free(args);
		plat_wasm_stack_mem_free(stack);
	}

	return ret;
}

static int
free_instance(struct instance_start *s)
{
	int ret = 0;

	if (s->inst != NULL) {
		wasm_runtime_deinstantiate(s->inst);
	}

	if (s->mmap_handle != NULL) {
		int error = plat_mod_fs_file_munmap(s->mmap_handle);

		if (error != 0) {
			xlog_error("plat_mod_fs_file_munmap failed with %d",
				   error);
			ret = error;
		}
	}

	if (s->stdout_fd >= 0) {
		module_log_cap_close(s->name, "stdout");
	}

	if (s->stderr_fd >= 0) {
		module_log_cap_close(s->name, "stderr");
	}

	plat_wasm_stack_mem_free(s->stack);
	return ret;
}

static int
ensure_instance(struct instance_start *s, struct module *mi,
		struct module_instance *m, const char **workspace,
		char **error)
{
	if (!mi->ops->loaded(mi)) {
		return EAGAIN;
	}

	int ret = mmap_wasm_file(s, mi, error);

	if (ret) {
		xlog_error("mmap_wasm_file failed with %d", ret);
		return ret;
	}

	ret = setup_module(s, error);

	if (ret) {
		xlog_error("setup_module failed");
		return ret;
	}

	ret = setup_fds(s, workspace, error);

	if (ret) {
		xlog_error("setup_fds failed with %d", ret);
		return ret;
	}

	ret = instantiate(s, error);

	if (ret) {
		xlog_error("instantiate failed");
		return ret;
	}

	ret = setup_thread(s, m, s->inst, error);

	if (ret) {
		xlog_error("setup_thread failed with %d", ret);
		return ret;
	}
	module_instance_set_status(m, MODULE_INSTANCE_STATUS_RUNNING);

	return ret;
}

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *dir, void *handle)
{
	int ret = EINVAL;
	struct instance_start s = {
		.name = m->name, .stdout_fd = -1, .stderr_fd = -1};
	char *error = NULL;

	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	// TODO: Replace assert (programming error)
	assert(handle != NULL);

	/* REVISIT: entryPoint */

	if (module_instance_get_status(m) != MODULE_INSTANCE_STATUS_LOADING) {
		ret = 0;
		goto end;
	}

	if (m->wasm_module_inst == NULL) {
		const char **workspace =
			(const char **)&m->sdk_handle->workspace;

		ret = ensure_instance(&s, handle, m, workspace, &error);

		if (ret != 0) {
			xlog_error("ensure_instance failed with %d", ret);
			goto end;
		}

		m->wasm_module = s.module;
		m->wasm_module_inst = s.inst;
		m->wasm_module_mmap_handle = s.mmap_handle;
		m->wasm_binary = s.binary;
		m->wasm_runner = s.wasm_runner;
		m->stack = s.stack;
	}

	return 0;

end:
	if (ret != 0) {
		int free_result = free_instance(&s);

		if (free_result != 0) {
			xlog_error("free_instance failed with %d",
				   free_result);
		}

		if (error != NULL) {
			free(m->failureMessage);
			m->failureMessage = error;
		}
	}

	return ret;
}

static int
impl_stop(struct module_instance *m)
{
	// TODO: Replace assert (programming error)
	assert(m->failureMessage == NULL);
	int ret = 0;
	if (module_instance_get_status(m) == MODULE_INSTANCE_STATUS_RUNNING) {
		// wait for WASM module to exit
		struct timespec max_wait = {0, 0};
		enum wasm_stopped_status status =
			EVP_AGENT_WASM_STOPPED_GRACEFULLY;
		getrealtime(&max_wait);
		max_wait.tv_sec += MAX_EXIT_TIME_IN_SECONDS;
		while (sem_timedwait(&m->sem, &max_wait)) {
			if (errno == ETIMEDOUT) {
				xlog_warning("Terminating Wasm instance %s",
					     m->name);
				wasm_runtime_terminate(m->wasm_module_inst);
				status = EVP_AGENT_WASM_STOPPED_CANCELLED;
				break;
			} else if (errno != EINTR) {
				ret = errno;
				xlog_warning("sem_timedwait error %d", ret);
				return ret;
			}
		}

		ret = pthread_join(m->wasm_runner, NULL);
		if (ret != 0) {
			xlog_error("pthread_join failed: %d", ret);
		}

		struct evp_agent_notification_wasm_stopped notif = {
			.name = m->name, .status = status};

		if (evp_agent_notification_publish(NULL, "wasm/stopped",
						   &notif)) {
			xlog_error("evp_agent_notification_publish failed");
		}

		module_instance_set_status(m, MODULE_INSTANCE_STATUS_STOPPED);
		xpthread_mutex_destroy(&m->lock);
		if (sem_destroy(&m->sem)) {
			xlog_abort("sem_destroy failed with errno %d", errno);
		}
	}
	if (m->wasm_module_inst != NULL) {
		/*
		 * REVISIT: what happens if the module instance
		 * created threads inside?
		 */
		wasm_runtime_set_custom_data(m->wasm_module_inst, NULL);
		wasm_runtime_deinstantiate(m->wasm_module_inst);
		m->wasm_module_inst = NULL;
	}

	if (m->wasm_module != NULL) {
		wasm_runtime_unload(m->wasm_module);
		m->wasm_module = NULL;
	}
	if (m->wasm_binary != NULL) {
		plat_mod_fs_file_munmap(m->wasm_module_mmap_handle);
		m->wasm_binary = NULL;
	}

	module_log_cap_close(m->name, "stdout");
	module_log_cap_close(m->name, "stderr");
	plat_wasm_stack_mem_free(m->stack);
	free(m->wasm_runner_exception);
	return ret;
}

static bool
impl_is_running(struct module_instance *m)
{
	enum module_instance_status status = module_instance_get_status(m);
	return status == MODULE_INSTANCE_STATUS_RUNNING;
}

static bool
impl_has_stopped(struct module_instance *m)
{
	enum module_instance_status status = module_instance_get_status(m);
	return status == MODULE_INSTANCE_STATUS_STOPPED;
}

static const char *
impl_stat(struct module_instance *m)
{
	const char *stat;
	enum module_instance_status status = module_instance_get_status(m);

	xpthread_mutex_lock(&m->lock);
	if (m->wasm_runner_exception) {
		free(m->failureMessage);
		m->failureMessage = strdup(m->wasm_runner_exception);
	}
	xpthread_mutex_unlock(&m->lock);

	switch (status) {
	case MODULE_INSTANCE_STATUS_RUNNING:
		{
			/*
			 * Note: musl pthread_kill returns 0 for exited
			 * threads.
			 */
			int ret = pthread_kill(m->wasm_runner, 0);
			switch (ret) {
			case 0:
				stat = "ok";
				break;
			case ESRCH:
				stat = "self-exiting";
				break;
			default:
				stat = "unknown";
				break;
			}

			xlog_debug("pthread_kill returned %d, errno=%d", ret,
				   errno);
		}
		break;
	case MODULE_INSTANCE_STATUS_STOPPED:
		stat = "self-exiting";
		break;
	case MODULE_INSTANCE_STATUS_STARTING:
	case MODULE_INSTANCE_STATUS_LOADING:
	default:
		stat = NULL;
		break;
	}
	return stat;
}

static int
impl_init(void)
{
	return 0;
}

const struct module_instance_impl_ops module_instance_impl_ops_wasm = {
	.name = "wasm",
	.convert_path = module_instance_impl_noop_convert_path,
	.is_running = impl_is_running,
	.has_stopped = impl_has_stopped,
	.start = impl_start,
	.post_create = impl_post_create,
	.stop = impl_stop,
	.stat = impl_stat,
	.init = impl_init,
};
