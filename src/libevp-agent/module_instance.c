/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <config.h>

#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "backdoor.h"
#include "cdefs.h"
#include "fsutil.h"
#include "global.h"
#include "manifest.h"
#if defined(CONFIG_EVP_SDK_SOCKET)
#include "local_socket.h"
#endif
#include "map.h"
#include "module.h"
#include "module_impl_ops.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "module_instance_impl_ops.h"
#include "path.h"
#include "reconcile.h"
#include "sdk_agent.h"
#include "sdk_impl.h"
#include "sdk_msg.h"
#include "xlog.h"
#include "xpthread.h"

/*
 * XXX todo: should we provide something like r_debug/link_map?
 */

struct _gc_ctx {
	const struct InstanceSpecs *list;
	int error;
};

struct name {
	const char *name;
	size_t len;
};

static struct map *instances;

static int
module_instance_compare_name(const void *key, const void *value)
{
	const struct name *name = key;
	const struct module_instance_comparable *m = value;

	return strlen(m->name) != name->len ||
	       strncmp(m->name, name->name, name->len);
}

static int
module_instance_compare_entrypoint(const void *key, const void *value)
{
	const char *name = key;
	const struct module_instance *m = value;
	return !m->entryPoint || strcmp(m->entryPoint, name);
}

/*
 * Returns 0 if the instances makes reference to the same.
 * It checks instanceSpec against the current module instance.
 * Otherwise returns any value !0.
 */
static int
module_instance_compare(const void *key, const void *value)
{
	const struct ModuleInstanceSpec *spec = key;
	const struct module_instance_comparable *m = value;
	// TODO: Replace assert (programming error)
	assert(m != NULL && m->name != NULL);
	// TODO: Replace assert (programming error)
	assert(spec != NULL && spec->name != NULL);

	if (spec->moduleId == NULL) {
		return strcmp(m->name, spec->name) || m->moduleId != NULL ||
		       m->version != spec->version;
	} else {
		return strcmp(m->name, spec->name) || m->moduleId == NULL ||
		       strcmp(m->moduleId, spec->moduleId) ||
		       m->version != spec->version;
	}
}

static void
module_instance_free_aliases(sdk_msg_topic_alias_queue *dst)
{
	struct sdk_msg_topic_alias *alias;

	while ((alias = TAILQ_FIRST(dst)) != NULL) {
		TAILQ_REMOVE(dst, alias, q);
		/*
		 * The following unnatural assertion was added to suppress
		 * a clang ananlyzer warning.
		 * "warning: Use of memory after it is freed [unix.Malloc]"
		 */
		// TODO: Replace assert (programming error)
		assert(alias != TAILQ_FIRST(dst));
		free(__UNCONST(alias->name));
		free(__UNCONST(alias->topic));
		free(alias);
	}
}

static void
module_instance_free_streams(struct StreamList *streams)
{
	if (!streams)
		return;

	for (size_t i = 0; i < streams->n; i++)
		stream_free(&streams->streams[i]);

	free(streams);
}

static bool
module_instance_is_backdoor(const struct module_instance *m)
{
	bool is_backdoor = m->moduleId == NULL;
	return is_backdoor;
}

static bool
module_instance_is_persistent(const struct module_instance *m)
{
	return (m->flags & MODULE_INSTANCE_PERSISTENT) ||
	       module_instance_is_backdoor(m);
}

static bool
module_instance_spec_is_backdoor(const struct ModuleInstanceSpec *spec)
{
	bool is_backdoor = spec->moduleId == NULL;
	return is_backdoor;
}

static int
module_instance_gc(const void *key, const void *value)
{
	struct _gc_ctx *ctx = __UNCONST(key);
	const struct InstanceSpecs *list = ctx->list;
	struct module_instance *m = __UNCONST(value);

	unsigned int i;
	for (i = 0; i < list->n; i++) {
		struct ModuleInstanceSpec *spec =
			__UNCONST(&list->instances[i]);

		if (is_backdoor_prefixed(spec->entryPoint) &&
		    !strcmp(m->name, spec->entryPoint)) {
			return 1;
		}

		if (!module_instance_compare(spec, m)) {
			return 1;
		}
	}

	// m->name is being freed in module_instance_stop1 so it needs to be
	// duplicated.
	char *name = xstrdup(m->name);
	int error = 0;
	int ret = module_instance_stop1(m);
	if (ret != EAGAIN && ret != EBUSY) {
		// Clean state must be done once instance has been stopped to
		// avoid race condition
		clean_instance_state(name);
		error = ret;
	} else {
		ret = EAGAIN;
	}

	// Overrite group error on unexpected errors
	if (error) {
		ctx->error = error;
	}

	// Write first occuring busy state error if no group error reported
	if (ret && !ctx->error) {
		ctx->error = ret;
	}

	free(name);
	return 1;
}

static int
module_instance_revert_backdoor(struct module_instance *m)
{
	if (is_backdoor_prefixed(m->entryPoint)) {
		xlog_info("REVERT MODULE INSTANCE %s to %s", m->name,
			  m->entryPoint);

		// turn persistent instance back into backdoor instance
		// update instance names in persisted instance states
		rename_instance_states(m->name, m->entryPoint);
		// reset name to entryPoint
		free(__UNCONST(m->name));
		m->name = xstrdup(m->entryPoint);
		free(__UNCONST(m->entryPoint));
		m->entryPoint = NULL;
		// NULL moduleId indicates backdoor instance
		free(__UNCONST(m->moduleId));
		m->moduleId = NULL;

		// TODO: Replace assert (programming error)
		assert(m->sdk_handle != NULL);
		sdk_handle_rename(m->sdk_handle, m->name);
	}
	return 0;
}

int
module_instance_stop1(struct module_instance *m)
{
	if (module_instance_is_persistent(m)) {
		return module_instance_revert_backdoor(m);
	}

	/* stop this */
	struct ModuleInstanceSpec spec = {
		.name = __UNCONST(m->name),
		.version = m->version,
		.moduleId = __UNCONST(m->moduleId),
	};
	xlog_info("STOP MODULE INSTANCE %s version %" PRIu32 " module %s",
		  m->name, m->version,
		  m->moduleId ? m->moduleId : "<no module>");
	free(m->failureMessage);
	m->failureMessage = NULL;
	sdk_signal_exit(m->sdk_handle);
	if (!module_instance_is_persistent(m) && m->ops != NULL &&
	    m->ops->instance != NULL) {
		int ret = m->ops->instance->stop(m);
		if (ret != 0) {
			xlog_warning("instance->stop failed "
				     "with %d",
				     ret);
			return ret;
		}
	}

#if defined(CONFIG_EVP_SDK_SOCKET)
	if (m->sdk_socket_worker_ctx.listen_fd != -1) {
		close(m->sdk_socket_worker_ctx.listen_fd);
		m->sdk_socket_worker_ctx.listen_fd = -1;
	}
	if (m->thread_created) {
		/* XXX i don't like pthread_cancel */
		int ret = pthread_cancel(m->sdk_socket_worker);
		if (ret != 0) {
			// TODO: Review exit (xerr) (system error)
			//       Prefer xlog_abort[if]
			xerr(1, "pthread_cancel");
		}
		ret = pthread_join(m->sdk_socket_worker, NULL);
		if (ret != 0) {
			// TODO: Review exit (xerr) (system error)
			//       Prefer xlog_abort[if]
			xerr(1, "pthread_join");
		}
		m->thread_created = false;
	}
#endif
	if (m->failureMessage != NULL) {
		xlog_warning("m->failureMessage is %s", m->failureMessage);
	}
	struct module_instance *n = map_put(instances, &spec, NULL);
	xlog_abortif(n != m, "mismatch mod instances found (%p != %p)", n, m);
	sdk_cleanup(m->sdk_handle);
	/* XXX for now */
	if (!module_instance_is_persistent(m)) {
		module_instance_free_aliases(&m->publish_topic_aliases);
		module_instance_free_aliases(&m->subscribe_topic_aliases);
	}
	module_instance_free_streams(m->streams);

	free(__UNCONST(m->name));
	free(__UNCONST(m->entryPoint));
	free(__UNCONST(m->moduleId));
	free(m);
	return 0;
}

static const char *
module_instance_dir(const char *name)
{
	const char *instance_dir = path_get(MODULE_INSTANCE_PATH_ID);
	static char path[PATH_MAX];
	int ret;
	ret = snprintf(path, sizeof(path), "%s/%s", instance_dir, name);
	if (ret <= 0 || (unsigned)ret >= sizeof(path))
		// TODO: Review exit (xlog_abort)
		//       other modules can work and we should only notify hub
		xlog_abort("path exceeds PATH_MAX");
	return path;
}

static void
init_module_instance_dir(void)
{
	const char *instance_dir = path_get(MODULE_INSTANCE_PATH_ID);
	int ret = mkdir(instance_dir, 0700);
	if (ret != 0 && errno != EEXIST)
		// TODO: Review exit (xerr)
		//       other modules can work and we should only notify hub
		xerr(1, "Failed to create MODULE_INSTANCE_DIR %s",
		     instance_dir);
}

static void
sdk_set_topic_aliases(struct TopicAliasList *src, // todo: miguel: change name
		      sdk_msg_topic_alias_queue *dst)
{
	struct sdk_msg_topic_alias *alias;
	int pt;

	// TODO: Replace assert (programming error)
	assert(TAILQ_EMPTY(dst));

	for (pt = (int)src->n - 1; pt >= 0; pt--) {
		alias = xmalloc(sizeof(struct sdk_msg_topic_alias));
		alias->name = xstrdup(src->aliases[pt].alias);
		alias->topic = xstrdup(src->aliases[pt].topic);
		TAILQ_INSERT_TAIL(dst, alias, q);
	}
}

int
module_instance_init(void)
{
	instances = map_init(16, module_instance_compare, NULL);
	init_module_instance_dir();

	g_evp_global.instance_states = json_value_init_object();
	return module_instance_impl_ops_init_all();
}

static int
module_instance_stop_each(const void *key, const void *value)
{
	struct module_instance *m = __UNCONST(value);
	if (m == NULL) {
		return 1;
	}
	// stop all modules, including persistent ones
	if (module_instance_is_persistent(m)) {
		// mark as non-persistent, non-backdoor
		m->flags &= ~(MODULE_INSTANCE_PERSISTENT);
		free(__UNCONST(m->moduleId));
		m->moduleId = xstrdup("backdoor");
	}
	module_instance_stop1(m);
	return 1;
}

void
module_instance_deinit(void)
{
	map_foreach(instances, module_instance_stop_each, NULL);
	map_free(instances);
	instances = NULL;
	json_value_free(g_evp_global.instance_states);
	g_evp_global.instance_states = NULL;
}

int
module_instance_stop(const struct InstanceSpecs *list)
{
	struct _gc_ctx ctx = {.list = list};
	map_foreach(instances, module_instance_gc, &ctx);
	return ctx.error;
}

const struct Stream *
module_instance_stream_from_name(const struct module_instance *m,
				 const char *name)
{
	if (m->streams == NULL) {
		return NULL;
	}

	for (size_t i = 0; i < m->streams->n; i++) {
		const struct Stream *s = &m->streams->streams[i];

		if (!strcmp(s->name, name)) {
			return s;
		}
	}

	return NULL;
}

static int
set_streams(const struct StreamList *src, struct StreamList **dst)
{
	int ret = 0;
	struct StreamList *list =
		malloc(src->n * (sizeof(*list) + sizeof(*list->streams)));
	if (list == NULL) {
		xlog_error("malloc(3) failed with errno %d", errno);
		ret = errno;
		goto end;
	}
	for (size_t i = 0; i < src->n; i++) {
		ret = stream_duplicate(&src->streams[i], &list->streams[i]);
		if (ret != 0) {
			goto end;
		}
	}
	list->n = src->n;
	*dst = list;
end:
	if (ret != 0) {
		free(list);
	}
	return ret;
}

static void
module_instance_rename_backdoor(const struct ModuleInstanceSpec *spec,
				struct module_instance *m)
{
	xlog_info("RENAME MODULE INSTANCE %s to %s", m->name, spec->name);

	// update instance names in persisted instance states
	rename_instance_states(m->name, spec->name);

	// update instance metadata
	free(__UNCONST(m->name));
	free(__UNCONST(m->entryPoint));
	free(__UNCONST(m->moduleId));
	m->name = xstrdup(spec->name);
	m->moduleId = xstrdup(spec->moduleId);
	m->entryPoint = xstrdup(spec->entryPoint);
	m->version = spec->version;
	m->flags |= MODULE_INSTANCE_PERSISTENT;
	// TODO: Replace assert (programming error)
	assert(m->sdk_handle != NULL);
	sdk_handle_rename(m->sdk_handle, m->name);

	// initialise pubsub aliases: these are not initialised when the
	// backdoor instance is first created
	TAILQ_INIT(&m->publish_topic_aliases);
	sdk_set_topic_aliases(spec->publish, &m->publish_topic_aliases);
	TAILQ_INIT(&m->subscribe_topic_aliases);
	sdk_set_topic_aliases(spec->subscribe, &m->subscribe_topic_aliases);

	sdk_lock();
	g_resend_request = true;
	sdk_unlock();
}

int
module_instance_create1(const struct ModuleInstanceSpec *spec,
			struct module_instance **mp)
{
	int ret = 0;
	struct module_instance *m = map_get(instances, spec);
	if (m != NULL) {
		*mp = m;
		ret = EEXIST;
		goto done;
	}
	if (is_backdoor_prefixed(spec->entryPoint)) {
		// Transfer this module instance spec to a running
		// backdoor instance. After this, the instance will no
		// longer be recognised as a backdoor but as a
		// persistent instance.
		m = get_module_instance_by_name(spec->entryPoint);
		if (m == NULL) {
			xlog_info("Backdoor instance not found: %s.",
				  spec->entryPoint);
			return EAGAIN;
		}
		module_instance_rename_backdoor(spec, m);
		*mp = m;
		ret = EEXIST;
		goto done;
	}
	m = xcalloc(1, sizeof(*m));
	if (spec->streams != NULL) {
		int error = set_streams(spec->streams, &m->streams);
		if (error != 0) {
			free(m);
			return error;
		}
	}
	/* set key fields */
	m->name = xstrdup(spec->name);
	if (spec->entryPoint) {
		m->entryPoint = xstrdup(spec->entryPoint);
	}
	if (!module_instance_spec_is_backdoor(spec)) {
		m->moduleId = xstrdup(spec->moduleId);
		m->version = spec->version;
	}
	/* set value fields */
	m->sdk_handle = sdk_handle_alloc();
	sdk_handle_init(m->sdk_handle, m->name);
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                                  \
	defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||                              \
	defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	m->pid = -1;
#endif
#if defined(CONFIG_EVP_SDK_SOCKET)
	m->sdk_socket_worker_ctx.listen_fd = -1;
	m->thread_created = false;
#endif
	/* XXX for now */
	if (!module_instance_spec_is_backdoor(spec)) {
		TAILQ_INIT(&m->publish_topic_aliases);
		sdk_set_topic_aliases(spec->publish,
				      &m->publish_topic_aliases);
		TAILQ_INIT(&m->subscribe_topic_aliases);
		sdk_set_topic_aliases(spec->subscribe,
				      &m->subscribe_topic_aliases);
	}
	/* Endow instance with its intended ops*/
	if (module_instance_spec_is_backdoor(spec)) {
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN)
		m->ops = module_impl_ops_get_by_name("dlfcn");
#elif defined(CONFIG_EVP_MODULE_IMPL_WASM)
		m->ops = module_impl_ops_get_by_name("wasm");
#elif defined(CONFIG_EVP_MODULE_IMPL_SPAWN)
		/* Even though SDK backdoor is only supported on NuttX,
		 * and NuttX does not support "spawn", we provide a
		 * module_impl_ops here so that we can run unit tests on
		 * backdoor functionality. */
		m->ops = module_impl_ops_get_by_name("spawn");
#elif defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
		m->ops = module_impl_ops_get_by_name("python");
#endif
	} else {
		m->ops = module_ops(spec->moduleId);
	}
	/* Final steps */
	map_put(instances, spec, m);
	sdk_handle_insert(m->sdk_handle);
done:
	xlog_abortif(m->ops == NULL, "ops vtable not set");
	*mp = m;
	return ret;
}

int
module_instance_create(const struct InstanceSpecs *list)
{
	unsigned int i;
	int result = 0;
	for (i = 0; i < list->n; i++) {
		const struct ModuleInstanceSpec *spec = &list->instances[i];
		struct module_instance *m;
		int ret = module_instance_create1(spec, &m);
		if (ret != 0 && ret != EEXIST) {
			result = ret;
			break;
		}
	}
	return result;
}

int
module_instance_start1(const struct ModuleInstanceSpec *spec,
		       struct module_instance **mp)
{
	struct module_instance *m;
	int ret = module_instance_create1(spec, &m);
	if (ret == EEXIST) {
		*mp = m;
		if (module_instance_spec_is_backdoor(spec)) {
			return EEXIST;
		}
		if (module_instance_is_persistent(m)) {
			return 0;
		}
		if (m->ops != NULL && m->ops->instance != NULL &&
		    (m->ops->instance->is_running(m) ||
		     m->ops->instance->has_stopped(m))) {
			return 0;
		}
	} else if (ret != 0) {
		return ret;
	} else {
		if (m->ops->instance != NULL) {
			m->ops->instance->post_create(m);
		}
	}
	*mp = m;
	/* Handle pending pre-validation failure messages */
	if (spec->failureMessage != NULL) {
		free(m->failureMessage);
		m->failureMessage = xstrdup(spec->failureMessage);
		return EINVAL;
	}

	/* start module instance */
	xlog_info("START MODULE INSTANCE %s version %" PRIu32 " module %s",
		  m->name, m->version,
		  m->moduleId ? m->moduleId : "<no module>");
	free(m->failureMessage);
	m->failureMessage = NULL;
	void *handle;
	if (module_instance_spec_is_backdoor(spec)) {
		handle = NULL;
	} else {
		handle = module_handle(spec->moduleId);
		if (handle == NULL) {
			/*
			 * This shouldn't happen unless the Hub gave us
			 * a broken DeploymentManifest.
			 */
			xasprintf(&m->failureMessage, "Module %s is not ready",
				  spec->moduleId);
			return EAGAIN;
		}
#if defined(__NuttX__)
		/* CONFIG_NAME_MAX is the max file name length.
		 * The moduleId field is used as a direcroty name. ModuleId is
		 * a UUID defined by the hub, and its length is 36. So it has
		 * to be at least 36.
		 */
#if CONFIG_NAME_MAX < 36
#error CONFIG_NAME_MAX value is invalid. The minimum value is 36.
#endif
		if (strlen(m->name) > CONFIG_NAME_MAX) {
			/*
			 * Cancel instantiate if the module instance name is
			 * longer than CONFIG_NAME_MAX because NuttX cannot
			 * treat directory which has name longer than
			 * CONFIG_NAME_MAX correctly.
			 */
			xasprintf(&m->failureMessage,
				  "Instance Name %s is too long", m->name);
			return ENAMETOOLONG;
		}
#endif
	}
	/* Ensure the workspace directory exists */
	const char *path = module_instance_dir(m->name);
	ret = mkdir(path, 0700);
	if (ret != 0 && errno != EEXIST) {
		xlog_error("mkdir %s error %d", path, errno);
		return -1;
	}
	xlog_debug("Ensuring instance dir %s", path);
	char workspace_path[PATH_MAX];
	ret = snprintf(workspace_path, sizeof(workspace_path), "%s/%s", path,
		       DEFAULT_WORKSPACE_DIR);
	if (ret <= 0 || (unsigned)ret >= sizeof(workspace_path)) {
		xlog_error("path exceeds PATH_MAX");
		return -1;
	}
	/*
	 * Note: The workspace directory is accessed by
	 * the corresponding module instance.
	 * 0700 might be too tight for some configurations
	 * especially with "docker" module impl.
	 */
	ret = mkdir(workspace_path, 0700);
	if (ret != 0 && errno != EEXIST) {
		xlog_error("mkdir %s error %d", workspace_path, errno);
		return -1;
	}
#if defined(CONFIG_EVP_SDK_SOCKET) // TODO this should not happen for WASM
	char sock_path[PATH_MAX];
	ret = snprintf(sock_path, sizeof(sock_path), "%s/%s", path,
		       SDK_SOCKET_NAME);
	if (ret <= 0 || (unsigned)ret >= sizeof(sock_path))
		// TODO: Review exit (xlog_abort)
		//       other modules can work and we should only notify hub
		xlog_abort("path exceeds PATH_MAX");

	/* Only creates the socket the first time */
	if (m->sdk_socket_worker_ctx.listen_fd == -1 &&
	    !module_instance_spec_is_backdoor(spec) &&
	    (m->ops == module_impl_ops_get_by_name("spawn") ||
	     m->ops == module_impl_ops_get_by_name("python") ||
	     m->ops == module_impl_ops_get_by_name("docker"))) {
		ret = local_listen_on(sock_path,
				      &m->sdk_socket_worker_ctx.listen_fd);
		if (ret != 0) {
			xasprintf(&m->failureMessage,
				  "Failed to create SDK socket, path=%s, "
				  "error=%d",
				  sock_path, ret);
			xlog_error("%s", m->failureMessage);
			return EAGAIN;
		}
	}

	// TODO: Replace assert (programming error)
	assert(m->sdk_handle != NULL);
	m->sdk_socket_worker_ctx.sdk_handle = m->sdk_handle;

	/* Check thread already created */
	if (!m->thread_created && !module_instance_spec_is_backdoor(spec) &&
	    (m->ops == module_impl_ops_get_by_name("spawn") ||
	     m->ops == module_impl_ops_get_by_name("python") ||
	     m->ops == module_impl_ops_get_by_name("docker"))) {
		ret = xpthread_create(&m->sdk_socket_worker, sdk_socket_thread,
				      &m->sdk_socket_worker_ctx,
				      MODULE_INSTANCE_PRIORITY, 0);
		if (ret != 0) {
			close(m->sdk_socket_worker_ctx.listen_fd);
			m->sdk_socket_worker_ctx.listen_fd = -1;
			return EAGAIN;
		}
		pthread_setname_np(m->sdk_socket_worker, "sdk_socket_worker");
		m->thread_created = true;
	}
#endif /* defined(CONFIG_EVP_SDK_SOCKET) */
	if (module_instance_spec_is_backdoor(spec)) {
		// TODO: Replace assert (programming error)
		assert(handle == NULL);
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN)
		m->pid = getpid();
		xlog_abortif(m->pid == -1, "Invalid process ID");
		sdk_handle_setpid(m->sdk_handle, m->pid);
#endif
	} else {
		ret = m->ops->instance->start(m, spec, path, handle);
		if (ret != 0) {
			xlog_warning(
				"ops->module_instance_start failed with %d",
				ret);
			return EAGAIN;
		}
	}
	free(m->failureMessage);
	m->failureMessage = NULL;
	return 0;
}

static int
try_start_instance(const JSON_Value *deployment,
		   const struct evp_hub_context *hub,
		   const struct ModuleInstanceSpec *spec)
{
	bool backdoor;
	const char *name = spec->name;

	if (hub->check_backdoor(deployment, name, &backdoor)) {
		xlog_error("check_backdoor failed");
		return EAGAIN;
	}

	if (backdoor) {
		return module_instance_start1(spec,
					      &(struct module_instance *){0});
	}

	const char *moduleId = spec->moduleId;

	if (moduleId == NULL) {
		xlog_error("unexpected null moduleId for instance %s", name);
		return EAGAIN;
	}

	const struct module *m = module_get(moduleId);

	if (m == NULL) {
		xlog_error("module_get failed for instance %s", name);
		return EAGAIN;
	}

	const struct module_impl_ops *ops = module_ops(moduleId);

	if (ops == NULL) {
		xlog_error("module_ops failed for instance %s", name);
		return EAGAIN;
	}

	if (!ops->loaded(m))
		return EAGAIN;

	return module_instance_start1(spec, &(struct module_instance *){0});
}

int
module_instance_start(const JSON_Value *deployment,
		      const struct evp_hub_context *hub,
		      const struct InstanceSpecs *list)
{
	int ret = 0;

	if (!list->n) {
		return ret;
	}

	for (size_t i = 0; i < list->n; i++) {
		const struct ModuleInstanceSpec *spec = &list->instances[i];
		int result = try_start_instance(deployment, hub, spec);

		if (result != 0) {
			if (result != EAGAIN || !ret) {
				ret = result;
			}
		}
	}

	return ret;
}

static JSON_Object *
module_instance_fill_json_common(JSON_Object *o,
				 const struct module_instance *m)
{
	JSON_Value *mv = json_value_init_object();
	JSON_Object *mo = json_value_get_object(mv);

	const char *status;
	if (m->failureMessage != NULL) {
		status = "error";
		json_object_set_string(mo, "failureMessage",
				       m->failureMessage);
	} else if ((status = m->ops->instance->stat(__UNCONST(m))) == NULL) {
		status = "unknown";
	}
	json_object_set_string(mo, "status", status);

	json_object_set_value(o, m->name, mv);
	return mo;
}

static int
module_instance_fill_json_evp1(const void *key, const void *value)
{
	JSON_Object *o = (void *)key; /* discard const */
	const struct module_instance *m = value;
	module_instance_fill_json_common(o, m);
	return 1; /* continue */
}

static int
module_instance_fill_json_evp2(const void *key, const void *value)
{
	JSON_Object *o = (void *)key; /* discard const */
	const struct module_instance *m = value;
	JSON_Object *mo = module_instance_fill_json_common(o, m);

	json_object_set_string(mo, "moduleId", m->moduleId);
	return 1; /* continue */
}

static int
module_instance_forward_fn(const void *message, const void *module_instance)
{
	struct sdk_event_message_sent *msg = __UNCONST(message);
	const struct module_instance *m = module_instance;

	struct sdk_msg_topic_alias *subscribe_alias;
	TAILQ_FOREACH (subscribe_alias, &m->subscribe_topic_aliases, q) {
		if (strcmp(msg->topic, subscribe_alias->topic) == 0) {
#if defined(SDK_LOG_VERBOSE)
			xlog_info("MESSAGE instance %s topic %s -> alias %s "
				  "blob '%.*s'",
				  m->name, msg->topic, subscribe_alias->name,
				  (int)msg->bloblen, (const char *)msg->blob);
#endif
			sdk_queue_message(m->name, subscribe_alias->name,
					  msg->blob, msg->bloblen);
			msg->reason = EVP_MESSAGE_SENT_CALLBACK_REASON_SENT;
		}
	}

	return 1; /* continue */
}

JSON_Value *
module_instance_get_json_value_evp1(void)
{
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);
	map_foreach(instances, module_instance_fill_json_evp1, o);
	return v;
}

JSON_Value *
module_instance_get_json_value_evp2(void)
{
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);
	map_foreach(instances, module_instance_fill_json_evp2, o);
	return v;
}

void
module_instance_notify(enum notify_type type, const char *module_instance_name,
		       size_t module_instance_name_len, EVP_RPC_ID id,
		       const char *topic, const void *blob, size_t bloblen)
{
	struct name name;
	struct module_instance *m;

	name.name = module_instance_name;
	name.len = module_instance_name_len;
	m = map_get_with(instances, module_instance_compare_name, &name);
	if (m == NULL) {
		free(__UNCONST(blob));
		xlog_info("instance_name %s topic %s", module_instance_name,
			  topic);
		return;
	}

#if defined(SDK_LOG_VERBOSE)
	xlog_info("NOTIFY type %d instance %.*s topic %s blob %.*s", type,
		  (int)module_instance_name_len, module_instance_name, topic,
		  (int)bloblen, (const char *)blob);
#endif
	switch (type) {
	case NOTIFY_CONFIG:
		sdk_queue_config(m->name, topic, blob, bloblen);
		break;
	case NOTIFY_RPC_REQUEST:
		sdk_queue_rpc_request(m->name, id, topic, blob);
		break;
	default:
		// TODO: Review exit (xerr)
		//       Programming error. Prefer xlog_abort.
		xerr(1, "%s: unknown type %d", __func__, (int)type);
		free(__UNCONST(blob));
	}
}

void
module_instance_message_forward(struct sdk_event_message_sent *msg)
{
	map_foreach(instances, module_instance_forward_fn, msg);
}

struct module_instance *
get_module_instance_by_name(const char *module_instance_name)
{
	struct name name;

	name.name = module_instance_name;
	name.len = strlen(module_instance_name);
	return map_get_with(instances, module_instance_compare_name, &name);
}

struct module_instance *
get_module_instance_by_entrypoint(const char *entrypoint)
{
	return map_get_with(instances, module_instance_compare_entrypoint,
			    entrypoint);
}

void
module_instance_message_send(struct module_instance *m,
			     struct sdk_event_message_sent *msg)
{
	struct sdk_msg_topic_alias *publish_alias;
	bool found = false;
	TAILQ_FOREACH (publish_alias, &m->publish_topic_aliases, q) {
		if (strcmp(msg->topic, publish_alias->name) == 0) {
			found = true;
#if defined(SDK_LOG_VERBOSE)
			xlog_info("MESSAGE instance %s alias %s -> publish "
				  "topic "
				  "%s "
				  "blob '%.*s'",
				  m->name, publish_alias->name,
				  publish_alias->topic, (int)msg->bloblen,
				  (const char *)msg->blob);
#endif
			msg->mqtt_published =
				sdk_forward_local_to_publish_topic(
					msg, publish_alias->topic);
		}
	}
	if (!found) {
		msg->reason = EVP_MESSAGE_SENT_CALLBACK_REASON_ERROR;
	}
}

struct dirent *
validate_module_instance_dir(struct dirent *d)
{
	/* Currently just used a hook function for a custom Fortify
	cleanse rule */
	// TODO: Replace assert (programming error)
	assert(d != NULL);
	/* REVISIT: add here extra validation of instance dir name */
	return d;
}

void
gc_module_instance_dir(void)
{
	const char *instance_dir = path_get(MODULE_INSTANCE_PATH_ID);
	DIR *dir = opendir(instance_dir);
	if (dir == NULL) {
		if (errno == ENOMEM) {
			// ENOMEM is the only error that is likely
			// unrecoverable
			xlog_abort("opendir(3) failed opening %s with: %s",
				   instance_dir, strerror(errno));
		} else if (errno == ENOENT) {
			xlog_warning("Instances dir %s no longer exists!",
				     instance_dir);
		} else {
			xlog_error("opendir(3) failed opening %s with: %s",
				   instance_dir, strerror(errno));
		}
		// No need to pursue
		return;
	}
	int ret;
	while (true) {
		struct dirent *d = readdir(dir);

		if (d == NULL) {
			break;
		}
		if (!strcmp(d->d_name, "..") || !strcmp(d->d_name, ".")) {
			continue;
		}
		d = validate_module_instance_dir(d);
		if (d == NULL) {
			continue;
		}
		struct module_instance *m;
		m = get_module_instance_by_name(d->d_name);
		if (m) {
			continue;
		}
		m = get_module_instance_by_entrypoint(d->d_name);
		if (m && module_instance_is_persistent(m)) {
			continue;
		}
		const char *dname = module_instance_dir(d->d_name);
		xlog_info("Removing instance dir %s", dname);
		ret = rmtree(dname);
		if (ret == -1) {
			xlog_error("rmtree on %s", dname);
		}
	}
	ret = closedir(dir);
	if (ret) {
		xlog_abort("closedir(3) failed closing %s with: %s",
			   instance_dir, strerror(errno));
	}
}

int
module_instance_convert_path(struct module_instance *m,
			     const char *path_in_module_instance,
			     char **resultp)
{
	return m->ops->instance->convert_path(m, path_in_module_instance,
					      resultp);
}
