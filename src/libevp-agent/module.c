/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "evp/agent.h"
#include "manifest.h"
#include "map.h"
#include "module.h"
#include "module_impl.h"
#include "module_impl_ops.h"
#include "xlog.h"
#include "xpthread.h"

static const struct module_impl_ops *
find_module_impl_ops(struct Module *mod)
{
	const struct module_impl_ops *ops;

	if (mod->moduleImpl != NULL) {
		ops = module_impl_ops_get_by_name(mod->moduleImpl);
		if (ops == NULL) {
			xlog_error("moduleImpl %s is not supported",
				   mod->moduleImpl);
		}
	} else {
		ops = module_impl_ops_get_default();
	}
	return ops;
}

static struct map *modules;

struct _gc_ctx {
	const struct ModuleList *list;
	int error;
};

static int
module_compare(const void *key, const void *value)
{
	const char *moduleId = key;
	const struct module *m = value;

	return strcmp(m->moduleId, moduleId);
}

static void
module_free1(struct module *m)
{
	if (m != NULL) {
		evp_agent_module_clear_failure_msg(m);
		xpthread_mutex_destroy(m->failureMessageMutex);
		free(m->failureMessageMutex);
		m->failureMessageMutex = NULL;
		free(__UNCONST(m->moduleId));
		free(m);
	}
}

static int
module_free_each(const void *key, const void *value)
{
	struct module *m = __UNCONST(value);
	map_put(modules, m->moduleId, NULL);
	module_free1(m);
	return 1;
}

static int
is_in_deployment_list(const struct module *module,
		      const struct ModuleList *list)
{
	unsigned int i;
	for (i = 0; i < list->n; i++) {
		const struct Module *spec = &list->modules[i];
		if (strcmp(module->moduleId, spec->moduleId) == 0) {
			break;
		}
	}

	/* Returns true if module was found in list and list is not empty
	 * Returns false otherwise
	 */
	return (i != list->n);
}

static int
unload(struct module *module)
{
	int ret;

	/* unload this */
	xlog_info("UNLOAD MODULE %s", module->moduleId);
	if (module->ops->loaded(module)) {
		module->ops->unload(module);
	}
	ret = module->ops->download_cancel(module);
	if (ret != 0) {
		return ret;
	}
	struct module *n = map_put(modules, module->moduleId, NULL);
	xlog_abortif(n != module, "mismatch mod instances found (%p != %p)", n,
		     module);
	module_free1(module);
	return 0;
}

static int
module_gc(const void *key, const void *value)
{
	struct _gc_ctx *ctx = __UNCONST(key);
	const struct ModuleList *list = ctx->list;
	struct module *module = __UNCONST(value);

	if (is_in_deployment_list(module, list)) {
		goto bail;
	}

	int ret = unload(module);
	if (ret) {
		ctx->error = ret;
	}
bail:
	return 1;
}

static int
module_download_cancel_each(const void *key, const void *value)
{
	struct _gc_ctx *ctx = __UNCONST(key);
	struct module *m = __UNCONST(value);
	int ret;

	/* unload this */
	xlog_info("CANCEL MODULE %s", m->moduleId);
	ret = m->ops->download_cancel(m);
	if (ret != 0) {
		xlog_error("Module %s could not be cancelled (%d)",
			   m->moduleId, ret);
		ctx->error = ret;
	}
	return 1;
}

void
module_init(void *param)
{
	modules = map_init(16, module_compare, NULL);
	module_impl_ops_init_all(param);
}

void
module_deinit(void)
{
	module_unload(&(struct ModuleList){0});
	map_foreach(modules, module_free_each, NULL);
	map_free(modules);
	modules = NULL;
}

int
module_unload(const struct ModuleList *list)
{
	struct _gc_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.list = list;
	map_foreach(modules, module_gc, &ctx);
	return ctx.error;
}

int
module_load(const struct ModuleList *list)
{
	unsigned int i;
	int result = 0;

	for (i = 0; i < list->n; i++) {
		struct Module *mod = __UNCONST(&list->modules[i]);

		const struct module_impl_ops *ops = find_module_impl_ops(mod);
		if (ops == NULL) {
			result = ENOTSUP;
			continue;
		}

		struct module *m = map_get(modules, mod->moduleId);
		if (m != NULL) {
			if (m->ops != ops) {
				/*
				 * moduleImpl has been changed for a moduleId.
				 * Probably a bug in the cloud side component.
				 */
				// TODO: Review exit (xlog_abort)
				xlog_abort("moduleImpl %s doesn't match for "
					   "module %s",
					   mod->moduleImpl, mod->moduleId);
			}
			if (m->ops->loaded(m)) {
				continue;
			}
		} else {
			m = xcalloc(1, sizeof(*m));
			m->failureMessageMutex =
				xmalloc(sizeof(struct evp_lock));
			xpthread_mutex_init(m->failureMessageMutex);
			m->moduleId = xstrdup(mod->moduleId);
			map_put(modules, m->moduleId, m);
			m->ops = ops;
		}
		// don't load the module if downloadUrl is NULL
		if (mod->downloadUrl != NULL) {
			int ret = m->ops->load(m, mod);
			if (ret != 0) {
				result = ret;
				continue;
			}
		}
		// TODO: Replace assert (programming error)
		assert(m->failureMessage == NULL);
	}
	return result;
}

void *
module_handle(const char *moduleId)
{
	struct module *m = map_get(modules, moduleId);
	if (m == NULL) {
		return NULL;
	}
	return m->ops->handle(m);
}

const struct module_impl_ops *
module_ops(const char *moduleId)
{
	struct module *m = map_get(modules, moduleId);
	if (m == NULL) {
		return NULL;
	}
	return m->ops;
}

/*
 * remove unnecessary modules from the storage
 */

void
module_prune(void)
{
	module_impl_ops_prune_all();
}

void
module_destroy(void)
{
	module_impl_ops_destroy_all();
}

int
module_download_cancel(void)
{
	struct _gc_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	map_foreach(modules, module_download_cancel_each, &ctx);
	return ctx.error;
}

static int
module_fill_json(const void *key, const void *value)
{
	JSON_Object *o = __UNCONST(key);
	const struct module *m = value;
	JSON_Value *mv = json_value_init_object();
	JSON_Object *mo = json_value_get_object(mv);

	const char *status;
	if (m->failureMessage != NULL) {
		status = "error";
		json_object_set_string(mo, "failureMessage",
				       m->failureMessage);
	} else if (m->ops->downloading(m)) {
		status = "downloading";
	} else if (m->ops->loaded(m)) {
		status = "ok";
	} else {
		status = "unknown";
	}
	json_object_set_string(mo, "status", status);

	json_object_set_value(o, m->moduleId, mv);
	return 1; /* continue */
}

JSON_Value *
module_get_json_value(void)
{
	JSON_Value *v = json_value_init_object();
	JSON_Object *o = json_value_get_object(v);
	map_foreach(modules, module_fill_json, o);
	return v;
}

const char *
evp_agent_module_get_id(const struct module *module)
{
	return module->moduleId;
}

int
evp_agent_module_set_failure_msg(struct module *module, const char *fmt, ...)
{
	int ret = -1;
	char *s = NULL;
	va_list ap, apc;

	va_start(ap, fmt);
	/* Remember that vsnprintf(3) leaves the va_list undefined on return.
	 */
	va_copy(apc, ap);

	int n = vsnprintf(NULL, 0, fmt, ap);
	if (n < 0) {
		xlog_error("vsnprintf failed");
		goto end;
	}

	size_t sz = n + 1;
	s = malloc(sz);
	if (!s) {
		xlog_error("malloc failed with %d", errno);
		goto end;
	}

	vsprintf(s, fmt, apc);
	xpthread_mutex_lock(module->failureMessageMutex);
	free(module->failureMessage);
	module->failureMessage = s;
	xpthread_mutex_unlock(module->failureMessageMutex);
	ret = 0;

end:
	va_end(ap);
	va_end(apc);

	if (ret) {
		free(s);
	}

	return ret;
}

void
evp_agent_module_clear_failure_msg(struct module *module)
{
	xpthread_mutex_lock(module->failureMessageMutex);
	free(module->failureMessage);
	module->failureMessage = NULL;
	xpthread_mutex_unlock(module->failureMessageMutex);
}

bool
evp_agent_module_is_in_use(const char *moduleId)
{
	return module_handle(moduleId);
}

struct module *
module_get(const char *moduleId)
{
	return map_get(modules, moduleId);
}
