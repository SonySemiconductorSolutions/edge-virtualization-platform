/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <assert.h>
#include <string.h>

#include "cdefs.h"
#include "module_impl_ops.h"

extern const struct module_impl_ops module_impl_ops_wasm,
	module_impl_ops_docker, module_impl_ops_dlfcn, module_impl_ops_spawn,
	module_impl_ops_python;

static const struct module_impl_ops *ops[] = {
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	&module_impl_ops_wasm,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	&module_impl_ops_docker,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN)
	&module_impl_ops_dlfcn,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_SPAWN)
	&module_impl_ops_spawn,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	&module_impl_ops_python,
#endif
};

const struct module_impl_ops *
module_impl_ops_get_default(void)
{
	return ops[0];
}

const struct module_impl_ops *
module_impl_ops_get_by_name(const char *name)
{
	for (size_t i = 0; i < __arraycount(ops); i++) {
		const struct module_impl_ops *entry = ops[i];
		if (!strcmp(name, entry->name)) {
			return entry;
		}
	}
	return NULL;
}

void
module_impl_ops_init_all(void *param)
{
	/*
	 * Note: Some of module impls share the same init operation.
	 * E.g. wasm and spawn shares module_impl_obj_init.
	 * It's the implementation's responsibility to be prepared to
	 * be called multiple times.
	 */

	for (size_t i = 0; i < __arraycount(ops); i++) {
		ops[i]->init(param);
	}
}

void
module_impl_ops_prune_all(void)
{
	/*
	 * Note: Some of module impls share the same prune operation.
	 * E.g. wasm and spawn shares module_impl_obj_prune.
	 * It's the implementation's responsibility to be prepared to
	 * be called multiple times.
	 */

	for (size_t i = 0; i < __arraycount(ops); i++) {
		ops[i]->prune();
	}
}

void
module_impl_ops_destroy_all(void)
{
	for (size_t i = 0; i < __arraycount(ops); i++) {
		ops[i]->destroy();
	}
}
