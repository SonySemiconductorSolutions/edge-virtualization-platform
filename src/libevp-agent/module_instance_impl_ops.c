/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <assert.h>
#include <string.h>

#include "cdefs.h"
#include "module_instance_impl_ops.h"

extern const struct module_instance_impl_ops module_instance_impl_ops_docker,
	module_instance_impl_ops_dlfcn, module_instance_impl_ops_spawn,
	module_instance_impl_ops_wasm, module_instance_impl_ops_python;

static const struct module_instance_impl_ops *ops[] = {
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	&module_instance_impl_ops_wasm,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	&module_instance_impl_ops_docker,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN)
	&module_instance_impl_ops_dlfcn,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_SPAWN)
	&module_instance_impl_ops_spawn,
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	&module_instance_impl_ops_python,
#endif
};

const struct module_instance_impl_ops *
module_instance_impl_ops_get_default(void)
{
	return ops[0];
}

const struct module_instance_impl_ops *
module_instance_impl_ops_get_by_name(const char *name)
{
	for (size_t i = 0; i < __arraycount(ops); i++) {
		const struct module_instance_impl_ops *entry = ops[i];
		if (!strcmp(name, entry->name)) {
			return entry;
		}
	}
	return NULL;
}

int
module_instance_impl_ops_init_all(void)
{
	for (size_t i = 0; i < __arraycount(ops); i++) {
		int ret = ops[i]->init();
		if (ret) {
			return ret;
		};
	}
	return 0;
}
