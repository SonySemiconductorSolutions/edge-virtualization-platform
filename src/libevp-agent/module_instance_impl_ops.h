/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_INSTANCE_IMPL_OPS_H
#define MODULE_INSTANCE_IMPL_OPS_H

#include <stdbool.h>

struct module_instance;

struct ModuleInstanceSpec;

struct module_instance_impl_ops {
	const char *name;
	bool (*is_running)(struct module_instance *m);
	bool (*has_stopped)(struct module_instance *m);
	int (*start)(struct module_instance *m,
		     const struct ModuleInstanceSpec *spec,
		     const char *workspace, void *handle);
	void (*post_create)(struct module_instance *m);
	int (*stop)(struct module_instance *m);
	const char *(*stat)(struct module_instance *m);
	int (*convert_path)(struct module_instance *m,
			    const char *path_in_module_instance,
			    char **resultp);

	int (*init)(void);
};

const struct module_instance_impl_ops *
module_instance_impl_ops_get_by_name(const char *name);
const struct module_instance_impl_ops *
module_instance_impl_ops_get_default(void);
int module_instance_impl_ops_init_all(void);

#endif
