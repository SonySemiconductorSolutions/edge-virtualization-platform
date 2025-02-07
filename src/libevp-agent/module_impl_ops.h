/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>

struct module;
struct module_instance_impl_ops;

struct Module;
struct ModuleInstanceSpec;

/*
 * module_impl_ops:
 *
 * Each MODULE_IMPL provides this vector.
 */

struct module_impl_ops {
	const char *name;
	bool (*loaded)(const struct module *m);
	bool (*downloading)(const struct module *m);
	int (*download_cancel)(struct module *m);
	int (*load)(struct module *m, const struct Module *modspec);
	void (*unload)(struct module *m);

	/* The validity of the return value of this function
	 * must match the validity of the downloaded module
	 * object (i.e. it is only valid after it is checked valid
	 * upon download).
	 */
	void *(*handle)(const struct module *m);

	/* optional; only used for CONFIG_EVP_MODULE_IMPL_OBJ */
	int (*load_obj)(struct module *m, const char *filename);

	void (*init)(void *param);
	void (*prune)(void);
	void (*destroy)(void);

	const struct module_instance_impl_ops *instance;
};

const struct module_impl_ops *module_impl_ops_get_default(void);
const struct module_impl_ops *module_impl_ops_get_by_name(const char *name);
void module_impl_ops_init_all(void *param);
void module_impl_ops_prune_all(void);
void module_impl_ops_destroy_all(void);
