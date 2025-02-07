/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_IMPL_NOOP_H
#define MODULE_IMPL_NOOP_H

struct module_instance;

int module_instance_impl_noop_convert_path(struct module_instance *m,
					   const char *path_in_module_instance,
					   char **resultp);

#endif
