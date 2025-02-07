/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_IMPL_OBJ_H
#define MODULE_IMPL_OBJ_H

#include <stdbool.h>

struct module;
struct Module;

bool module_impl_obj_downloading(const struct module *m);
void module_impl_obj_destroy(void);
int module_impl_obj_download_cancel(struct module *m);
int module_impl_obj_load(struct module *m, const struct Module *modspec);
void module_impl_obj_init(void *param);
void module_impl_obj_prune(void);

#endif
