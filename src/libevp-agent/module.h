/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

struct ModuleList;
struct module_impl_ops;

void module_init(void *param);
void module_deinit(void);
void module_destroy(void);
int module_unload(const struct ModuleList *);
int module_load(const struct ModuleList *);
void *module_handle(const char *);
const struct module_impl_ops *module_ops(const char *);
void module_prune(void);
int module_download_cancel(void);
struct module *module_get(const char *moduleId);

JSON_Value *module_get_json_value(void);
