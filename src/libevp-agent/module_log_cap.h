/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_LOG_CAP_H
#define MODULE_LOG_CAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int module_log_cap_open(const char *instance, const char *stream);
void module_log_cap_close(const char *instance, const char *stream);
void module_log_cap_flush(const char *instance, const char *stream);
int module_log_cap_set_enable(const char *instance, const char *stream,
			      bool value);
int module_log_cap_get_enable(const char *instance, const char *stream,
			      bool *value);
void module_log_cap_start(void);
void module_log_cap_stop(void);
void module_log_cap_init(void);
void module_log_cap_free(void);

#endif // MODULE_LOG_CAP_H
