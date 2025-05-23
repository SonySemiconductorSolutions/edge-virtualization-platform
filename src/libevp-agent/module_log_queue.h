/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_LOG_QUEUE_H
#define MODULE_LOG_QUEUE_H

#include <stdbool.h>
#include <stddef.h>

void module_log_queue_init(void);
void module_log_queue_free(void);
int module_log_queue_put(const char *instance_id, const char *stream,
			 const char *log);
size_t module_log_queue_write(void *data, size_t sz);
size_t module_log_queue_read(void *data, size_t sz);
size_t module_log_queue_get_len(void);
bool module_log_queue_is_full(void);

#endif // MODULE_LOG_QUEUE_H
