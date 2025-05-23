/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h> /* bool */
#include <stdint.h>
#include <time.h> /* time_t */

void main_loop_wakeup(const char *name);
void main_loop_init(void);
void main_loop_add_abs_timeout_sec(const char *name, time_t to);
void main_loop_add_timeout_ms(const char *name, unsigned int timeout_ms);
/*
 * Request next wake-up time in ms
 *
 * @param name				Who is requesting the wakeup
 * @param abs_timeout_ms	Absolute time to wakeup in ms
 */
void main_loop_add_abs_timeout_ms(const char *name, uint64_t abs_timeout_ms);
int main_loop_add_fd(int fd, bool want_write);
int main_loop_block(void);
