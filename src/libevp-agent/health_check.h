/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__HEALTH_CHECK_H__)
#define __HEALTH_CHECK_H__

#include <sys/wait.h>

enum pid_status {
	PID_STATUS_RUNNING = 1,
	PID_STATUS_EXITED_OK = 0,
	PID_STATUS_CHECK_BACKOFF = -1,
};

enum pid_status check_pid_status(pid_t pid);

#endif /* !defined(__HEALTH_CHECK_H__) */
