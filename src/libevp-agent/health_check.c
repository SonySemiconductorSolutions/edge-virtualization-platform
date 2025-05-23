/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <errno.h>

#include <internal/util.h>

#include "health_check.h"

#define MAX_WAIT_RETRIES 3

enum pid_status
check_pid_status(pid_t pid)
{
	pid_t ret;
	int status;
	int retry_count = MAX_WAIT_RETRIES;

	while (--retry_count) {
		ret = waitpid(pid, &status, WNOHANG);
		if (ret == pid) {
			return PID_STATUS_EXITED_OK;
		}
		if (ret == (pid_t)-1) {
			if (errno == ECHILD) {
				return PID_STATUS_EXITED_OK;
			}
			if (errno == EINTR) {
				continue;
			}
		}
		if (ret == 0) {
			return PID_STATUS_RUNNING;
		}
	}

	return PID_STATUS_CHECK_BACKOFF;
}
