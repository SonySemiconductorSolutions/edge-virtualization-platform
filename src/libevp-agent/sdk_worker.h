/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SDK_WORKER_H
#define SDK_WORKER_H

struct EVP_client;

struct sdk_socket_context {
	struct EVP_client *sdk_handle;
	int listen_fd;
};

void *sdk_socket_thread(void *vp);

#endif
