/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>

typedef int mqtt_pal_tcp_socket_handle;

ssize_t mqtt_pal_tcp_sendall(mqtt_pal_tcp_socket_handle fd, const void *buf,
			     size_t len, int flags);
ssize_t mqtt_pal_tcp_recvall(mqtt_pal_tcp_socket_handle fd, void *buf,
			     size_t bufsz, int flags);
