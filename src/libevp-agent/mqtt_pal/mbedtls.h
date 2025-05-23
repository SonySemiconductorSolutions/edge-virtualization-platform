/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/types.h>

struct mbedtls_ssl_context;
typedef struct mbedtls_ssl_context *mqtt_pal_mbedtls_socket_handle;

ssize_t mqtt_pal_mbedtls_sendall(mqtt_pal_mbedtls_socket_handle fd,
				 const void *buf, size_t len, int flags);
ssize_t mqtt_pal_mbedtls_recvall(mqtt_pal_mbedtls_socket_handle fd, void *buf,
				 size_t bufsz, int flags);
