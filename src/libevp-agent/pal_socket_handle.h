/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__PAL_SOCKET_HANDLE_H__)
#define __PAL_SOCKET_HANDLE_H__
#include "tcp.h"
#include "tls.h"

#define PAL_TYPE_TCP     0
#define PAL_TYPE_MBEDTLS 1

union pal_socket_value {
	int tcp;
	struct tls_connection_context tls;
};

struct pal_socket {
	int type;
	union pal_socket_value socket;
};

#endif /* __PAL_SOCKET_HANDLE_H__ */
