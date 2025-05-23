/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>

#define TCP_BLOCKING 1

int tcp_connect_socket(int *socketfd, const char *host, const char *port,
		       unsigned int flags);
void tcp_socket_init(int *socketfd);
void tcp_socket_free(int *socketfd);

int tcp_prepare_poll(int socketfd, bool want_write);
