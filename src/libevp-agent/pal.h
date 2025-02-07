/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pal_socket_handle.h"

#define PAL_BLOCKING 1
#define PAL_INSECURE 2

void pal_socket_init(struct pal_socket *socket, void *conf);
int pal_connect(struct pal_socket *socket, const char *host, const char *port,
		unsigned int flags, void *conf);
int pal_connect_on_fd(struct pal_socket *socket, const char *host,
		      unsigned int flags, void *conf, int fd);
int pal_prepare_poll(struct pal_socket *socket, bool want_write);
void pal_socket_free(struct pal_socket *socket);
