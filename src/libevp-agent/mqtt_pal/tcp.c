/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#undef MQTT_USE_CUSTOM_SOCKET_HANDLE
#undef mqtt_pal_socket_handle

#include "tcp.h"

#define mqtt_pal_sendall       mqtt_pal_tcp_sendall
#define mqtt_pal_recvall       mqtt_pal_tcp_recvall
#define mqtt_pal_socket_handle mqtt_pal_tcp_socket_handle

#include "../MQTT-C/src/mqtt_pal.c"
