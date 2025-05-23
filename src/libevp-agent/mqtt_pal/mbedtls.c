/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#undef MQTT_USE_CUSTOM_SOCKET_HANDLE
#undef mqtt_pal_socket_handle

#include "mbedtls.h"

#define MQTT_USE_MBEDTLS
#define mqtt_pal_sendall       mqtt_pal_mbedtls_sendall
#define mqtt_pal_recvall       mqtt_pal_mbedtls_recvall
#define mqtt_pal_socket_handle mqtt_pal_mbedtls_socket_handle

#include "../MQTT-C/src/mqtt_pal.c"
