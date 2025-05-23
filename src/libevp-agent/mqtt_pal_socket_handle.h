/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__MQTT_PAL_SOCKET_HANDLE_H__)
#define __MQTT_PAL_SOCKET_HANDLE_H__

#define MQTT_USE_CUSTOM_SOCKET_HANDLE

struct pal_socket;
typedef struct pal_socket *_mqtt_pal_socket_handle;
#define mqtt_pal_socket_handle _mqtt_pal_socket_handle

#endif /* __MQTT_PAL_SOCKET_HANDLE_H__ */
