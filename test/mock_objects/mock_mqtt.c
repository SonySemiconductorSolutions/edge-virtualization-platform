/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <malloc.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "mqtt_custom.h"
#include "xlog.h"

/* This is defined weak here to allow it to be intercepted in specific tests */
__attribute__((weak)) enum MQTTErrors
__wrap_mqtt_publish(struct mqtt_client *client, const char *topic_name,
		    const void *application_message,
		    size_t application_message_size, uint8_t publish_flags)
{
	if (!get_connected()) {
		return MQTT_ERROR_SOCKET_ERROR;
	}
	char *payload = xstrndup((char *)application_message,
				 application_message_size);
	xlog_info("MQTT publish %s: %s", topic_name, payload);
	agent_write_to_pipe(payload);
	free(payload);
	return MQTT_OK;
}

enum MQTTErrors __attribute__((weak))
__wrap_mqtt_subscribe(struct mqtt_client *client, const char *topic_name,
		      int max_qos_level)
{
	return MQTT_OK;
}

void __attribute__((weak))

__wrap_mqtt_init_reconnect(
	struct mqtt_client *client,
	void (*connected_callback)(struct mqtt_client *client, void **state),
	void (*reconnect_callback)(struct mqtt_client *client, void **state),
	void *reconnect_state,
	void (*publish_response_callback)(
		void **state, struct mqtt_response_publish *publish))
{
	/* MQTT-C has alignment requirements, so try to ensure the largest
	 * alignment possible without the use of the
	 * __attribute__((aligned(4))) extension, as hinted by the
	 * documentation. */
	static uintmax_t
		sendbuf[CONFIG_EVP_MQTT_SEND_BUFF_SIZE / sizeof(uintmax_t)],
		recvbuf[sizeof(sendbuf) / sizeof(*sendbuf)];

	client->socketfd = (struct pal_socket *)-1;
	client->error = MQTT_ERROR_INITIAL_RECONNECT;
	client->connected_callback = connected_callback;
	client->reconnect_callback = reconnect_callback;
	client->reconnect_state = reconnect_state;
	mqtt_reinit(client, NULL, (uint8_t *)sendbuf, sizeof(sendbuf),
		    (uint8_t *)recvbuf, sizeof(recvbuf));
}

enum MQTTErrors __attribute__((weak))
__wrap_mqtt_sync(struct mqtt_client *client)
{
	if (client->error == MQTT_ERROR_INITIAL_RECONNECT) {
		client->error = MQTT_OK;
		client->connected_callback(client, &client->reconnect_state);
		set_connected(true);
		return MQTT_OK;
	}
	if (!get_connected()) {
		return MQTT_ERROR_SOCKET_ERROR;
	}
	return MQTT_OK;
}

enum MQTTErrors __attribute__((weak))
__wrap_mqtt_disconnect(struct mqtt_client *client)
{
	set_connected(false);
	return MQTT_OK;
}
