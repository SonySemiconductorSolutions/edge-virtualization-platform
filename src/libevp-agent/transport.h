/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "mqtt.h"
#include "pal.h"

struct evp_agent_context;

enum transport_status {
	TRANSPORT_STATUS_READY,
	TRANSPORT_STATUS_CONNECTING,
	TRANSPORT_STATUS_CONNECTED
};

struct transport_ctxt {
	struct pal_socket socket;

	void (*hub_connected)(struct evp_agent_context *ctxt,
			      struct transport_ctxt *transport,
			      const char *device_id, const char *client_id);
	void (*hub_on_message)(struct evp_agent_context *ctxt,
			       const char *topic, int packet_id, int qos_level,
			       const char *payload);

	char *host;
	char *port;
	const char *device_id; /* used in explicit device level topic prefix */
	char *client_id;
	const char *user;
	const char *pass;
	size_t sendbufsize;
	size_t recvbufsize;
	uint64_t connect_timestamp;
	void *socket_conf;
	unsigned char *sendbuf;
	unsigned char *recvbuf;
	struct mqtt_client c;
	enum transport_status status;
	struct evp_agent_context *agent;
	enum MQTTErrors last_error;
	bool initial_get_done;
};

struct evp_agent_context;
struct tls_context;

struct transport_ctxt *transport_setup(
	void (*on_connected_cb)(struct evp_agent_context *ctxt,
				struct transport_ctxt *transport,
				const char *device_id, const char *client_id),
	void (*on_message_cb)(struct evp_agent_context *ctxt,
			      const char *topic, int packet_id, int qos_level,
			      const char *payload),
	struct evp_agent_context *ctxt, struct tls_context *tls_context);

int transport_sync(struct transport_ctxt *ctxt, uint64_t now);

int transport_connect(struct transport_ctxt *ctxt);

int transport_disconnect(struct transport_ctxt *ctxt);

bool transport_is_connected(struct transport_ctxt *ctxt);

int transport_send(struct transport_ctxt *ctxt, char *topic,
		   const char *payload, int payloadlen, int qos);

int transport_subscribe(struct transport_ctxt *ctxt, const char *topic_name);

void transport_free(struct transport_ctxt *ctxt);

/* TODO: this is a quick and dirty hack, and limits us to one struct
 * transport_ctxt instance. */
extern struct mqtt_client *g_mqtt_client;

#endif
