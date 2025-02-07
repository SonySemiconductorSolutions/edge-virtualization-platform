/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <inttypes.h>
#if defined(__NuttX__) || defined(__GLIBC__)
#include <malloc.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "evp/agent.h"
#include "hub.h"
#include "mqtt_custom.h"
#include "pal.h"
#include "proxy.h"
#include "retry.h"
#include "timeutil.h"
#include "transport.h"
#include "xlog.h"
#include "xmqtt.h"

#define MQTT_CONNACK_TIMEOUT_MS (180 * 1000)

static struct retry_state mqtt_retry_state;
/* TODO: this is a quick and dirty hack, and limits us to one struct
 * transport_ctxt instance. */
struct mqtt_client *g_mqtt_client;

static const struct retry_params mqtt_retry_params = {
	.name = "MQTT-SYNC",
	.max_backoff = 7, /* 64 seconds */

	/*
	 * Consider two devices mistakenly configured with the same
	 * credential. Because TB only keeps the latest connection with
	 * the credential, a connection made by one of these devices
	 * effectively disconnects the other. Immediate reconnect
	 * attempts merely make the situation worse. To handle such
	 * situations better, avoid resetting the backoff too soon.
	 */
	.recovering_grace_period_ms = 30 * 1000,
};

static enum MQTTErrors
mqtt_inspector_callback(struct mqtt_client *client)
{
	struct transport_ctxt *ctxt = client->reconnect_state;
	// TODO: Replace assert (programming error)
	assert(ctxt != NULL);

	if (ctxt->connect_timestamp != 0 &&
	    gettime_ms() > ctxt->connect_timestamp + MQTT_CONNACK_TIMEOUT_MS) {
		client->error = MQTT_ERROR_CONNECTION_REFUSED;
		xlog_error("MQTT CONNACK timeout %" PRIu64 "/%d mS",
			   gettime_ms() - ctxt->connect_timestamp,
			   MQTT_CONNACK_TIMEOUT_MS);

		ctxt->status = TRANSPORT_STATUS_CONNECTING;

		return MQTT_ERROR_CONNECTION_REFUSED;
	}
	return MQTT_OK;
}

static void
mqtt_connected_callback(struct mqtt_client *client, void **vp)
{
	struct transport_ctxt *ctxt = *vp;
	// TODO: Replace assert (programming error)
	assert(ctxt != NULL);

	ctxt->connect_timestamp = 0;

	if (ctxt->hub_connected != NULL) {
		ctxt->hub_connected(ctxt->agent, ctxt, ctxt->device_id,
				    ctxt->client_id);
	}
	ctxt->status = TRANSPORT_STATUS_CONNECTED;
}

static void
mqtt_reconnect_callback(struct mqtt_client *client, void **vp)
{
	struct transport_ctxt *ctxt = *vp;
	// TODO: Replace assert (programming error)
	assert(ctxt != NULL);

	enum MQTTErrors rc;
	int rv;

	if (client->error == MQTT_ERROR_INITIAL_RECONNECT) {
		// TODO: Replace assert (programming error)
		assert(client->socketfd == (mqtt_pal_socket_handle)-1);
		xlog_info("%s: initial connect", __func__);
	} else {
		// TODO: Replace assert (programming error)
		assert(client->socketfd == &ctxt->socket);
		/*
		 * No need to reconnect on MQTT_ERROR_SEND_BUFFER_IS_FULL.
		 */
		if (client->error == MQTT_ERROR_SEND_BUFFER_IS_FULL) {
			xlog_warning("%s: Ignoring %s", __func__,
				     mqtt_error_str(client->error));
			MQTT_PAL_MUTEX_UNLOCK(&client->mutex);
			return;
		}
		xlog_error("%s: called with mqtt error %s", __func__,
			   mqtt_error_str(client->error));
		pal_socket_free(&ctxt->socket);
	}
	ctxt->status = TRANSPORT_STATUS_CONNECTING;
	/*
	 * XXX Ideally, we should do this non-blocking.
	 * Otherwise, this can block the main loop for long.
	 */
	char *proxy_host = config_get_string(EVP_CONFIG_MQTT_PROXY_HOST);
	char *proxy_port = config_get_string(EVP_CONFIG_MQTT_PROXY_PORT);

	if (proxy_host != NULL && proxy_port != NULL) {
		char *proxy_username =
			config_get_string(EVP_CONFIG_MQTT_PROXY_USERNAME);
		char *proxy_password =
			config_get_string(EVP_CONFIG_MQTT_PROXY_PASSWORD);
		char *proxy;
		char *proxy_user = NULL;
		int fd;

		xasprintf(&proxy, "http://%s:%s", proxy_host, proxy_port);
		if (proxy_username != NULL && proxy_password != NULL) {
			xasprintf(&proxy_user, "%s:%s", proxy_username,
				  proxy_password);
		}
		rv = tunnel_over_proxy(proxy, proxy_user, ctxt->host,
				       ctxt->port, &fd);
		free(proxy);
		free(proxy_user);
		if (rv == 0) {
			rv = pal_connect_on_fd(&ctxt->socket, ctxt->host, 0,
					       ctxt->socket_conf, fd);
			if (rv != 0) {
				close(fd);
			}
		}
		free(proxy_username);
		free(proxy_password);
	} else {
		rv = pal_connect(&ctxt->socket, ctxt->host, ctxt->port, 0,
				 ctxt->socket_conf);
		xlog_info("%s: pal_connect(): %d", __func__, rv);
	}
	free(proxy_host);
	free(proxy_port);

	/*
	 * Note: mqtt_reinit should be called even when pal_connect failed.
	 * Otherwise mqtt_sync will crash due to socketfd being -1, which
	 * in not appropriate for mbedtls.
	 *
	 * XXX probably this should be fixed in MQTT-C.
	 */
	mqtt_reinit(client, &ctxt->socket, ctxt->sendbuf, ctxt->sendbufsize,
		    ctxt->recvbuf, ctxt->recvbufsize);
	if (client->error != MQTT_ERROR_CONNECT_NOT_CALLED) {
		xlog_error("mqtt_reinit failure: err = %d", rv);
	}
	if (rv != 0) {
		xlog_error("mqtt connect failure: err = %d", rv);
		client->error = MQTT_ERROR_SOCKET_ERROR;
		MQTT_PAL_MUTEX_UNLOCK(&client->mutex);
		return;
	}

	rc = mqtt_connect(client, ctxt->client_id, NULL, NULL, 0, ctxt->user,
			  ctxt->pass, MQTT_CONNECT_CLEAN_SESSION, 400);
	xlog_info("%s: mqtt_connect(): %d", __func__, rv);
	if (rc != MQTT_OK) {
		xlog_error("mqtt_connect failed with %d (%s)", rc,
			   mqtt_error_str(rc));
	}

	ctxt->connect_timestamp = gettime_ms();
}

static void
on_message(void **state, struct mqtt_response_publish *msg)
{
	/* Create copies to ensure valid strings with null char at the end */
	char *topic = xstrndup(msg->topic_name, msg->topic_name_size);
	char *payload = xstrndup(msg->application_message,
				 msg->application_message_size);

	struct transport_ctxt *ctxt = *state;
	// TODO: Replace assert (programming error)
	assert(ctxt != NULL);

	// Don't print data from/to instances in INFO level
	// Since it is user data and it can be confidential
	xlog_info("onMessage: topic=%s, id=%d, qos=%d, size=%zu", topic,
		  (int)msg->packet_id, (int)msg->qos_level,
		  msg->application_message_size);

	xlog_debug("onMessage: topic=%s, id=%d, qos=%d, payload=%s", topic,
		   (int)msg->packet_id, (int)msg->qos_level, payload);

	ctxt->hub_on_message(ctxt->agent, topic, msg->packet_id,
			     msg->qos_level, payload);
	free(topic);
	free(payload);
}

struct transport_ctxt *
transport_setup(void (*on_connected_cb)(struct evp_agent_context *ctxt,
					struct transport_ctxt *transport,
					const char *device_id,
					const char *client_id),
		void (*on_message_cb)(struct evp_agent_context *ctxt,
				      const char *topic, int packet_id,
				      int qos_level, const char *payload),
		struct evp_agent_context *agent_ctxt,
		struct tls_context *tls_context)
{
	struct transport_ctxt *ctxt =
		xcalloc(1, sizeof(struct transport_ctxt));

	/*
	 * MQTT-C requires the send buffer to be large enough to hold
	 * a single MQTT control packet to send.
	 *
	 * Things potentially use large packets are:
	 *
	 * - periodic_report.  The agent periodically publishes a TB attribute
	 *   which includes EVP deployment status, system info, and all EVP
	 *   states. Depending the workload, it can be large.
	 *
	 * - EVP RPC with large payload.
	 *
	 * - EVP Telemetry with large payload.
	 */

	ctxt->sendbufsize = CONFIG_EVP_MQTT_SEND_BUFF_SIZE;

	/*
	 * MQTT-C requires the receive buffer to be large enough to hold
	 * a single MQTT control packet to receive.
	 *
	 * Things potentially use large packets are:
	 *
	 * - The TB attributes we query after a (re)connect, which
	 *   includes EVP deployment manifest and all EVP configurations,
	 *   can likely be the largest packet to receive. It even includes
	 *   the TB attibutes which we don't really need to query (eg.
	 *   TB client attributes) because TB doesn't seem to have a way to
	 *   query attributes selectively.
	 *   The successive updates are less of problems because they are
	 *   partial ("patch") and thus likely smaller.
	 *
	 * - EVP RPC with large payload.
	 */

	ctxt->recvbufsize = CONFIG_EVP_MQTT_RECV_BUFF_SIZE;

	ctxt->hub_connected = on_connected_cb;
	ctxt->hub_on_message = on_message_cb;

	/* Read client ID from env or TLS certificate */
	const char *client_id_env = getenv("EVP_MQTT_CLIENTID");
	ctxt->client_id = NULL;

	if (tls_context && tls_context->mqtt.ca_crt &&
	    tls_context->mqtt.client_crt && tls_context->mqtt.client_key) {
		xlog_info("Using TLS transport for MQTT");

		ctxt->client_id = tls_get_subject_common_name(
			tls_context->mqtt.client_crt);
		if (ctxt->client_id != NULL) {
			xlog_info(
				"Using client_id from TLS client certificate");
		} else if (client_id_env != NULL) {
			ctxt->client_id = xstrdup(client_id_env);
		}
		ctxt->socket_conf = &tls_context->mqtt.ssl_conf;
	} else {
		xlog_info("Using TCP transport for MQTT");

		if (client_id_env != NULL) {
			ctxt->client_id = xstrdup(client_id_env);
			ctxt->socket_conf = NULL;
		} else {
			xlog_info("Using (null) MQTT client_id");
		}
		ctxt->socket_conf = NULL;
	}

	pal_socket_init(&ctxt->socket, ctxt->socket_conf);
	ctxt->sendbuf = xmalloc(ctxt->sendbufsize);
	ctxt->recvbuf = xmalloc(ctxt->recvbufsize);
	ctxt->status = TRANSPORT_STATUS_READY;

	ctxt->host = config_get_string(EVP_CONFIG_MQTT_HOST);
	ctxt->port = config_get_string(EVP_CONFIG_MQTT_PORT);
	ctxt->device_id = getenv("EVP_MQTT_DEVICE_ID");
	ctxt->user = getenv("EVP_MQTT_USERNAME");
	ctxt->pass = getenv("EVP_MQTT_PASSWORD");
	ctxt->connect_timestamp = 0;
	ctxt->agent = agent_ctxt;

	retry_state_init(&mqtt_retry_state);

	mqtt_init_reconnect(&ctxt->c, mqtt_connected_callback,
			    mqtt_reconnect_callback, ctxt, on_message);
	ctxt->c.inspector_callback = mqtt_inspector_callback;
	ctxt->c.publish_response_callback_state = ctxt;
	g_mqtt_client = &ctxt->c;
	return ctxt;
}

int
transport_sync(struct transport_ctxt *ctxt, uint64_t now)
{
	if (ctxt->status == TRANSPORT_STATUS_READY) {
		return 0;
	}
	if (retry_check(&mqtt_retry_params, &mqtt_retry_state, now)) {

		enum MQTTErrors rc = mqtt_sync(&ctxt->c);
		if (ctxt->last_error != rc) {
			evp_agent_notification_publish(ctxt->agent,
						       "mqtt/sync/err",
						       mqtt_error_str(rc));
		}
		ctxt->last_error = rc;

		if (rc != MQTT_OK) {
			xlog_warning("mqtt_sync failed with %d (%s)", rc,
				     mqtt_error_str(rc));
			retry_failed(&mqtt_retry_params, &mqtt_retry_state,
				     now);
		} else {
			retry_succeeded(&mqtt_retry_params, &mqtt_retry_state,
					now);
		}
	}
	if (ctxt->c.error == MQTT_OK) {
		bool want_write;
		mqtt_prepare_poll(&ctxt->c, &want_write);
		return pal_prepare_poll(&ctxt->socket, want_write);
	}
	return 0;
}

int
transport_connect(struct transport_ctxt *ctxt)
{
	if (ctxt->status != TRANSPORT_STATUS_CONNECTED &&
	    ctxt->status != TRANSPORT_STATUS_CONNECTING) {
		ctxt->status = TRANSPORT_STATUS_CONNECTING;
		ctxt->c.error = MQTT_ERROR_INITIAL_RECONNECT;
		ctxt->c.socketfd = (mqtt_pal_socket_handle)-1;
		ctxt->c.time_of_last_send = MQTT_PAL_TIME();
		return 0;
	} else {
		return -1;
	}
}

int
transport_disconnect(struct transport_ctxt *ctxt)
{
	if (ctxt->status == TRANSPORT_STATUS_CONNECTED ||
	    ctxt->status == TRANSPORT_STATUS_CONNECTING) {
		enum MQTTErrors rc;
		rc = mqtt_disconnect(&ctxt->c);
		if (rc == MQTT_OK) {
			rc = mqtt_sync(&ctxt->c);
		}
		if (rc != MQTT_OK) {
			xlog_error("Failed to send MQTT DISCONNECT: %s",
				   mqtt_error_str(rc));
		}
		pal_socket_free(&ctxt->socket);
		ctxt->status = TRANSPORT_STATUS_READY;

		return 0;
	} else {
		return -1;
	}
}

bool
transport_is_connected(struct transport_ctxt *ctxt)
{
	return ctxt->status == TRANSPORT_STATUS_CONNECTED;
}

void
transport_free(struct transport_ctxt *ctxt)
{
	free(ctxt->sendbuf);
	free(ctxt->recvbuf);
	pal_socket_free(&ctxt->socket);
	free(ctxt->host);
	free(ctxt->port);
	free(ctxt->client_id);
	free(ctxt);
}

int
transport_send(struct transport_ctxt *ctxt, char *topic, const char *payload,
	       int payloadlen, int qos)
{
	enum MQTTErrors rc;
	if (qos > 2) {
		xlog_error("Invalid QOS value: %d", qos);
		return EINVAL;
	}
	rc = mqtt_publish(&ctxt->c, topic, payload, payloadlen,
			  (qos << 1) & MQTT_PUBLISH_QOS_MASK);
	xlog_debug("SEND topic=%s, payload=%s, rc=%d", topic, payload,
		   (int)rc);
	if (rc != MQTT_OK) {
		xlog_warning("mqtt_publish failed with %d (%s)", rc,
			     mqtt_error_str(rc));
		return EAGAIN;
	}
	return 0;
}

int
transport_subscribe(struct transport_ctxt *ctxt, const char *topic)
{
	xlog_info("mqtt_subscribe to '%s'", topic);

	enum MQTTErrors rc = mqtt_subscribe(&ctxt->c, topic, 0);
	if (rc == MQTT_OK) {
		return 0;
	} else {
		xlog_error("mqtt_subscribe failed with %d (%s)", rc,
			   mqtt_error_str(rc));
		return -1;
	}
}
