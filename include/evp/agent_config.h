/*
 * SPDX-FileCopyrightText: 2025 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EVP_CONFIG_H
#define EVP_CONFIG_H

#include <config.h>

#include <stdbool.h>

enum config_key {
	EVP_CONFIG_TLS_CA_CERT,
	EVP_CONFIG_MQTT_HOST,
	EVP_CONFIG_MQTT_PORT,
	EVP_CONFIG_MQTT_TLS_CA_CERT,
	EVP_CONFIG_MQTT_TLS_CLIENT_CERT,
	EVP_CONFIG_MQTT_TLS_CLIENT_KEY,
	EVP_CONFIG_MQTT_MFS_QOS,
	EVP_CONFIG_HTTPS_CA_CERT,
	EVP_CONFIG_MQTT_PROXY_HOST,
	EVP_CONFIG_MQTT_PROXY_PORT,
	EVP_CONFIG_MQTT_PROXY_USERNAME,
	EVP_CONFIG_MQTT_PROXY_PASSWORD,
	EVP_CONFIG_HTTP_PROXY_HOST,
	EVP_CONFIG_HTTP_PROXY_PORT,
	EVP_CONFIG_HTTP_PROXY_USERNAME,
	EVP_CONFIG_HTTP_PROXY_PASSWORD,
	EVP_CONFIG_REGISTRY_AUTH,
	EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC,
	EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC,
	EVP_CONFIG_CONFIGURATION_ID,
	EVP_CONFIG_TRANSPORT_QUEUE_LIMIT,
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	EVP_CONFIG_DOCKER_TLS_CA_CERT,
	EVP_CONFIG_DOCKER_TLS_CLIENT_CERT,
	EVP_CONFIG_DOCKER_TLS_CLIENT_KEY,
#endif /* defined(CONFIG_EVP_MODULE_IMPL_DOCKER) */
	EVP_CONFIG_PK_FILE,
	EVP_CONFIG_IOT_PLATFORM,
	EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY,
};

struct config {
	enum config_key key;
	void *value;
	size_t size;
	void (*free)(void *);
};

/* Functions that call the backend-specific implementations */
int load_config_impl(struct config *, void **, size_t *);
void unload_config_impl(struct config *, void *, size_t);
struct config *get_config_impl(enum config_key);
bool config_is_pk_file(enum config_key key);

#endif /* EVP_CONFIG_H */
