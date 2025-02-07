/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>

#define MIN_REPORT_INTERVAL_SEC       3
#define MAX_REPORT_INTERVAL_SEC       180
#define DEFAULT_MQTT_MFS_QOS          1
#define DEFAULT_TRANSPORT_QUEUE_LIMIT CONFIG_EVP_MQTT_SEND_BUFF_SIZE

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

struct config;

struct config *get_config(enum config_key);
void free_config(struct config *);
int load_config(struct config *, void **, size_t *);
char *load_simple_config(struct config *);
void unload_config(struct config *, void *, size_t);

/**
 * Get a string representation of the configuration setting.
 * The returned string is allocated on the heap and must be freed
 * after use.
 *
 * Settings are determined in the following order:
 * - Device level configuration from the Hub
 * - Configuration from environment or settings
 *
 * If the setting is not defined in either of these then NULL is returned.
 *
 * @param[in] key: configuration key
 *
 * @return the configuration value as a string, or NULL if not defined
 */
char *config_get_string(enum config_key key);

/**
 * Get an int representation of the configuration setting.
 *
 * Settings are determined in the following order:
 * - Device level configuration from the Hub
 * - Configuration from environment or settings
 * - Compile time default value
 *
 * If the setting is not defined in any of these then EINVAL is returned
 * and `value` is not set.
 *
 * @param[in] key: configuration key
 * @param[out] value: configuration integer value
 *
 * @return 0 in case of success, EINVAL if setting is not available or not a
 * valid number.
 */
int config_get_int(enum config_key key, intmax_t *value);

#endif /* CONFIG_H */
