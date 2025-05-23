/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file implements the config.h interface,
 * backed by getenv() and mbedtls. (MBEDTLS_FS_IO)
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <internal/cdefs.h>
#include <internal/config_impl.h>
#include <internal/util.h>

struct config_def {
	const char *var_name;
} g_config_defs[] = {
	[EVP_CONFIG_TLS_CA_CERT] =
		{
			"EVP_TLS_CA_CERT",
		},
	[EVP_CONFIG_MQTT_HOST] =
		{
			"EVP_MQTT_HOST",
		},
	[EVP_CONFIG_MQTT_PORT] =
		{
			"EVP_MQTT_PORT",
		},
	[EVP_CONFIG_MQTT_TLS_CA_CERT] =
		{
			"EVP_MQTT_TLS_CA_CERT",
		},
	[EVP_CONFIG_MQTT_TLS_CLIENT_CERT] =
		{
			"EVP_MQTT_TLS_CLIENT_CERT",
		},
	[EVP_CONFIG_MQTT_TLS_CLIENT_KEY] =
		{
			"EVP_MQTT_TLS_CLIENT_KEY",
		},
	[EVP_CONFIG_MQTT_MFS_QOS] =
		{
			"EVP_MQTT_MFS_QOS",
		},
	[EVP_CONFIG_HTTPS_CA_CERT] =
		{
			"EVP_HTTPS_CA_CERT",
		},
	[EVP_CONFIG_REGISTRY_AUTH] =
		{
			"EVP_REGISTRY_AUTH",
		},
	[EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC] =
		{
			"EVP_REPORT_STATUS_INTERVAL_MIN_SEC",
		},
	[EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC] =
		{
			"EVP_REPORT_STATUS_INTERVAL_MAX_SEC",
		},
	[EVP_CONFIG_TRANSPORT_QUEUE_LIMIT] =
		{
			"EVP_TRANSPORT_QUEUE_LIMIT",
		},
	[EVP_CONFIG_CONFIGURATION_ID] =
		{
			"EVP_CONFIGURATION_ID",
		},
	[EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY] =
		{
			"EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY",
		},
	[EVP_CONFIG_MQTT_PROXY_HOST] =
		{
			"EVP_MQTT_PROXY_HOST",
		},
	[EVP_CONFIG_MQTT_PROXY_PORT] =
		{
			"EVP_MQTT_PROXY_PORT",
		},
	[EVP_CONFIG_MQTT_PROXY_USERNAME] =
		{
			"EVP_MQTT_PROXY_USERNAME",
		},
	[EVP_CONFIG_MQTT_PROXY_PASSWORD] =
		{
			"EVP_MQTT_PROXY_PASSWORD",
		},
	[EVP_CONFIG_HTTP_PROXY_HOST] =
		{
			"EVP_HTTP_PROXY_HOST",
		},
	[EVP_CONFIG_HTTP_PROXY_PORT] =
		{
			"EVP_HTTP_PROXY_PORT",
		},
	[EVP_CONFIG_HTTP_PROXY_USERNAME] =
		{
			"EVP_HTTP_PROXY_USERNAME",
		},
	[EVP_CONFIG_HTTP_PROXY_PASSWORD] =
		{
			"EVP_HTTP_PROXY_PASSWORD",
		},
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	[EVP_CONFIG_DOCKER_TLS_CA_CERT] =
		{
			"EVP_DOCKER_TLS_CA_CERT",
		},
	[EVP_CONFIG_DOCKER_TLS_CLIENT_CERT] =
		{
			"EVP_DOCKER_TLS_CLIENT_CERT",
		},
	[EVP_CONFIG_DOCKER_TLS_CLIENT_KEY] =
		{
			"EVP_DOCKER_TLS_CLIENT_KEY",
		},
#endif /* defined(CONFIG_EVP_MODULE_IMPL_DOCKER) */
	[EVP_CONFIG_IOT_PLATFORM] =
		{
			"EVP_IOT_PLATFORM",
		},
};

struct config *
get_config_impl(enum config_key key)
{
	const struct config_def *def = &g_config_defs[key];
	const char *value;
	if (is_config_optional(key)) {
		value = getenv(def->var_name);
	} else {
		value = xgetenv(def->var_name);
	}
	if (value == NULL) {
		return NULL;
	}
	struct config *config = xmalloc(sizeof(*config));
	config->key = key;
	config->value = xstrdup(value);
	config->size = strlen(value) + 1;
	config->free = free;
	return config;
}

int
load_config_impl(struct config *config, void **vpp, size_t *sizep)
{
	*vpp = config->value;
	*sizep = config->size;
	return 0;
}

void
unload_config_impl(struct config *config, void *vp0, size_t size)
{
	// nothing to unload
}

bool
config_is_pk_file(enum config_key key)
{
	switch (key) {
	case EVP_CONFIG_TLS_CA_CERT:
	case EVP_CONFIG_MQTT_TLS_CA_CERT:
	case EVP_CONFIG_MQTT_TLS_CLIENT_CERT:
	case EVP_CONFIG_MQTT_TLS_CLIENT_KEY:
	case EVP_CONFIG_HTTPS_CA_CERT:
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	case EVP_CONFIG_DOCKER_TLS_CA_CERT:
	case EVP_CONFIG_DOCKER_TLS_CLIENT_CERT:
	case EVP_CONFIG_DOCKER_TLS_CLIENT_KEY:
#endif /* defined(CONFIG_EVP_MODULE_IMPL_DOCKER) */
	case EVP_CONFIG_PK_FILE:
		return true;
	default:
		return false;
	}
}
