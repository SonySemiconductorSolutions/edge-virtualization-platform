/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <internal/config_impl.h>
#include <internal/util.h>

#include "device_config.h"
#include "global.h"
#include "xlog.h"

__CTASSERT(MIN_REPORT_INTERVAL_SEC <= MAX_REPORT_INTERVAL_SEC);

char *
load_simple_config(struct config *config)
{
	void *vp;
	size_t sz;
	int ret;

	if (config == NULL) {
		return NULL;
	}
	ret = load_config(config, &vp, &sz);
	if (ret) {
		xlog_error("Failed to load config %d", (int)config->key);
		return NULL;
	}
	// TODO: Replace assert (programming error)
	assert(strlen(vp) + 1 == sz);
	return vp;
}

int
load_config(struct config *config, void **vpp, size_t *sizep)
{
	void *vp;
	size_t size;
	if (config == NULL) {
		vp = NULL;
		size = 0;
	} else if (config_is_pk_file(config->key)) {
		return config_load_pk_file(config->value, vpp, sizep);
	} else {
		return load_config_impl(config, vpp, sizep);
	}
	*vpp = vp;
	*sizep = size;
	return 0;
}

void
unload_config(struct config *config, void *vp0, size_t size)
{
	if (config == NULL) {
		return;
	}
	if (config_is_pk_file(config->key)) {
		config_unload_pk_file(vp0, size);
	} else {
		unload_config_impl(config, vp0, size);
	}
}

bool
is_config_optional(enum config_key key)
{
	switch (key) {
	case EVP_CONFIG_IOT_PLATFORM: /* EVP1 (evp1-tb) is asigned as default
					 value*/
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	case EVP_CONFIG_DOCKER_TLS_CA_CERT:
	case EVP_CONFIG_DOCKER_TLS_CLIENT_CERT:
	case EVP_CONFIG_DOCKER_TLS_CLIENT_KEY:
#endif /* defined(CONFIG_EVP_MODULE_IMPL_DOCKER) */
		return true;
	case EVP_CONFIG_MQTT_HOST:
	case EVP_CONFIG_MQTT_PORT:
		return false;
	case EVP_CONFIG_TLS_CA_CERT:
	case EVP_CONFIG_MQTT_TLS_CA_CERT:
	case EVP_CONFIG_MQTT_TLS_CLIENT_CERT:
	case EVP_CONFIG_MQTT_TLS_CLIENT_KEY:
	case EVP_CONFIG_HTTPS_CA_CERT:
	case EVP_CONFIG_REGISTRY_AUTH:
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC:
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC:
	case EVP_CONFIG_CONFIGURATION_ID:
	case EVP_CONFIG_MQTT_PROXY_HOST:
	case EVP_CONFIG_MQTT_PROXY_PORT:
	case EVP_CONFIG_MQTT_PROXY_USERNAME:
	case EVP_CONFIG_MQTT_PROXY_PASSWORD:
	case EVP_CONFIG_MQTT_MFS_QOS:
	case EVP_CONFIG_HTTP_PROXY_HOST:
	case EVP_CONFIG_HTTP_PROXY_PORT:
	case EVP_CONFIG_HTTP_PROXY_USERNAME:
	case EVP_CONFIG_HTTP_PROXY_PASSWORD:
	case EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY:
	case EVP_CONFIG_TRANSPORT_QUEUE_LIMIT:
		return true;
	case EVP_CONFIG_PK_FILE:
	default:
		// TODO: Review exit (xlog_abort)
		//       programming error
		xlog_abort("Invalid state %d", (int)key);
	}
}

void
free_config(struct config *config)
{
	if (config != NULL) {
		if (config->free == NULL) {
			return;
		}

		if (config->key != EVP_CONFIG_PK_FILE) {
			config->free(__UNCONST(config->value));
		}

		config->free(config);
	}
}

/*
 * Retrieve the current Device Level Configuration setting
 */
static struct config *
get_config_dynamic(enum config_key key)
{
	char *s;
	struct config *cfg;
	struct device_config *devcfg = g_evp_global.devcfg;

	if (!devcfg)
		return NULL;

	switch (key) {
	case EVP_CONFIG_REGISTRY_AUTH:
		if (!devcfg->registry_auth)
			return NULL;
		s = xstrdup(devcfg->registry_auth);
		break;
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC:
		if (devcfg->interval_min == INVALID_TIME)
			return NULL;
		xasprintf(&s, "%d", devcfg->interval_min);
		break;
	case EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC:
		if (devcfg->interval_max == INVALID_TIME)
			return NULL;
		xasprintf(&s, "%d", devcfg->interval_max);
		break;
	case EVP_CONFIG_CONFIGURATION_ID:
		if (!devcfg->config_id)
			return NULL;
		s = xstrdup(devcfg->config_id);
		break;
	default:
		return NULL;
	}

	cfg = xmalloc(sizeof(*cfg));
	*cfg = (struct config){
		.value = s, .key = key, .size = strlen(s) + 1, .free = free};

	return cfg;
}

struct config *
get_config(enum config_key key)
{
	struct config *value;
	value = get_config_dynamic(key);
	if (value == NULL)
		value = get_config_impl(key);
	return value;
}

char *
config_get_string(enum config_key key)
{
	struct config *cfg;
	void *vp;
	size_t sz;
	int rv;
	char *val;
	cfg = get_config(key);
	if (cfg == NULL) {
		return NULL;
	}
	rv = load_config(cfg, &vp, &sz);
	if (rv) {
		xlog_error("Failed to load config %d", (int)cfg->key);
		free_config(cfg);
		return NULL;
	}
	// TODO: Replace assert (programming error)
	assert(strlen(vp) + 1 == sz);
	val = xstrdup(vp);
	free_config(cfg);
	return val;
}

int
config_get_int(enum config_key key, intmax_t *value)
{
	struct config *cfg;
	void *vp;
	size_t sz;
	int rv;

	rv = EINVAL;
	cfg = get_config(key);
	if (cfg != NULL) {
		rv = load_config(cfg, &vp, &sz);
		if (rv == 0) {
			rv = string_to_int(vp, value);
		}
		free_config(cfg);
	}

	if (rv != 0) {
		// provide compile-time default number values
		// for some settings
		switch (key) {
		case EVP_CONFIG_REPORT_STATUS_INTERVAL_MIN_SEC:
			*value = MIN_REPORT_INTERVAL_SEC;
			rv = 0;
			break;
		case EVP_CONFIG_REPORT_STATUS_INTERVAL_MAX_SEC:
			*value = MAX_REPORT_INTERVAL_SEC;
			rv = 0;
			break;
		case EVP_CONFIG_MQTT_MFS_QOS:
			*value = DEFAULT_MQTT_MFS_QOS;
			rv = 0;
			break;
		case EVP_CONFIG_TRANSPORT_QUEUE_LIMIT:
			*value = DEFAULT_TRANSPORT_QUEUE_LIMIT;
			rv = 0;
			break;
		default:
			break;
		}
	}

	return rv;
}
