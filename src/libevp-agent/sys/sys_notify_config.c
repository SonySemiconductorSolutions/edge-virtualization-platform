/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/chan.h>
#include <internal/string_map.h>

#include "../instance_config.h"
#include "../sdk_impl.h"
#include "../xlog.h"
#include "sys.h"

struct config_sys_closure {
	const struct sys_config *cfg;
	enum SYS_type_configuration type;
	char *topic, *value;
};

/*
 * call_config_cb receives a chan message asynchronously and
 * for that reason the caller has to allocate msg->param
 * before leaving sys_notify_config and it implies that is our
 * responsability to free the param received
 */
static void
call_config_cb(struct chan_msg *msg)
{
	struct config_sys_closure *cl = msg->param;
	const struct sys_config *cfg = cl->cfg;

	cfg->cb(cfg->c, cl->topic, cl->value, cl->type, SYS_REASON_FINISHED,
		cfg->user);
	free(cl->topic);
	free(cl->value);
	free(cl);
}

static enum SYS_type_configuration
trans_type(enum config_type type)
{
	if (type == EVP_CONFIG_HUB)
		return SYS_CONFIG_HUB;
	if (type == EVP_CONFIG_PERSIST)
		return SYS_CONFIG_PERSIST;
	return SYS_CONFIG_ANY;
}

static int
notify_sub(const struct sys_config *cfg, int type, const char *topic,
	   const char *value)
{
	char *valuedup = NULL, *topicdup = NULL;
	struct config_sys_closure *cl = NULL;
	enum SYS_type_configuration stype = trans_type(type);

	if (stype == SYS_CONFIG_ANY) {
		xlog_error("notify for invalid config_type %d", type);
		goto failure;
	}

	if (stype == SYS_CONFIG_PERSIST && cfg->persist_read) {
		return 0;
	}

	if (cfg->type != SYS_CONFIG_ANY && cfg->type != stype) {
		/* Subscriber is not interested in this configuration
		 * notification type. */
		return 0;
	}

	/* The message shall be sent asynchronously, so these must be
	 * duplicated.*/
	if ((topicdup = strdup(topic)) == NULL) {
		xlog_error("failed to duplicate topic");
		goto failure;
	}

	if ((valuedup = strdup(value)) == NULL) {
		xlog_error("failed to duplicate value");
		goto failure;
	}

	if ((cl = malloc(sizeof(*cl))) == NULL) {
		xlog_error("out of memory notifying '%s'", topic);
		goto failure;
	}

	*cl = (struct config_sys_closure){
		.cfg = cfg,
		.topic = topicdup,
		.value = valuedup,
		.type = stype,
	};

	struct chan_msg msg = {
		.fn = call_config_cb,
		.param = cl,
	};
	if (chan_send(cfg->c->ch, &msg) == 0) {
		xlog_error("out of memory delivering configuration '%s'",
			   topic);
		goto failure;
	}

	return 0;

failure:
	free(topicdup);
	free(valuedup);
	free(cl);
	return -1;
}

int
sys_notify_config(struct sys_group *gr, int type, const char *topic,
		  const char *value)
{
	const struct sys_config *cfg = string_map_lookup(gr->cfg_map, topic);
	if (!cfg) {
		xlog_info("notify for unknown system configuration '%s'",
			  topic);
		return -1;
	}

	for (; cfg; cfg = cfg->next) {
		if (notify_sub(cfg, type, topic, value)) {
			xlog_error("failed to notify config subscriber");
			return -1;
		}
	}

	return 0;
}
