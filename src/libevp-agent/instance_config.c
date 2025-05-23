/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>
#include <parson.h>

#include <internal/string_map.h>
#include <internal/util.h>

#include "agent_internal.h"
#include "base64.h"
#include "global.h"
#include "hub.h"
#include "instance_config.h"
#include "map.h"
#include "module_instance.h"
#include "persist.h"
#include "sys/sys.h"
#include "xlog.h"

static const char prefix[] = "configuration/";

void
instance_config_ctor(struct instance_config *cp, const char *instance,
		     const char *name, const char *value)
{
	*cp = (struct instance_config){
		.instance = xstrdup(instance),
		.name = xstrdup(name),
		.value = xstrdup(value),
	};
}

void
instance_config_reqs_dtor(struct instance_config_reqs *reqs)
{
	struct instance_config_req *bp, *lim;

	if (reqs->nreqs == 0)
		return;
	lim = &reqs->reqs[reqs->nreqs];
	for (bp = reqs->reqs; bp < lim; ++bp) {
		free(bp->instance);
		free(bp->name);
		free(bp->value);
	}
	free(reqs->reqs);
}

void
instance_config_dtor(struct instance_config *cp)
{
	free(cp->instance);
	free(cp->name);
	free(cp->value);
}

static void
update_desired_instance_config(struct instance_config_req *req)
{
	char *name;
	JSON_Object *desired;
	JSON_Status st;

	desired = json_value_get_object(g_evp_global.desired);
	if (!desired) {
		xlog_error("Corrupted desired object");
		return;
	}

	xasprintf(&name, "configuration/%s/%s", req->instance, req->name);
	if (req->delete) {
		st = json_object_remove(desired, name);
	} else {
		st = json_object_set_string(desired, name, req->value);
	}

	if (st != JSONSuccess) {
		xlog_error("%s: error updating module instance config",
			   __func__);
	}

	free(name);
}

static int
hub_evp1_new_instance_config_req(const char *name, const char *value,
				 int delete, struct instance_config_reqs *reqs)
{
	const char *p, *q;
	size_t size;
	struct instance_config_req *req;

	p = name + sizeof("configuration/") - 1;
	q = strchr(p, '/');
	if (!q) {
		return -1;
	}

	reqs->nreqs++;
	size = reqs->nreqs * sizeof(*reqs->reqs);
	reqs->reqs = xrealloc(reqs->reqs, size);

	req = &reqs->reqs[reqs->nreqs - 1];
	req->instance = xstrndup(p, q - p);
	req->name = xstrdup(q + 1);
	req->value = (value) ? xstrdup(value) : NULL;
	req->delete = delete;

	return 0;
}

static int
hub_evp1_del_instance_config_req(JSON_Value *value,
				 struct instance_config_reqs *reqs)
{
	JSON_Array *ary;
	size_t i, sz;

	ary = json_value_get_array(value);
	if (!ary) {
		xlog_error("%s: invalid json", __func__);
		return -1;
	}

	sz = json_array_get_count(ary);
	for (i = 0; i < sz; ++i) {
		const char *name = json_array_get_string(ary, i);

		if (hub_evp1_new_instance_config_req(name, NULL, 1, reqs) <
		    0) {
			return -1;
		}
	}

	return 0;
}

static int
hub_evp1_add_instance_config_req(const char *name, JSON_Value *value,
				 struct instance_config_reqs *reqs)
{
	const char *s;

	s = json_value_get_string(value);
	if (!s) {
		xlog_error("%s: invalid json", __func__);
		return -1;
	}

	return hub_evp1_new_instance_config_req(name, s, 0, reqs);
}

int
hub_evp1_parse_instance_config(JSON_Value *payload,
			       struct instance_config_reqs *reqs)
{
	JSON_Object *o;
	size_t sz, i;

	*reqs = (struct instance_config_reqs){0};

	o = json_value_get_object(payload);
	if (!o) {
		return -1;
	}

	sz = json_object_get_count(o);
	for (i = 0; i < sz; i++) {
		const char *name = json_object_get_name(o, i);
		JSON_Value *value = json_object_get_value_at(o, i);

		if (strcmp(name, "deleted") == 0) {
			if (hub_evp1_del_instance_config_req(value, reqs) < 0)
				goto error;
			continue;
		}

		if (strncmp(name, prefix, sizeof(prefix) - 1) == 0) {
			if (hub_evp1_add_instance_config_req(name, value,
							     reqs) < 0)
				goto error;
			continue;
		}
	}

	if (reqs->nreqs != 0) {
		return 0;
	}

error:
	instance_config_reqs_dtor(reqs);
	return -1;
}

/* These evp2 functions are currently doing the same of the evp1
 * variants, however we want to keep this, as the parsing and
 * generation of instance_config will be changed in the future */
static int
hub_evp2_new_instance_config_req(const char *name, const char *value,
				 int delete, struct instance_config_reqs *reqs)
{
	const char *p, *q;
	size_t size;
	struct instance_config_req *req;

	p = name + sizeof("configuration/") - 1;
	q = strchr(p, '/');
	if (!q) {
		return -1;
	}

	reqs->nreqs++;
	size = reqs->nreqs * sizeof(*reqs->reqs);
	reqs->reqs = xrealloc(reqs->reqs, size);

	req = &reqs->reqs[reqs->nreqs - 1];
	req->instance = xstrndup(p, q - p);
	req->name = xstrdup(q + 1);
	req->value = (value) ? xstrdup(value) : NULL;
	req->delete = delete;

	return 0;
}

static int
hub_evp2_del_instance_config_req(JSON_Value *value,
				 struct instance_config_reqs *reqs)
{
	JSON_Array *ary;
	size_t i, sz;

	ary = json_value_get_array(value);
	if (!ary) {
		xlog_error("%s: invalid json", __func__);
		return -1;
	}

	sz = json_array_get_count(ary);
	for (i = 0; i < sz; ++i) {
		const char *name = json_array_get_string(ary, i);

		if (hub_evp2_new_instance_config_req(name, NULL, 1, reqs) < 0)
			return -1;
	}

	return 0;
}

static int
hub_evp2_add_instance_config_req(const char *name, JSON_Value *value,
				 struct instance_config_reqs *reqs)
{
	const char *s;

	s = json_value_get_string(value);
	if (!s) {
		xlog_error("%s: invalid json", __func__);
		return -1;
	}

	return hub_evp2_new_instance_config_req(name, s, 0, reqs);
}

int
hub_evp2_parse_instance_config(JSON_Value *payload,
			       struct instance_config_reqs *reqs)
{
	JSON_Object *o;
	size_t sz, i;

	*reqs = (struct instance_config_reqs){0};

	o = json_value_get_object(payload);
	if (!o) {
		return -1;
	}

	sz = json_object_get_count(o);
	for (i = 0; i < sz; i++) {
		const char *name = json_object_get_name(o, i);
		JSON_Value *value = json_object_get_value_at(o, i);

		if (strcmp(name, "deleted") == 0) {
			if (hub_evp2_del_instance_config_req(value, reqs) < 0)
				goto error;
			continue;
		}

		if (strncmp(name, prefix, sizeof(prefix) - 1) == 0) {
			if (hub_evp2_add_instance_config_req(name, value,
							     reqs) < 0)
				goto error;
			continue;
		}
	}

	if (reqs->nreqs != 0) {
		return 0;
	}

error:
	instance_config_reqs_dtor(reqs);
	return -1;
}

int
hub_evp1_notify_config(const char *instance, const char *name,
		       const char *value)
{
	void *blob;
	size_t bloblen;
	int ret;

	ret = base64_decode(value, strlen(value), &blob, &bloblen);
	if (ret != 0) {
		xlog_error("%s: error decoding base64", __func__);
		return ret;
	}
	/* Note: module_instance_notify frees blob */
	module_instance_notify(NOTIFY_CONFIG, instance, strlen(instance), 0,
			       name, blob, bloblen);
	return 0;
}

int
hub_evp2_notify_config(const char *instance, const char *name,
		       const char *value)
{
	const void *blob = strdup(value);
	if (!blob) {
		xlog_error("%s: strdup error", __func__);
		return -1;
	}
	size_t bloblen = strlen(value);
	/* Note: module_instance_notify frees blob */
	module_instance_notify(NOTIFY_CONFIG, instance, strlen(instance), 0,
			       name, blob, bloblen);
	return 0;
}

struct sysapp_config {
	const struct evp_agent_context *agent;
	const struct instance_config *cfg;
};

static int
process_sysapp_config(const char *topic, void *value, void *user)
{
	const struct sysapp_config *syscfg = user;
	const struct evp_agent_context *agent = syscfg->agent;
	const struct instance_config *icfg = syscfg->cfg;
	struct sys_config *cfg = value;

	if (strcmp(topic, icfg->name)) {
		return 1;
	}

	if (cfg->type != SYS_CONFIG_PERSIST && cfg->type != SYS_CONFIG_ANY) {
		return 1;
	}

	if (cfg->persist_read) {
		return 1;
	}

	if (sys_notify_config(agent->sys, EVP_CONFIG_PERSIST, topic,
			      icfg->value)) {
		return 0;
	}

	cfg->persist_read = true;
	return 1;
}

static int
process_config_helper(const void *key, const void *f)
{
	const struct evp_agent_context *agent = key;
	const struct instance_config *cfg = f;

	if (!strcmp(cfg->instance, sys_prefix)) {
		struct sysapp_config syscfg = {
			.agent = agent,
			.cfg = cfg,
		};

		string_map_forall(agent->sys->cfg_map, process_sysapp_config,
				  &syscfg);
	} else {
		agent->hub->notify_config(cfg->instance, cfg->name,
					  cfg->value);
	}
	return 1;
}

void
process_config(struct evp_agent_context *agent)
{
	if (!g_evp_global.instancecfg)
		return;

	map_foreach(g_evp_global.instancecfg, process_config_helper, agent);
}

static void
del_instance_config(struct instance_config_req *req)
{
	struct instance_config key, *p;
	struct map *map;

	update_desired_instance_config(req);

	map = g_evp_global.instancecfg;
	if (!map)
		return;

	key = (struct instance_config){
		.instance = req->instance,
		.name = req->name,
	};

	p = map_del(map, &key);
	if (p) {
		instance_config_dtor(p);
		free(p);
	}
}

static int
instance_config_eq(const void *f1, const void *f2)
{
	const struct instance_config *cfg1 = f1, *cfg2 = f2;

	if (strcmp(cfg1->instance, cfg2->instance) != 0)
		return -1;
	if (strcmp(cfg1->name, cfg2->name) != 0)
		return -1;

	return 0;
}

static void
add_instance_config(struct instance_config_req *req)
{
	struct instance_config key, *cfg, *p;
	struct map *map;

	update_desired_instance_config(req);

	map = g_evp_global.instancecfg;
	if (!map) {
		map = map_init(0, instance_config_eq, NULL);
		g_evp_global.instancecfg = map;
	}

	cfg = xmalloc(sizeof(*cfg));
	instance_config_ctor(cfg, req->instance, req->name, req->value);

	key = (struct instance_config){
		.instance = req->instance,
		.name = req->name,
	};

	p = map_put(map, &key, cfg);
	if (p) {
		instance_config_dtor(p);
		free(p);
	}
}

void
evp_process_instance_config(struct evp_agent_context *agent,
			    struct instance_config_reqs *reqs,
			    enum config_type type)
{
	struct instance_config_req *lim, *bp;

	if (reqs->nreqs == 0)
		return;

	lim = &reqs->reqs[reqs->nreqs];
	for (bp = reqs->reqs; bp < lim; ++bp) {
		if (bp->delete)
			del_instance_config(bp);
		else
			add_instance_config(bp);
	}

	save_desired(agent);

	for (bp = reqs->reqs; bp < lim; ++bp) {
		if (bp->delete)
			continue;

		if (sys_is_sysapp(bp->instance)) {
			sys_notify_config(agent->sys, type, bp->name,
					  bp->value);
		} else {
			agent->hub->notify_config(bp->instance, bp->name,
						  bp->value);
		}
	}

	dump_global();
}
