/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef INSTANCE_CONFIG_H
#define INSTANCE_CONFIG_H

#include <parson.h>

enum config_type {
	EVP_CONFIG_HUB,
	EVP_CONFIG_PERSIST,
};

struct instance_config {
	char *instance;
	char *name;
	char *value;
};

struct instance_config_req {
	int delete;
	char *instance;
	char *name;
	char *value;
};

struct instance_config_reqs {
	int nreqs;
	struct instance_config_req *reqs;
};

struct evp_agent_context;

void instance_config_ctor(struct instance_config *cp, const char *instance,
			  const char *name, const char *value);
void instance_config_reqs_dtor(struct instance_config_reqs *req);
void instance_config_dtor(struct instance_config *cp);

int hub_evp1_parse_instance_config(JSON_Value *payload,
				   struct instance_config_reqs *reqs);
int hub_evp2_parse_instance_config(JSON_Value *payload,
				   struct instance_config_reqs *reqs);

int hub_evp1_notify_config(const char *instance, const char *name,
			   const char *value);
int hub_evp2_notify_config(const char *instance, const char *name,
			   const char *value);

/**
 * Apply business logic to module instance configuration requests received from
 * the hub
 */
void evp_process_instance_config(struct evp_agent_context *agent,
				 struct instance_config_reqs *reqs,
				 enum config_type type);

void process_config(struct evp_agent_context *agent);

#endif
