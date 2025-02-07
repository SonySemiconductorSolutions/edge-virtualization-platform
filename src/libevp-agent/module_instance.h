/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MODULE_INSTANCE_H
#define MODULE_INSTANCE_H

#include <stddef.h>

#include <evp/sdk_types.h>
#include <parson.h>

struct InstanceSpecs;
struct module_instance;
struct evp_hub_context;

int module_instance_init(void);
void module_instance_deinit(void);
int module_instance_stop(const struct InstanceSpecs *);
int module_instance_start(const JSON_Value *deployment,
			  const struct evp_hub_context *hub,
			  const struct InstanceSpecs *list);
int module_instance_create(const struct InstanceSpecs *);

struct ModuleInstanceSpec;
int module_instance_start1(const struct ModuleInstanceSpec *,
			   struct module_instance **);
int module_instance_stop1(struct module_instance *);

JSON_Value *module_instance_get_json_value_evp1(void);
JSON_Value *module_instance_get_json_value_evp2(void);

enum notify_type {
	NOTIFY_CONFIG = 1,
	NOTIFY_STATE = 2,
	NOTIFY_MESSAGE = 3,
	NOTIFY_RPC_REQUEST = 4,
};

void module_instance_notify(enum notify_type type,
			    const char *module_instance_name,
			    size_t module_instance_name_len, EVP_RPC_ID id,
			    const char *topic, const void *blob,
			    size_t bloblen);

struct sdk_event_message_sent;
void module_instance_message_forward(struct sdk_event_message_sent *msg);
void module_instance_message_send(struct module_instance *m,
				  struct sdk_event_message_sent *msg);

struct module_instance *get_module_instance_by_name(const char *);
void gc_module_instance_dir(void);

int module_instance_convert_path(struct module_instance *m,
				 const char *path_in_module_instance,
				 char **resultp);

const struct Stream *
module_instance_stream_from_name(const struct module_instance *m,
				 const char *name);

#endif /* MODULE_INSTANCE_H */
