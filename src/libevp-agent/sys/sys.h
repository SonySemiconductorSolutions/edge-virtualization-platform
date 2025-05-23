/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SYS_H_
#define SYS_H_

#include <stdbool.h>
#include <stddef.h>

#include <evp/sdk_sys.h>

#include "../instance_config.h"

struct string_map;
struct chan;

struct sys_config {
	struct SYS_client *c;
	SYS_config_cb cb;
	enum SYS_type_configuration type;
	void *user;
	bool persist_read;
	struct sys_config *next;
};

struct sys_command {
	struct SYS_client *c;
	char *command;
	SYS_command_cb fn;
	void *user;
};

struct sys_telemetry {
	struct SYS_client *c;
	char *topic, *value;
	SYS_telemetry_cb cb;
	void *user;
	struct sys_telemetry *next;
};

struct sys_group {
	struct string_map *cfg_map;
	struct string_map *ddc_map;
	struct string_map *state_map;
	struct chan *ch;
	/* Doubly-linked circular list. */
	struct SYS_client *list;
	struct sys_telemetry *telemetries;
};

struct sys_response {
	struct SYS_client *c;
	SYS_response_id id;
	char *response;
	enum SYS_response_status status;
	SYS_response_cb cb;
	void *user;
	enum SYS_callback_reason reason;
	struct sys_response *next;
};

struct SYS_client {
	struct EVP_client *h;
	struct sys_group *gr;
	struct chan *ch;
	/* Doubly-linked circular list. */
	struct SYS_client *prev, *next;
	/* Singly-linked list. */
	struct sys_response *resp_head, *resp_tail;
};

struct sys_group *sys_group_alloc(void);
void sys_group_dealloc(struct sys_group *gr);

int sys_notify_config(struct sys_group *gr, int type, const char *topic,
		      const char *value);
int sys_notify_ddc(struct sys_group *gr, const char *method,
		   const char *params, SYS_response_id id);

void sys_config_dealloc(void *cfg);
void sys_ddc_dealloc(void *ddc);
void sys_state_dealloc(void *state);
void sys_telemetry_dealloc(struct sys_telemetry *t);

struct SYS_client *sys_client_alloc(struct sys_group *gr);
void sys_client_dealloc(struct SYS_client *cl);

struct SYS_client *sys_register(struct sys_group *gr);
int sys_unregister(struct sys_group *gr, struct SYS_client *cl);

int sys_collect_states(struct sys_group *gr,
		       void (*fn)(const char *, const char *, const void *,
				  size_t, void *),
		       void *user);

typedef int (*sys_collect_cb)(SYS_response_id id, const char *resp,
			      enum SYS_response_status status, void *user);

typedef int (*sys_telemetry_collect)(const char *key,
				     const struct sys_telemetry *value,
				     void *user);

int sys_collect_telemetry(struct sys_group *gr, sys_telemetry_collect cb,
			  void *user);
int sys_process_events(struct sys_group *gr);
int sys_collect_responses(struct sys_group *gr, sys_collect_cb cb, void *user);

bool sys_is_sysapp(const char *name);

extern const char *const sys_prefix;

#endif
