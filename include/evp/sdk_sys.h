/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SDK_SYS_H
#define SDK_SYS_H

#include <stddef.h>

typedef unsigned long long SYS_response_id;

enum SYS_result {
	SYS_RESULT_OK,
	SYS_RESULT_TIMEDOUT,
	SYS_RESULT_ERRNO,
	SYS_RESULT_SHOULD_EXIT,
	SYS_RESULT_ERROR_NO_MEM,
	SYS_RESULT_ERROR_BAD_PARAMS,
	SYS_RESULT_ERROR_ALREADY_REGISTERED,
};

enum SYS_callback_reason {
	SYS_REASON_FINISHED,
	SYS_REASON_MORE_DATA,
	SYS_REASON_TIMEOUT,
	SYS_REASON_ERROR,
};

enum SYS_type_configuration {
	SYS_CONFIG_PERSIST,
	SYS_CONFIG_HUB,
	SYS_CONFIG_ANY,
};

enum SYS_response_status {
	SYS_RESPONSE_STATUS_OK,
	SYS_RESPONSE_STATUS_METHOD_NOT_FOUND,
	SYS_RESPONSE_STATUS_ERROR,
};

struct SYS_client;

struct SYS_blob_data {
	const char *method;
	const char *url;
	const char *response_headers;
	void *blob_buffer;
	int error;
	int status_code;
	size_t len;
};

struct SYS_http_header {
	const char *key;
	const char *value;
};

typedef void (*SYS_config_cb)(struct SYS_client *c, const char *topic,
			      const char *value,
			      enum SYS_type_configuration type,
			      enum SYS_callback_reason reason, void *user);

typedef enum SYS_result (*SYS_blob_cb)(struct SYS_client *c,
				       struct SYS_blob_data *blob,
				       enum SYS_callback_reason reason,
				       void *user);

enum SYS_result SYS_get_blob(struct SYS_client *c, const char *url,
			     const struct SYS_http_header *headers,
			     SYS_blob_cb cb, void *user);

enum SYS_result SYS_put_blob(struct SYS_client *c, const char *url,
			     const struct SYS_http_header *headers,
			     unsigned long long datalen, SYS_blob_cb cb,
			     void *user);

enum SYS_result SYS_put_blob_mstp(struct SYS_client *c,
				  const char *storage_name,
				  const char *filename,
				  unsigned long long datalen, SYS_blob_cb cb,
				  void *user);

enum SYS_result SYS_set_configuration_cb(struct SYS_client *c,
					 const char *topic, SYS_config_cb cb,
					 enum SYS_type_configuration type,
					 void *user);

typedef void (*SYS_telemetry_cb)(struct SYS_client *c,
				 enum SYS_callback_reason reason, void *user);

enum SYS_result SYS_send_telemetry(struct SYS_client *c, const char *topic,
				   const char *value, SYS_telemetry_cb cb,
				   void *user);

typedef void (*SYS_command_cb)(struct SYS_client *c, SYS_response_id id,
			       const char *body, void *user);

enum SYS_result SYS_register_command_cb(struct SYS_client *c,
					const char *command, SYS_command_cb cb,
					void *user);

typedef void (*SYS_response_cb)(struct SYS_client *c,
				enum SYS_callback_reason reason, void *user);

enum SYS_result SYS_set_response_cb(struct SYS_client *c, SYS_response_id id,
				    const char *response,
				    enum SYS_response_status status,
				    SYS_response_cb cb, void *user);

enum SYS_result SYS_set_state(struct SYS_client *c, const char *key,
			      const char *value);

enum SYS_result SYS_process_event(struct SYS_client *c, int ms);
enum SYS_result SYS_notify_close(struct SYS_client *c);
const char *SYS_result_tostr(enum SYS_result r);
const char *SYS_reason_tostr(enum SYS_callback_reason r);

#endif
