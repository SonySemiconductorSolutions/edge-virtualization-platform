/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AGENT_TEST_H
#define AGENT_TEST_H

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <cmocka.h>
#include <evp/agent.h>

#include <internal/evp_config.h>

#include "evp_hub.h"

typedef bool (*agent_test_verify_t)(const char *data, const void *user_data,
				    va_list va);

struct multi_check {
	union {
		char *value_rw;
		const char *value;
	};
	bool found;
};

typedef struct expect_unexpect {
	const char *expect;
	const char *unexpect;
} expect_unexpect_t;

struct test_instance_config {
	char *key;
	char *config_key;
	char *state_key;
	char *value_noenc;
	char *value;
};

typedef int (*evp_agent_loop_fn_t)(struct evp_agent_context *ctxt);

typedef int (*popen_parser_t)(FILE *fp, void *user);

enum message_log_level {
	MESSAGE_LOG_INFO,
	MESSAGE_LOG_ERROR,
};

#define message_info(...)                                                     \
	message_log(MESSAGE_LOG_INFO, __func__, __FILE__, __LINE__,           \
		    __VA_ARGS__)
#define message_error(...)                                                    \
	message_log(MESSAGE_LOG_ERROR, __func__, __FILE__, __LINE__,          \
		    __VA_ARGS__)

void message_log(enum message_log_level level, const char *func,
		 const char *file, int line, const char *fmt, ...);

int vpopenf(popen_parser_t parser, void *user, const char *fmt, va_list va);
int popenf(popen_parser_t parser, void *user, const char *fmt, ...);

int popen_parse_int(FILE *fp, void *user);
int popen_strcpy(FILE *fp, void *user);

/**
 * Execute a printf-like formatted command
 */
int systemf(const char *fmt, ...);

/**
 * Create a configuration value
 * This creates a formatted configuration value.
 * The value will be encoded to the configured encoding
 * according to the hub type (EVP1 or TB).
 */
int vasconfigf(char **pvalue, const char *fmt, va_list va);
int asconfigf(char **pvalue, const char *fmt, ...);

/**
 * Create instance configuration pair object with the automatic
 * conversion to b64 for EVP1.
 */
struct test_instance_config *test_instance_config_create(const char *id,
							 const char *topic,
							 const char *fmt, ...);

void test_instance_config_free(struct test_instance_config *config);

JSON_Object *object_create(const char *in);
char *object_serialize(JSON_Object *o);
void object_free(JSON_Object *o);
int object_add_instance_config(JSON_Object *o,
			       struct test_instance_config *config);

/*
 * Helper functions to craft manifests
 */

/**
 * Create an initial empty manifest object
 *
 * @param manifest_in: a potential manifest string input used to initialize the
 * object. If set to NULL, creates an empty object.
 */
JSON_Object *manifest_create(const char *manifest_in,
			     const char *deployment_id);

JSON_Object *manifest_add_instance_spec(JSON_Object *o, const char *instance,
					const char *module, const char *ep,
					int version);

JSON_Object *manifest_add_module_spec(JSON_Object *o, const char *instance,
				      const char *impl, const char *hash,
				      const char *url, const char *ep);

/**
 * Convert manifest deployment attribute to the current schema version:
 *
 *     { "deployment": <DEPLOYMENT> }
 *
 * Where DEPLOYMENT is the message payload as JSON object (EVP2) or serialized
 * string (EVP1)
 */
void manifest_finalize(JSON_Object *o);

/**
 * Serialize manifest into a payload string
 *
 * @param o: JSON object
 *
 * @return A stsdup-ed string of serialized deployment attribute
 */
char *manifest_serialize_deployment(JSON_Object *o);

/**
 * Utility function to validate a json string following a language
 * similar to printf strings
 */
bool verify_json(const char *text, const void *user_data, va_list va);

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that there is a data item with identical string value.
 * Ignores non-matching items.
 */
bool verify_equals(const char *data, const void *user_data, va_list va);

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that there is a data item with matching substring value.
 * Ignores non-matching items.
 */
bool verify_contains(const char *data, const void *user_data, va_list va);

/**
 * Utility callback function to verify agent_poll() data.
 * Checkt that data contains expect and not contains unexpect values
 *
 * @param data pointer to string to check
 * @param user_data user_data is a type expect_unexpect_t
 */
bool verify_contains_except(const char *data, const void *user_data,
			    va_list va);

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that all items in set are contained in data wichever the order.
 * Ignores non-matching items.
 */
bool verify_contains_in_unordered_set(const char *data, const void *user_data,
				      va_list va);

/**
 * Utility callback function to verify agent_poll() data.
 * Verifies data with cmocka check_expected().
 * To use, call cmocka expect_...(verify_expected, data, ...) before invoking
 * agent_poll().
 * Fails on non-matching items.
 */
bool verify_expected(const char *data, const void *user_data, va_list va);

bool get_connected(void);

void set_connected(bool connect);

int agent_test_call_count(int inc);

/**
 * Initializes a text file in instance workspace directory
 * Ensure workspace directory is created and create a file from the output of
 * `command`
 */
void agent_init_instance_workspace_file(const char *instance_id,
					const char *filename,
					const char *command);
/**
 * Configure environment for running an EVP Agent system test
 */
void agent_test_setup(void);

/**
 * Override the agent loop function
 */
void agent_set_loop_function(evp_agent_loop_fn_t loop_fun);

/**
 * Get a valid evp_hub_type from environment
 *
 * @return A valid evp_hub_type. In case off error an assert is raised
 */
const enum evp_hub_type agent_test_get_hub_type(void);

/**
 * Configure agent test with offline hub mode
 */
void agent_test_enable_capture_mode(void);

/**
 * Instantiate an EVP Agent and run it in its own thread.
 * agent_test_start() also creates a pipe that can be used to collect and poll
 * for test data. The Agent thread is exited by calling agent_test_exit().
 */
struct evp_agent_context *agent_test_start(void);

/**
 * Stop the agent thread
 */
void agent_test_exit(void);

/**
 * Write to test data pipe.
 * Usually invoked from a callback that may be called from a separate thread
 * from the test.
 */
void agent_write_to_pipe(const char *data);

/**
 * Wait for data to arrive in test data pipe, and validate with callback
 * function.
 * @param[in] verify_callback user provided function to validate test data
 * @param[in] user_data provided to verify_callback along with test data
 */
void agent_poll(agent_test_verify_t verify_callback, const void *user_data,
		...);

void agent_register_payload(unsigned int id, enum evp_hub_type hub_type,
			    const char *payload);

const char *agent_get_payload(unsigned int id);

char *agent_get_payload_formatted(unsigned int id, ...);

/**
 * Send initial configuration response. This can include any combination of:
 * - deployment manifest
 * - device configuration
 * - module instance configuration
 */
void agent_send_initial(struct evp_agent_context *ctxt, const char *deployment,
			const char *device_config,
			const char *instance_config);

/**
 * Send a deployment manifest payload with the configured hub envelope
 */
void agent_send_deployment(struct evp_agent_context *ctxt,
			   const char *payload);

/**
 * Send a module instance config payload with the configured hub envelope
 */
void agent_send_instance_config(struct evp_agent_context *ctxt,
				const char *payload);

/**
 * Send a device config payload with the configured hub envelope
 */
void agent_send_device_config(struct evp_agent_context *ctxt,
			      const char *payload);

/**
 * Send a direct command request payload with the configured hub envelope
 */
void agent_send_direct_command_req(struct evp_agent_context *ctxt,
				   const char *payload,
				   EVP_RPC_ID mqtt_request_id);

/**
 * Send a storage token response payload with the configured hub envelope
 */
void agent_send_storagetoken_response(struct evp_agent_context *ctxt,
				      const char *payload,
				      const char *evp1_topic_reqid);

/**
 * Wait maximum timeout seconds for the agent to reach the given status
 */
void agent_poll_status(struct evp_agent_context *ctxt,
		       enum evp_agent_status status, int timeout);

struct agent_deployment {
	struct evp_agent_context *ctxt;
	bool init;
};

void agent_ensure_deployment_status(const char *id, const char *status);
void agent_ensure_instance_status(const char *id, const char *status);

void agent_ensure_deployment(struct agent_deployment *d, const char *payload,
			     const char *deploymentId);

void agent_ensure_deployment_config(struct agent_deployment *d,
				    const char *payload,
				    const char *deploymentId,
				    const char *instance_config);

#endif // AGENT_TEST_H
