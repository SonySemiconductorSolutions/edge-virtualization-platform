/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"

enum { SERVICE };

#define REQID    0
#define METHOD   "test-method"
#define KEY      "param1"
#define VALUE    "input1"
#define RESPONSE "{\"response\": \"awesome!\"}"
#define BODY     "{\\\"" KEY "\\\": \\\"" VALUE "\\\"}"

#define EVP1_SERVICE                                                          \
	"{"                                                                   \
	"\"method\": \"ModuleMethodCall\","                                   \
	"\"params\": {"                                                       \
	"    \"moduleInstance\": \"$system\","                                \
	"    \"moduleMethod\": \"" METHOD "\","                               \
	"    \"params\": \"" BODY "\"}"                                       \
	"}"

#define EVP2_SERVICE                                                          \
	"{"                                                                   \
	"\"direct-command-request\": {"                                       \
	"    \"reqid\": \"" ___STRING(REQID) "\","                            \
					     "    \"method\": \"" METHOD      \
					     "\","                            \
					     "    \"instance\": \"$system\"," \
					     "    \"params\": \"" BODY "\"}"  \
					     "}"

struct test {
	struct evp_agent_context *ctxt;
	pthread_t thread;
	sem_t sem;
	enum SYS_result result;
};

static int user_dummy;

static void
service_evp1(struct SYS_client *c, SYS_response_id id, const char *body)
{
	/* CMocka functions cannot be called from other threads. */
	assert(!strcmp(body, "\"" BODY "\""));
}

static void
service_evp2(struct SYS_client *c, SYS_response_id id, const char *body)
{
	JSON_Value *v = json_parse_string(body);
	const JSON_Object *o;
	const char *value;

	/* CMocka functions cannot be called from other threads. */
	assert(v);
	o = json_value_get_object(v);
	assert(o);
	value = json_object_get_string(o, KEY);
	assert(value);
	assert(!strcmp(value, VALUE));
	json_value_free(v);
}

static void
response_cb(struct SYS_client *c, enum SYS_callback_reason reason, void *user)
{
	/* CMocka functions cannot be called from other threads. */
	assert(reason == SYS_REASON_FINISHED);
	assert(user == &user_dummy);
}

static void
service_cb(struct SYS_client *c, SYS_response_id id, const char *body,
	   void *user)
{
	enum SYS_result result;

	switch (agent_test_get_hub_type()) {
	case EVP_HUB_TYPE_EVP1_TB:
		service_evp1(c, id, body);
		break;
	case EVP_HUB_TYPE_EVP2_TB:
		service_evp2(c, id, body);
		break;
	case EVP_HUB_TYPE_UNKNOWN:
		abort();
		break;
	}

	result = SYS_set_response_cb(c, id, RESPONSE, SYS_RESPONSE_STATUS_OK,
				     response_cb, &user_dummy);

	assert(result == SYS_RESULT_OK);
	assert(user == &user_dummy);
}

static void *
sysapp(void *args)
{
	struct test *test = args;
	struct evp_agent_context *ctxt = test->ctxt;
	sem_t *sem = &test->sem;
	struct SYS_client *c = evp_agent_register_sys_client(ctxt);
	enum SYS_result *result = &test->result;

	if (!c) {
		fprintf(stderr, "%s: evp_agent_register_sys_client failed\n",
			__func__);
		*result = SYS_RESULT_ERROR_NO_MEM;
		return NULL;
	}

	*result = SYS_register_command_cb(c, METHOD, service_cb, &user_dummy);

	if (*result != SYS_RESULT_OK) {
		fprintf(stderr, "%s: SYS_register_command_cb failed\n",
			__func__);
		goto end;
	}

	/* Notify test_sysapp_command. */
	if (sem_post(sem)) {
		*result = SYS_RESULT_ERRNO;
		fprintf(stderr, "%s: sem_post(3): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	*result = SYS_process_event(c, -1);

	if (*result) {
		fprintf(stderr, "%s: SYS_process_event failed with %s\n",
			__func__, SYS_result_tostr(*result));
		goto end;
	}

	*result = SYS_process_event(c, -1);

	if (*result) {
		fprintf(stderr, "%s: SYS_process_event failed with %s\n",
			__func__, SYS_result_tostr(*result));
		goto end;
	}

end:

	if (evp_agent_unregister_sys_client(ctxt, c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sys_client failed\n",
			__func__);
	}

	return NULL;
}

static void
test_sysapp_command(void **state)
{
	struct test *test = *state;
	struct evp_agent_context *ctxt = test->ctxt;

	/* Wait for SYS_register_command_cb. */
	assert_int_equal(sem_wait(&test->sem), 0);
	agent_send_direct_command_req(ctxt, agent_get_payload(SERVICE), REQID);
	assert_int_equal(pthread_join(test->thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

static int
setup(void **state)
{
	static struct test test;
	int error;

	if (sem_init(&test.sem, 0, 0)) {
		fprintf(stderr, "%s: sem_init(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	agent_test_setup();
	test.ctxt = agent_test_start();

	if (!test.ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	error = pthread_create(&test.thread, NULL, sysapp, &test);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	agent_register_payload(SERVICE, EVP_HUB_TYPE_EVP1_TB, EVP1_SERVICE);
	agent_register_payload(SERVICE, EVP_HUB_TYPE_EVP2_TB, EVP2_SERVICE);

	*state = &test;
	return 0;
}

static int
teardown(void **state)
{
	struct test *test = *state;

	if (sem_destroy(&test->sem)) {
		fprintf(stderr, "%s: sem_destroy(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	agent_test_exit();
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sysapp_command),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
