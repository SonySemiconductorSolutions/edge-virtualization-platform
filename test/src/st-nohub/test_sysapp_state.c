/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "../sync.h"
#include "agent_test.h"
#include "evp/agent.h"
#include "hub.h"
#include "mqtt_custom.h"
#include "sys/sys.h"

#define EXPECTED_KEY_1   "key-1"
#define EXPECTED_VALUE_1 "value 1"
#define EXPECTED_KEY_2   "key-2"
#define EXPECTED_VALUE_2 "value 2"

static struct test {
	struct evp_agent_context *ctxt;
	struct SYS_client *app;
} test;

static void
make_state_str(char **s, const char *key, const char *value)
{
	assert(asprintf(s, "state/%s/%s: %s", sys_prefix, key, value) > 0);
}

static int
convert_state(JSON_Object *o, const char *name, const void *blob,
	      size_t bloblen)
{
	char *s;
	char *value = strndup(blob, bloblen);
	make_state_str(&s, name, blob);
	agent_write_to_pipe(s);
	free(value);
	free(s);
	return 0;
}

int
__wrap_hub_evp1_convert_state(JSON_Object *o, const char *name,
			      const void *blob, size_t bloblen)
{
	return convert_state(o, name, blob, bloblen);
}

int
__wrap_hub_evp2_convert_state(JSON_Object *o, const char *name,
			      const void *blob, size_t bloblen)
{
	return convert_state(o, name, blob, bloblen);
}

static void
test_sysapp_state(void **state)
{
	struct test *test = *state;
	char *s;

	assert_int_equal(
		SYS_set_state(test->app, EXPECTED_KEY_1, EXPECTED_VALUE_1),
		SYS_RESULT_OK);
	assert_int_equal(
		SYS_set_state(test->app, EXPECTED_KEY_2, EXPECTED_VALUE_2),
		SYS_RESULT_OK);

	make_state_str(&s, EXPECTED_KEY_1, EXPECTED_VALUE_1);
	agent_poll(verify_contains, s);
	free(s);

	make_state_str(&s, EXPECTED_KEY_2, EXPECTED_VALUE_2);
	agent_poll(verify_contains, s);
	free(s);
}

static int
setup(void **state)
{
	agent_test_setup();

	test.ctxt = agent_test_start();
	test.app = evp_agent_register_sys_client(test.ctxt);

	if (!test.app) {
		fprintf(stderr, "%s: evp_agent_register_sys_client failed\n",
			__func__);
		return -1;
	}

	*state = &test;
	return 0;
}

static int
teardown(void **state)
{
	struct test *test = *state;

	if (evp_agent_unregister_sys_client(test->ctxt, test->app)) {
		fprintf(stderr, "%s: evp_agent_unregister_sys_client failed\n",
			__func__);
	}

	agent_test_exit();
	return 0;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sysapp_state),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
