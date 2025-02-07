/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "notification.h"

#define TEST_VALUE 10

static struct args {
	int dummy;
} test_args;

static int
on_notification(const void *args, void *user_data)
{
	const int *data = user_data;

	assert_ptr_equal(args, &test_args);
	assert_int_equal(*data, TEST_VALUE);
	function_called();
	return 0;
}

static void
test_evp_notify(void **state)
{
	struct evp_agent_context *ctxt = *state;
	static const char event[] = "start";
	int data = TEST_VALUE;

	assert_int_equal(evp_agent_notification_subscribe(
				 ctxt, event, on_notification, &data),
			 0);
	expect_function_call(on_notification);
	assert_int_equal(
		evp_agent_notification_publish(ctxt, event, &test_args), 0);
}

static void
test_evp_notify_badevent(void **state)
{
	struct evp_agent_context *ctxt = *state;
	static const char event[] = "this-event-should-never-exist";
	int data = TEST_VALUE;

	assert_int_not_equal(evp_agent_notification_subscribe(
				     ctxt, event, on_notification, &data),
			     0);
}

static int
setup(void **state)
{
	struct evp_agent_context *ctxt = evp_agent_setup("test");

	*state = ctxt;
	return 0;
}

static int
teardown(void **state)
{
	struct evp_agent_context *ctxt = *state;

	evp_agent_free(ctxt);
	return 0;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_evp_notify),
		cmocka_unit_test(test_evp_notify_badevent),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
