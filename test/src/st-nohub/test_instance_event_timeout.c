/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agent_test.h"
#include "blob.h"
#include "evp/sdk.h"
#include "module_instance_impl.h"
#include "mqtt_custom.h"
#include "xlog.h"

struct test_args {
	struct evp_agent_context *agent;
	struct EVP_client *h;
};

/*
 * The goal of ths test is check that the EVP_processEvent call waits for the
 * specific tiemout an returns EVP_TIMEDOUT if there is not any event to
 * process
 */
void
test_instance_timeout(void **state)
{
	struct test_args *args = *state;
	struct timespec before, after;

	assert_int_equal(clock_gettime(CLOCK_REALTIME, &before), 0);
	EVP_RESULT res = EVP_processEvent(args->h, 3000);
	assert_int_equal(res, EVP_TIMEDOUT);
	assert_int_equal(clock_gettime(CLOCK_REALTIME, &after), 0);
	assert_in_range(after.tv_sec, before.tv_sec + 2, before.tv_sec + 3);
}

static int
teardown(void **state)
{
	struct test_args *args = *state;

	if (args) {
		agent_test_exit();
		free(args);
	}

	return 0;
}

static int
setup(void **state)
{
	struct test_args *args = malloc(sizeof(*args));

	*state = args;

	if (!args)
		goto failure;

	putenv("EVP_IOT_PLATFORM=tb");
	agent_test_setup();

	if (!(args->agent = agent_test_start()))
		goto failure;
	else if (!(args->h = evp_agent_add_instance(args->agent, "test")))
		goto failure;

	return 0;

failure:
	teardown(state);
	return -1;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_instance_timeout),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
