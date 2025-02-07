/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "mqtt_custom.h"

void
test_systest(void **state)
{
	// start agent
	agent_test_start();

	// test polling with verify_equals
	agent_write_to_pipe("some data");
	agent_poll(verify_equals, "some data");

	// test polling with verify_contains
	agent_write_to_pipe("some data with a magic substring");
	agent_poll(verify_contains, "magic");

	// test polling with verify_expected
	agent_write_to_pipe("this is expected");
	expect_string(verify_expected, data, "this is expected");
	agent_poll(verify_expected, NULL);

	// test empty string
	agent_write_to_pipe("");
	agent_poll(verify_equals, "");

	// test padded data
	agent_write_to_pipe("padding");
	agent_write_to_pipe("other data");
	agent_write_to_pipe("padding");
	agent_write_to_pipe("padding");
	agent_poll(verify_equals, "other data");

	// test multiple data
	agent_write_to_pipe("some other data");
	agent_write_to_pipe("some more data");
	agent_poll(verify_equals, "some other data");
	agent_poll(verify_equals, "some more data");

	// test bigger string
	char *big = malloc(4096);
	memset(big, 'a', 4095);
	big[4095] = '\0';
	agent_write_to_pipe(big);
	agent_poll(verify_equals, big);

	// test bigger string with padding
	memset(big, 'b', 1235);
	agent_write_to_pipe("padding");
	agent_write_to_pipe("padding");
	agent_write_to_pipe(big);
	agent_write_to_pipe("padding");
	agent_write_to_pipe("padding");
	agent_poll(verify_equals, big);

	free(big);
}

int
setup(void **state)
{
	agent_test_setup();
	return 0;
}

int
teardown(void **state)
{
	agent_test_exit();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_systest),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
