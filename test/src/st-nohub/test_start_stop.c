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

void
test_start_stop(void **state)
{
	int ret;
	size_t iterations = 0;
	enum evp_agent_status status;
	struct evp_agent_context *ctxt;

	// instantiate EVP Agent context
	ctxt = evp_agent_setup("evp_agent_main");
	assert_non_null(ctxt);

	// start and connect agent
	ret = evp_agent_start(ctxt);
	assert_int_equal(ret, 0);
	ret = evp_agent_connect(ctxt);
	assert_int_equal(ret, 0);
	status = evp_agent_get_status(ctxt);
	while (status != EVP_AGENT_STATUS_CONNECTED && iterations++ < 1000) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
		status = evp_agent_get_status(ctxt);
	}
	assert_int_equal(status, EVP_AGENT_STATUS_CONNECTED);

	// stop agent
	ret = evp_agent_stop(ctxt);
	assert_int_equal(ret, 0);
	while (status != EVP_AGENT_STATUS_STOPPED && iterations++ < 1000) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
		status = evp_agent_get_status(ctxt);
	}
	assert_int_equal(status, EVP_AGENT_STATUS_STOPPED);

	// restart agent
	ret = evp_agent_start(ctxt);
	assert_int_equal(ret, 0);
	while (status != EVP_AGENT_STATUS_READY && iterations++ < 1000) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
		status = evp_agent_get_status(ctxt);
	}
	assert_int_equal(status, EVP_AGENT_STATUS_READY);

	// stop agent again
	ret = evp_agent_stop(ctxt);
	assert_int_equal(ret, 0);
	while (status != EVP_AGENT_STATUS_STOPPED && iterations++ < 1000) {
		ret = evp_agent_loop(ctxt);
		assert_int_equal(ret, 0);
		status = evp_agent_get_status(ctxt);
	}
	assert_int_equal(status, EVP_AGENT_STATUS_STOPPED);

	// free context
	evp_agent_free(ctxt);
	assert_int_equal(ret, 0);
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
		cmocka_unit_test(test_start_stop),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
