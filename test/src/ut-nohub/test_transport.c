/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>

#include "agent_internal.h"
#include "main_loop.h"
#include "timeutil.h"
#include "transport.h"

void
on_connected(struct evp_agent_context *ctxt, struct transport_ctxt *transport,
	     const char *device_id, const char *client_id)
{
	check_expected(ctxt);
}

void
on_message(struct evp_agent_context *ctxt, const char *topic, int packet_id,
	   int qos_level, const char *payload)
{
	fail_msg("invalid callback invocation");
}

int
__wrap_evp_agent_notification_publish(struct evp_agent_context *ctxt,
				      const char *event, const void *args)
{
	return 0;
}

void
test_happy(void **state)
{
	int ret;
	bool connected;
	struct evp_agent_context agent_ctxt; // dummy agent context
	struct transport_ctxt *transport_ctxt;

	// Calling main_loop_init() is required in order to set `g_main_thread`
	// and prevent an assertion failure in:
	// `transport_sync->mqtt_prepare_poll->main_loop_add_abs_timespec`
	// And it is called in each test to reset `g_npollfds`
	main_loop_init();

	// create transport context and configure with callbacks
	transport_ctxt =
		transport_setup(on_connected, on_message, &agent_ctxt, NULL);
	assert_non_null(transport_ctxt);
	connected = transport_is_connected(transport_ctxt);
	assert_false(connected);

	// sync before connect
	transport_sync(transport_ctxt, gettime_ms());
	connected = transport_is_connected(transport_ctxt);
	assert_false(connected);

	// connect and sync
	ret = transport_connect(transport_ctxt);
	assert_int_equal(ret, 0);
	expect_value(on_connected, ctxt, &agent_ctxt);
	transport_sync(transport_ctxt, gettime_ms());
	connected = transport_is_connected(transport_ctxt);
	assert_true(connected);

	// disconnect and sync
	ret = transport_disconnect(transport_ctxt);
	assert_int_equal(ret, 0);
	transport_sync(transport_ctxt, gettime_ms());
	connected = transport_is_connected(transport_ctxt);
	assert_false(connected);

	// reconnect and sync
	ret = transport_connect(transport_ctxt);
	assert_int_equal(ret, 0);
	expect_value(on_connected, ctxt, &agent_ctxt);
	transport_sync(transport_ctxt, gettime_ms());
	connected = transport_is_connected(transport_ctxt);
	assert_true(connected);

	// disconnect and free
	ret = transport_disconnect(transport_ctxt);
	assert_int_equal(ret, 0);
	transport_sync(transport_ctxt, gettime_ms());
	connected = transport_is_connected(transport_ctxt);
	assert_false(connected);
	transport_free(transport_ctxt);
}

void
test_invalid_connect(void **state)
{
	int ret;
	struct evp_agent_context agent_ctxt; // dummy agent context
	main_loop_init();
	struct transport_ctxt *transport_ctxt =
		transport_setup(on_connected, on_message, &agent_ctxt, NULL);
	assert_non_null(transport_ctxt);

	// connect
	ret = transport_connect(transport_ctxt);
	assert_int_equal(ret, 0);
	expect_value(on_connected, ctxt, &agent_ctxt);
	transport_sync(transport_ctxt, gettime_ms());

	// connect again (error)
	ret = transport_connect(transport_ctxt);
	assert_int_not_equal(ret, 0);
	transport_sync(transport_ctxt, gettime_ms());

	// free context
	transport_free(transport_ctxt);
}

void
test_invalid_disconnect(void **state)
{
	int ret;
	struct evp_agent_context agent_ctxt; // dummy agent context
	main_loop_init();
	struct transport_ctxt *transport_ctxt =
		transport_setup(on_connected, on_message, &agent_ctxt, NULL);
	assert_non_null(transport_ctxt);

	// disconnect without connect (error)
	ret = transport_disconnect(transport_ctxt);
	assert_int_not_equal(ret, 0);

	// free context
	transport_free(transport_ctxt);
}

int
setup(void **state)
{
	putenv("EVP_MQTT_HOST=test.mqtt.host.value");
	putenv("EVP_MQTT_PORT=1234");
	return 0;
}

int
teardown(void **state)
{
	// put teardown here
	return 0;
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_happy),
		cmocka_unit_test(test_invalid_connect),
		cmocka_unit_test(test_invalid_disconnect),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
