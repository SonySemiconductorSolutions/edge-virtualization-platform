/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include <internal/util.h>

#include "hub.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "module_log_cap.h"
#include "module_log_queue.h"
#include "path.h"
#include "xlog.h"

static struct test_context {
	union {
		int fd;
		int fds[4];
	};
} g_context;

#define MODULE_1_ID "module-id-a"
#define MODULE_2_ID "module-id-b"
#define MESSAGE     "INFO:A message"
#define WARNING     "WARN:A warning"

#define TIMEOUT_US_SLICE    10000
#define TIMEOUT_US(timeout) timeout * 1000000 / TIMEOUT_US_SLICE

#define WAIT_FOR(cond, timeout)                                               \
	for (int i = 0; (cond); assert_true(i++ < TIMEOUT_US(timeout)),       \
		 usleep(TIMEOUT_US_SLICE))

static struct mock_streamer_ctxt {
	char *lines[4];
	int count;
} g_mock_streamer_ctxt;

int
__wrap_module_log_queue_put(const char *name, const char *stream,
			    const char *log)
{
	printf("[   MOCK   ] Received from %s/%s line: %s\n", name, stream,
	       log);
	g_mock_streamer_ctxt.lines[g_mock_streamer_ctxt.count] = strdup(log);
	g_mock_streamer_ctxt.count++;
	return 0;
}

void
test_console_open_close(void **state)
{
	struct test_context *ctxt = *state;
	assert_true(ctxt->fd >= 0);
}

void
test_log_cap(void **state)
{
	struct test_context *ctxt = *state;

	dprintf(ctxt->fd, MESSAGE "\n" WARNING "\n");

	WAIT_FOR(g_mock_streamer_ctxt.count < 2, 2);
	assert_int_equal(g_mock_streamer_ctxt.count, 2);
	assert_string_equal(g_mock_streamer_ctxt.lines[0], MESSAGE);
	assert_string_equal(g_mock_streamer_ctxt.lines[1], WARNING);
}

void
test_log_cap_split(void **state)
{
	struct test_context *ctxt = *state;

	dprintf(ctxt->fds[0], MESSAGE "\nINFO:Split mes");
	dprintf(ctxt->fds[0], "sage\n");

	WAIT_FOR(g_mock_streamer_ctxt.count < 2, 2);
	assert_int_equal(g_mock_streamer_ctxt.count, 2);
	assert_string_equal(g_mock_streamer_ctxt.lines[0], MESSAGE);
	assert_string_equal(g_mock_streamer_ctxt.lines[1],
			    "INFO:Split message");
}

void
test_log_cap_interleave(void **state)
{
	struct test_context *ctxt = *state;
	char *data[] = {
		MESSAGE " from " MODULE_1_ID "\n",
		WARNING " from " MODULE_1_ID "\n",
		MESSAGE " from " MODULE_2_ID "\n",
		WARNING " from " MODULE_2_ID "\n",
	};

	for (int i = 0; i < 4; i++) {
		dprintf(ctxt->fds[i], "%s", data[i]);
	}

	WAIT_FOR(g_mock_streamer_ctxt.count < 4, 2);
	assert_int_equal(g_mock_streamer_ctxt.count, 4);
	for (int i = 0; i < 4; i++) {
		assert_memory_equal(g_mock_streamer_ctxt.lines[i], data[i],
				    strlen(data[i]) - 1);
	}
}

void
test_log_cap_enable(void **state)
{
	struct test_context *ctxt = *state;

	bool enable;
	module_log_cap_set_enable(MODULE_1_ID, "stdout", false);
	assert_int_equal(
		module_log_cap_get_enable(MODULE_1_ID, "stdout", &enable), 0);
	assert_int_equal(enable, false);

	dprintf(ctxt->fd, "%s\n", MESSAGE);

	sleep(1);
	assert_int_equal(g_mock_streamer_ctxt.count, 0);

	module_log_cap_set_enable(MODULE_1_ID, "stdout", true);
	assert_int_equal(
		module_log_cap_get_enable(MODULE_1_ID, "stdout", &enable), 0);
	assert_int_equal(enable, true);

	dprintf(ctxt->fd, "%s\n", WARNING);

	WAIT_FOR(g_mock_streamer_ctxt.count < 1, 2);
	assert_int_equal(g_mock_streamer_ctxt.count, 1);
	assert_string_equal(g_mock_streamer_ctxt.lines[0], WARNING);
}

void
test_log_instance_not_found(void **state)
{
	bool enable;

	int ret;
	ret = module_log_cap_set_enable("no-valid-instance-name", "stdout",
					false);
	assert_int_equal(ret, -1);

	ret = module_log_cap_get_enable("no-valid-instance-name", "stdout",
					&enable);
	assert_int_equal(ret, -1);
}

static int
open_and_enable(const char *instance, const char *stream)
{
	int fd = module_log_cap_open(instance, stream);
	module_log_cap_set_enable(instance, stream, true);
	return fd;
}

static void
teardown_mock(void)
{
	for (int i = 0; i < g_mock_streamer_ctxt.count; i++) {
		free(g_mock_streamer_ctxt.lines[i]);
		g_mock_streamer_ctxt.lines[i] = NULL;
	}
	g_mock_streamer_ctxt.count = 0;
}

int
setup_test(void **state)
{
	struct test_context *ctxt = *state;

	ctxt->fd = open_and_enable(MODULE_1_ID, "stdout");
	return 0;
}

int
teardown_test(void **state)
{
	struct test_context *ctxt = *state;

	module_log_cap_close(MODULE_1_ID, "stdout");
	ctxt->fd = -1;

	teardown_mock();
	return 0;
}

int
setup_multi(void **state)
{
	struct test_context *ctxt = *state;

	ctxt->fds[0] = open_and_enable(MODULE_1_ID, "stdout");
	ctxt->fds[1] = open_and_enable(MODULE_1_ID, "stderr");
	ctxt->fds[2] = open_and_enable(MODULE_2_ID, "stdout");
	ctxt->fds[3] = open_and_enable(MODULE_2_ID, "stderr");

	return 0;
}

int
teardown_multi(void **state)
{
	struct test_context *ctxt = *state;

	module_log_cap_close(MODULE_1_ID, "stdout");
	module_log_cap_close(MODULE_1_ID, "stderr");
	module_log_cap_close(MODULE_2_ID, "stdout");
	module_log_cap_close(MODULE_2_ID, "stderr");
	ctxt->fds[0] = -1;
	ctxt->fds[1] = -1;
	ctxt->fds[2] = -1;
	ctxt->fds[3] = -1;

	teardown_mock();
	return 0;
}

int
setup_suite(void **state)
{
	module_log_cap_init();
	module_log_cap_start();
	sleep(1);
	return 0;
}

int
teardown_suite(void **state)
{
	module_log_cap_stop();
	return 0;
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_prestate_setup_teardown(
			test_console_open_close, setup_test, teardown_test,
			&g_context),
		cmocka_unit_test_prestate_setup_teardown(
			test_log_cap, setup_test, teardown_test, &g_context),
		cmocka_unit_test_prestate_setup_teardown(
			test_log_cap_split, setup_test, teardown_test,
			&g_context),
		cmocka_unit_test_prestate_setup_teardown(
			test_log_cap_interleave, setup_multi, teardown_multi,
			&g_context),
		cmocka_unit_test_prestate_setup_teardown(
			test_log_cap_enable, setup_test, teardown_test,
			&g_context),
		cmocka_unit_test_prestate_setup_teardown(
			test_log_instance_not_found, setup_test, teardown_test,
			&g_context),
	};
	// run tests
	return cmocka_run_group_tests(tests, setup_suite, teardown_suite);
}
