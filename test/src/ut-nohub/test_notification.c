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
test_notify(void **state)
{
	static const char event[] = "hello";
	int data = TEST_VALUE;
	struct notification *notif = notification_alloc();

	assert_non_null(notif);
	assert_int_equal(notification_subscribe(notif, event, on_notification,
						&data, NULL),
			 0);
	expect_function_call(on_notification);
	assert_int_equal(notification_publish(notif, event, &test_args), 0);
	notification_free(notif);
}

static void
test_notify_unsubscribe(void **state)
{
	static const char event[] = "hello";
	int data = TEST_VALUE;
	struct notification *notif = notification_alloc();
	struct notification_entry *entry = NULL;

	assert_non_null(notif);
	assert_int_equal(notification_subscribe(notif, event, on_notification,
						&data, &entry),
			 0);
	assert_non_null(entry);
	expect_function_call(on_notification);
	assert_int_equal(notification_publish(notif, event, &test_args), 0);
	assert_int_equal(notification_unsubscribe(notif, entry), 0);
	assert_int_equal(notification_publish(notif, event, &test_args), 0);
	notification_free(notif);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_notify),
		cmocka_unit_test(test_notify_unsubscribe),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
