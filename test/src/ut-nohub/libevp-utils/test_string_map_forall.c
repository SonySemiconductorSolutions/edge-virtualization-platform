/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string_map_internal.h>

#include <cmocka.h>

#include <internal/string_map.h>

static const char value[] = "value";

enum { ELEMENTS = 10 };

static int
callback(const char *key, void *value, void *user)
{
	check_expected(value);
	check_expected(user);
	function_called();
	return 1;
}

static void
test_string_map_forall(void **state)
{
	struct string_map *m = *state;
	int user;

	for (int i = 0; i < ELEMENTS; i++) {
		/* Since map items are sorted according to the hash function,
		 * it is not possible to know in which order they will be
		 * called. Therefore, it is not possible to check the key, but
		 * only the parameters shared among all items in the hash
		 * table. */
		expect_value(callback, user, &user);
		expect_string(callback, value, value);
		expect_function_call(callback);
	}

	assert_int_equal(string_map_forall(m, callback, &user), 0);
}

static void
test_string_map_forall_null_free(void **state)
{
	struct string_map *m = *state;
	int user;

	for (int i = 0; i < ELEMENTS; i++) {
		/* Since map items are sorted according to the hash function,
		 * it is not possible to know in which order they will be
		 * called. Therefore, it is not possible to check the key, but
		 * only the parameters shared among all items in the hash
		 * table. */
		expect_value(callback, user, &user);
		expect_value(callback, value, value);
		expect_function_call(callback);
	}

	assert_int_equal(string_map_forall(m, callback, &user), 0);
	assert_int_equal(string_map_count(m), ELEMENTS);
}

static int
callback_rm(const char *key, void *value, void *user)
{
	check_expected(value);
	check_expected(user);
	function_called();
	return -1;
}

static void
test_string_map_forall_remove(void **state)
{
	struct string_map *m = *state;
	int user;

	for (int i = 0; i < ELEMENTS; i++) {
		/* Since map items are sorted according to the hash function,
		 * it is not possible to know in which order they will be
		 * called. Therefore, it is not possible to check the key, but
		 * only the parameters shared among all items in the hash
		 * table. */
		expect_value(callback_rm, user, &user);
		expect_string(callback_rm, value, value);
		expect_function_call(callback_rm);
	}

	assert_int_equal(string_map_forall(m, callback_rm, &user), 0);
	assert_int_equal(string_map_count(m), 0);
}

static void
test_string_map_forall_empty(void **state)
{
	const struct string_map *m = *state;

	assert_int_equal(string_map_count(m), 0);
}

static void
free_fn(void *ptr)
{
	free(ptr);
}

static int
setup_element(struct string_map *m, int i)
{
	char buf[sizeof("2147483647")];
	int n = snprintf(buf, sizeof(buf), "%d", i);

	if (n < 0 || (unsigned)n >= sizeof(buf)) {
		return -1;
	}

	char *valuedup = strdup(value);

	if (!valuedup) {
		return -1;
	}

	return string_map_insert(m, buf, valuedup, false);
}

static int
setup(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	for (int i = 0; i < ELEMENTS; i++) {
		if (setup_element(m, i)) {
			string_map_dealloc(m);
			return -1;
		}
	}

	*state = m;
	return 0;
}

static int
setup_element_readonly_value(struct string_map *m, int i)
{
	char buf[sizeof("2147483647")];
	int n = snprintf(buf, sizeof(buf), "%d", i);

	if (n < 0 || (unsigned)n >= sizeof(buf)) {
		return -1;
	}

	return string_map_insert(m, buf, (void *)value, false);
}

static int
setup_null(void **state)
{
	struct string_map *m = string_map_alloc(1, NULL);

	if (!m)
		return -1;

	for (int i = 0; i < ELEMENTS; i++) {
		if (setup_element_readonly_value(m, i)) {
			string_map_dealloc(m);
			return -1;
		}
	}

	*state = m;
	return 0;
}

static int
setup_empty(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	*state = m;
	return 0;
}

static int
teardown(void **state)
{
	struct string_map *m = *state;

	string_map_dealloc(m);
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_string_map_forall, setup,
						teardown),
		cmocka_unit_test_setup_teardown(
			test_string_map_forall_null_free, setup_null,
			teardown),
		cmocka_unit_test_setup_teardown(test_string_map_forall_remove,
						setup, teardown),
		cmocka_unit_test_setup_teardown(test_string_map_forall_empty,
						setup_empty, teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
