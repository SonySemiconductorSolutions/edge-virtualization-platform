/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string_map_internal.h>

#include <cmocka.h>

#include <internal/string_map.h>

static const char key[] = "key";

/* clang sanitizer is known to rely on strdup(3) before main() is
 * called, which leads to undefined behaviour since __wrap_strdup
 * relies on symbols initialized by cmocka_run_group_tests. */
static bool can_use_strdup;

static void
free_fn(void *args)
{
}

char *
__wrap_strdup(const char *s)
{
	char *__real_strdup(const char *);

	if (can_use_strdup) {
		check_expected(s);
		function_called();
	}

	return __real_strdup(s);
}

static void
test_string_map_insert(void **state)
{
	char value[] = "value";
	struct string_map *m = *state;

	expect_value(__wrap_strdup, s, key);
	expect_function_call(__wrap_strdup);
	assert_int_equal(string_map_insert(m, key, value, false), 0);
}

static void
test_string_map_insert_overwrite(void **state)
{
	char value[] = "value";
	struct string_map *m = *state;

	assert_int_equal(string_map_insert(m, key, value, true), 0);
}

static void
test_string_map_insert_failed_overwrite(void **state)
{
	char value[] = "value";
	struct string_map *m = *state;

	assert_int_not_equal(string_map_insert(m, key, value, false), 0);
}

static int
setup_empty(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	can_use_strdup = true;
	*state = m;
	return 0;
}

static int
setup(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	expect_value(__wrap_strdup, s, key);
	expect_function_call(__wrap_strdup);

	if (string_map_insert(m, key, "value", false)) {
		string_map_dealloc(m);
		return -1;
	}

	can_use_strdup = true;
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
		cmocka_unit_test_setup_teardown(test_string_map_insert,
						setup_empty, teardown),
		cmocka_unit_test_setup_teardown(
			test_string_map_insert_overwrite, setup, teardown),
		cmocka_unit_test_setup_teardown(
			test_string_map_insert_failed_overwrite, setup,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
