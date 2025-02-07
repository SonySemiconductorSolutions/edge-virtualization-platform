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
static char value[] = "value";

static void
test_string_map_lookup(void **state)
{
	struct string_map *m = *state;

	assert_ptr_equal(string_map_lookup(m, key), value);
}

static void
test_string_map_lookup_not_found(void **state)
{
	struct string_map *m = *state;

	assert_null(string_map_lookup(m, key));
}

static void
free_fn(void *ptr)
{
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
setup(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	if (string_map_insert(m, key, value, false)) {
		string_map_dealloc(m);
		return -1;
	}

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
		cmocka_unit_test_setup_teardown(test_string_map_lookup, setup,
						teardown),
		cmocka_unit_test_setup_teardown(
			test_string_map_lookup_not_found, setup_empty,
			teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
