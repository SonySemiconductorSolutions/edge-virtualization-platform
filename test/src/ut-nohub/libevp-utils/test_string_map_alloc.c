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

/* clang sanitizer is known to rely on malloc(3) before main() is
 * called, which leads to undefined behaviour since __wrap_malloc
 * relies on symbols initialized by cmocka_run_group_tests. */
static bool mock_malloc;

void *
__wrap_malloc(size_t size)
{
	void *__real_malloc(size_t);

	if (mock_malloc) {
		return mock_ptr_type(void *);
	}

	return __real_malloc(size);
}

static void
test_string_map_alloc(void **state)
{
	struct string_map *m = string_map_alloc(1, NULL);

	assert_non_null(m);
	string_map_dealloc(m);
}

static void
test_string_map_alloc_null(void **state)
{
	struct string_map *m;

	will_return(__wrap_malloc, NULL);
	m = string_map_alloc(1, NULL);
	assert_null(m);
}

static int
setup(void **state)
{
	mock_malloc = false;
	return 0;
}

static int
setup_null(void **state)
{
	mock_malloc = true;
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_string_map_alloc, setup),
		cmocka_unit_test_setup(test_string_map_alloc_null, setup_null),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
