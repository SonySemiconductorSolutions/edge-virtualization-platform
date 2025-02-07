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

static void
free_fn(void *args)
{
	function_called();
}

void
__wrap_free(void *ptr)
{
	void __real_free(void *);

	function_called();
	__real_free(ptr);
}

static void
test_string_map_dealloc(void **state)
{
	struct string_map *m = *state;

	expect_function_calls(free_fn, 1);
	/* Expected calls:
	 *	- free(m->bucket[i].key);
	 *	- free(m->bucket[i]);
	 *	- free(m->bucket);
	 *	- free(m);
	 * "i" is the index calculated by hashing the key.
	 */
	expect_function_calls(__wrap_free, 4);
	string_map_dealloc(m);
}

static int
setup(void **state)
{
	struct string_map *m = string_map_alloc(1, free_fn);

	if (!m)
		return -1;

	if (string_map_insert(m, "key", "value", false)) {
		string_map_dealloc(m);
		return -1;
	}

	*state = m;
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_string_map_dealloc, setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
