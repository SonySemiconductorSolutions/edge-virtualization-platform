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

static void
test_djb2_equal(void **state)
{
	assert_int_equal(djb2("hash"), djb2("hash"));
}

static void
test_djb2_diff(void **state)
{
	assert_int_not_equal(djb2("hash"), djb2("hsah"));
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_djb2_equal),
		cmocka_unit_test(test_djb2_diff),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
