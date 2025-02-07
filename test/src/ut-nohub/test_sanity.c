/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>

#include "hub.h"

void
test_sanity(void **state)
{
	assert_int_equal(2, 1 + 1); // sanity lost?
}

int
setup(void **state)
{
	// put setup here
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
		cmocka_unit_test(test_sanity),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
