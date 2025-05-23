/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* for asprintf */
#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
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

void
test_hexstr_to_char(void **status)
{
	unsigned char result[20];
	unsigned char expected[20] = {
		0xee, 0xfd, 0x5b, 0xc2, 0xc5, 0x47, 0xbf, 0x82, 0xb1, 0x77,
		0xb6, 0x25, 0x9c, 0x13, 0xf7, 0x72, 0x3d, 0xc8, 0x76, 0xd9,
	};
	int ret;

	ret = hexstr_to_char("eefd5bc2c547bf82b177b6259c13f7723dc876d9",
			     result, 20);
	assert_true(ret == 0);
	assert_true(!memcmp(expected, result, 20));
	ret = hexstr_to_char("eefd5bc2c547bf82bX77b6259c13f7723dc876d9",
			     result, 20);
	assert_true(ret == EINVAL);
	ret = hexstr_to_char("eefd5bc2c547bf82X177b6259c13f7723dc876d9",
			     result, 20);
	assert_true(ret == EINVAL);
	ret = hexstr_to_char("-efd5bc2c547bf82b177b6259c13f7723dc876d9",
			     result, 20);
	assert_true(ret == EINVAL);
	memset(result, 0, sizeof(result));
	ret = hexstr_to_char("EEFD5BC2C547BF82B177B6259C13F7723DC876D9",
			     result, 20);
	assert_true(ret == 0);
	assert_true(!memcmp(expected, result, 20));
	ret = hexstr_to_char("eefd5bc2c547bf82b177b6259c13f7723dc876d", result,
			     20);
	assert_true(ret == EINVAL);
	ret = hexstr_to_char("eefd5bc2c547bf82b177b6259c13f7723dc876", result,
			     20);
	assert_true(ret == EINVAL);
	ret = hexstr_to_char("eefd5bc2c547bf82b177b6259c13f7723dc876d900",
			     result, 20);
	assert_true(ret == EINVAL);
}

void
test_xmemdup(void **status)
{
	const char *orig = "hello";
	int i;
	for (i = 0; i < 5; i++) {
		void *copy = xmemdup(orig, i);
		assert_true(copy != NULL);
		assert_true(!memcmp(orig, copy, i));
		free(copy);
	}
}

void
test_copy_with_prefix_change(void **status)
{
	char *result;

	result = copy_with_prefix_change("hi world", "hi", "hello");
	assert_true(!strcmp("hello world", result));
	free(result);

	result = copy_with_prefix_change("good morning world", "good morning",
					 "hello");
	assert_true(!strcmp("hello world", result));
	free(result);

	result = copy_with_prefix_change("hello world", "hi", "hello");
	assert_true(!result);
}

void
test_string_to_int(void **status)
{
	const char *good_case = "33";
	int ret;
	intmax_t val;
	int val_expected = 33;

	/* Good cases*/
	ret = string_to_int(good_case, &val);
	assert_true(ret == 0);
	assert_true(val == val_expected);

	/* Bad cases */
	const char *bad[] = {
		"", " ", "a", "33 ", "33a", "a33", "3a3",
	};

	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		ret = string_to_int(bad[i], &val);
		assert_true(ret != 0);
	}
}

void
test_getenv_int(void **status)
{
	int val;
	int error;

	error = getenv_int("UT_ENV_VAR_OK", &val);
	assert_true(error == 0);
	assert_true(val == 33);

	error = getenv_int("UT_ENV_VAR_BAD", &val);
	assert_true(error == EINVAL);

	error = getenv_int("UT_ENV_VAR_NOT_EXIST", &val);
	assert_true(error == ENOENT);
}

int
setup(void **state)
{
	putenv("UT_ENV_VAR_OK=33");
	putenv("UT_ENV_VAR_BAD=33a");
	return 0;
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hexstr_to_char),
		cmocka_unit_test(test_xmemdup),
		cmocka_unit_test(test_copy_with_prefix_change),
		cmocka_unit_test(test_string_to_int),
		cmocka_unit_test(test_getenv_int),
	};
	return cmocka_run_group_tests(tests, setup, NULL);
}
