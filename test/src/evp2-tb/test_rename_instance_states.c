/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>
#include <parson.h>

#include "global.h"
#include "hub.h"
#include "module_instance.h"
#include "path.h"
#include "persist.h"
#include "reconcile.h"

#define TEST_RENAME_INSTANCE1 "backdoor-EA_Main"
#define TEST_RENAME_INSTANCE2 "b218f90b-9228-423f-8e02-a6d3527bc15e"
#define TEST_RENAME_INSTANCE3 "backdoor-EA_UD"
#define TEST_RENAME_KEY1      "state/" TEST_RENAME_INSTANCE1 "/placeholder"
#define TEST_RENAME_KEY2      "state/" TEST_RENAME_INSTANCE2 "/placeholder"
#define TEST_RENAME_KEY3      "state/" TEST_RENAME_INSTANCE3 "/placeholder"
#define TEST_RENAME_VALUE     "eyJIYXJkd2FyZSI6eyJTZW5zb3IiOiJJTVg1MDAiLCJTZW5=="

void
test_rename(void **state)
{
	// create states
	JSON_Object *obj = json_value_get_object(g_evp_global.instance_states);
	assert_non_null(obj);
	json_object_set_string(obj, TEST_RENAME_KEY1, TEST_RENAME_VALUE);
	assert_string_equal(json_object_get_string(obj, TEST_RENAME_KEY1),
			    TEST_RENAME_VALUE);
	assert_null(json_object_get_string(obj, TEST_RENAME_KEY2));
	json_object_set_string(obj, TEST_RENAME_KEY3, TEST_RENAME_VALUE);
	assert_string_equal(json_object_get_string(obj, TEST_RENAME_KEY3),
			    TEST_RENAME_VALUE);
	// rename (some) states
	rename_instance_states(TEST_RENAME_INSTANCE1, TEST_RENAME_INSTANCE2);
	// check that old state is removed
	assert_null(json_object_get_string(obj, TEST_RENAME_KEY1));
	// check that new state is valid
	assert_non_null(json_object_get_string(obj, TEST_RENAME_KEY2));
	assert_string_equal(json_object_get_string(obj, TEST_RENAME_KEY2),
			    TEST_RENAME_VALUE);
	// check that other state remains
	assert_string_equal(json_object_get_string(obj, TEST_RENAME_KEY3),
			    TEST_RENAME_VALUE);
}

int
setup(void **state)
{
	path_init(getenv("EVP_DATA_DIR"));
	init_local_twins_db();
	load_current(NULL);
	assert_int_equal(module_instance_init(), 0);
	return 0;
}

int
teardown(void **state)
{
	json_value_free(g_evp_global.current);
	path_free();
	return 0;
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_rename),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
