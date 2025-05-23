/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h>

#include "test_blob_mstp_cache.h"

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_prestate_setup_teardown(
			test_mstp_cache_store, setup_test_blob_core,
			teardown_test_blob_core,
			TEST_BLOB_PARAM("performance_boot_mstp",
					TEST_IMPL_SPAWN, 1)),
	};

	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup_suite_blob_mstp_cache,
				      teardown_suite_blob_core);
}
