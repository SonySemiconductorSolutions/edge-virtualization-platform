/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_blob.h"

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_prestate_setup_teardown(
			test_upload_http_file, setup_test_blob_core,
			teardown_test_blob_core,
			TEST_BLOB_PARAM("upload_http_file", TEST_IMPL_WASM)),
	};

	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup_suite_blob_core,
				      teardown_suite_blob_core);
}
