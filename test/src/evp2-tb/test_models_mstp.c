/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <cdefs.h>
#include <models/mstp.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>

#include <internal/util.h>

#include "hub.h"

#define HEADER_AUTHENTICATE_NAME  "WWW-Authanticate"
#define HEADER_AUTHENTICATE_VALUE "Basic"

void
test_models_mstp_storagetoken_response(void **state)
{
	struct storagetoken_response resp;
	const char *url = "https://mockurl.net";

	storagetoken_response_ctor(&resp, 5, NULL, url, 0,
				   STORAGETOKEN_RESPONSE_TYPE_SINGLE_FILE);
	storagetoken_response_add_header(&resp, HEADER_AUTHENTICATE_NAME,
					 HEADER_AUTHENTICATE_VALUE);
	assert_int_equal(resp.status, 5);
	assert_ptr_equal(resp.error, NULL);
	assert_string_equal(resp.url, url);
	assert_ptr_not_equal(resp.url, url);
	assert_ptr_not_equal(resp.headers, NULL);
	assert_int_equal(resp.headers_len, 1);
	assert_string_equal(resp.headers[0], HEADER_AUTHENTICATE_NAME
			    ": " HEADER_AUTHENTICATE_VALUE);

	storagetoken_response_dtor(&resp);
}

void
test_models_mstp_storagetoken_response_error(void **state)
{
	struct storagetoken_response resp;
	const char *error = "An error";

	storagetoken_response_ctor(&resp, -1, error, NULL, 0,
				   STORAGETOKEN_RESPONSE_TYPE_SINGLE_FILE);
	assert_int_equal(resp.status, -1);
	assert_string_equal(resp.error, error);
	assert_ptr_equal(resp.url, NULL);
	assert_ptr_not_equal(resp.headers, NULL);
	assert_int_equal(resp.headers_len, 0);

	storagetoken_response_dtor(&resp);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_models_mstp_storagetoken_response),
		cmocka_unit_test(test_models_mstp_storagetoken_response_error),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, NULL, NULL);
}
