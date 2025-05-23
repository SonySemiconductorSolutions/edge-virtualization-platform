/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include <internal/util.h>

#include "blob.h"
#include "work.h"

#define MY_ERROR_NUM 1
#define MY_ERROR_STR "Operation not permitted"

static void
test_blob_strerror_get_success(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	assert_string_equal(strerror(MY_ERROR_NUM), MY_ERROR_STR);

	wk->op = BLOB_OP_GET;
	wk->result = BLOB_RESULT_SUCCESS;
	wk->wk.status = WORK_STATUS_DONE;
	wk->http_status = 200;

	err = blob_strerror(wk);
	assert_string_equal(err, "Download succeeded with http status 200");

	free(err);
}

static void
test_blob_strerror_invalid_op_not_done(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	assert_string_equal(strerror(MY_ERROR_NUM), MY_ERROR_STR);

	wk->op = (enum blob_work_op) - 1;
	wk->wk.status = WORK_STATUS_CANCELLED;

	err = blob_strerror(wk);
	assert_string_equal(err, "Invalid operation is not done");

	free(err);
}

static void
test_blob_strerror_invalid_result(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	assert_string_equal(strerror(MY_ERROR_NUM), MY_ERROR_STR);

	wk->op = BLOB_OP_GET;
	wk->wk.status = WORK_STATUS_DONE;
	wk->result = 255;

	err = blob_strerror(wk);
	assert_string_equal(err, "Invalid result 255");

	free(err);
}

static void
test_blob_strerror_get_error(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	assert_string_equal(strerror(MY_ERROR_NUM), MY_ERROR_STR);

	wk->op = BLOB_OP_GET;
	wk->wk.status = WORK_STATUS_DONE;
	wk->result = BLOB_RESULT_ERROR;

	err = blob_strerror(wk);
	assert_string_equal(err,
			    "Download failed with errno 1 (" MY_ERROR_STR ")");

	free(err);
}

static void
test_blob_strerror_get_error_http(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	wk->op = BLOB_OP_GET;
	wk->result = BLOB_RESULT_ERROR_HTTP;
	wk->wk.status = WORK_STATUS_DONE;
	wk->http_status = 500;

	err = blob_strerror(wk);
	assert_string_equal(err, "Download failed with http status 500");

	free(err);
}

static void
test_blob_strerror_put_error_http(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	wk->op = BLOB_OP_PUT;
	wk->result = BLOB_RESULT_ERROR_HTTP;
	wk->wk.status = WORK_STATUS_DONE;
	wk->http_status = 500;

	err = blob_strerror(wk);
	assert_string_equal(err, "Upload failed with http status 500");

	free(err);
}

static void
test_blob_strerror_put_error(void **state)
{
	struct blob_work *wk = *state;
	char *err;

	assert_string_equal(strerror(MY_ERROR_NUM), MY_ERROR_STR);

	wk->op = BLOB_OP_PUT;
	wk->result = BLOB_RESULT_ERROR;
	wk->wk.status = WORK_STATUS_DONE;

	err = blob_strerror(wk);
	assert_string_equal(err,
			    "Upload failed with errno 1 (" MY_ERROR_STR ")");

	free(err);
}

static int
setup(void **state)
{
	struct blob_work *wk = blob_work_alloc();
	assert_false(wk == NULL);

	wk->type = BLOB_TYPE_AZURE_BLOB;
	wk->url = xstrdup("http://foo");
	wk->error = MY_ERROR_NUM;

	*state = wk;

	return 0;
}

static int
teardown(void **state)
{
	struct blob_work *wk = *state;

	blob_work_free(wk);

	return 0;
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_blob_strerror_get_error),
		cmocka_unit_test(test_blob_strerror_get_error_http),
		cmocka_unit_test(test_blob_strerror_put_error),
		cmocka_unit_test(test_blob_strerror_put_error_http),
		cmocka_unit_test(test_blob_strerror_get_success),
		cmocka_unit_test(test_blob_strerror_invalid_op_not_done),
		cmocka_unit_test(test_blob_strerror_invalid_result),

	};
	// test run
	return cmocka_run_group_tests(tests, setup, teardown);
}
