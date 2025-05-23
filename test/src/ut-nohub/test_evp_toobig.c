/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <internal/record_hdr.h>
#include <internal/request.h>
#include <internal/util.h>

#include "ioutil.h"
#include "sdk_agent.h"
#include "sdkrpc/server.h"

#define BIG_REQUEST_FD 10000

int __real_write(int, void *, size_t);
void *__real_sdk_build_simple_response(size_t *, EVP_RESULT);

void *flatcc_buffer;
EVP_RESULT expected;

int
__wrap_write(int fd, void *buf, size_t len)
{
	switch (fd) {
	case BIG_REQUEST_FD:
		return len;
	default:
		return __real_write(fd, buf, len);
	}
}

int
__wrap_discardall(int fd, size_t len)
{
	return 0;
}

void *
__wrap_sdk_build_simple_response(size_t *sizep, EVP_RESULT result)
{
	assert_int_equal(result, expected);
	flatcc_buffer = __real_sdk_build_simple_response(sizep, result);
	return flatcc_buffer;
}

ssize_t
__wrap_readall(int fd, void *buf, size_t len)
{
	switch (fd) {
	case BIG_REQUEST_FD:
		assert_int_equal(len, sizeof(struct record_hdr));
		memcpy(buf,
		       &(struct record_hdr){.size = SDKRPC_MAX_REQUEST_SIZE +
						    1},
		       len);
		return len;
	default:
		fail_msg("unexpected fd=%d\n", fd);
		return -1;
	}
}

static int
setup_big_request(void **status)
{
	static struct sdk_server svr = {
		.fd = BIG_REQUEST_FD,
	};
	*status = &svr;
	expected = EVP_TOOBIG;
	return 0;
}

static void
test_big_request(void **status)
{
	int r;
	struct sdk_server *svr = *status;

	r = sdk_svr_process(svr, NULL, NULL);

	assert_int_equal(r, 0);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_big_request,
						setup_big_request, NULL),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
