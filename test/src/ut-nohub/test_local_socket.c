/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "agent_test.h"
#include "hub.h"
#include "local_socket.h"
#include "path.h"

void
test_local_socket(void **status)
{
	static char too_long_path[200];
	char path[FILENAME_MAX];
	int cfd;
	int sfd;
	int slfd;
	int ret;

	memset(too_long_path, 'a', sizeof(too_long_path) - 1);
	too_long_path[sizeof(too_long_path) - 1] = 0;
	ret = local_listen_on(too_long_path, &slfd);
	assert_true(ret == ENAMETOOLONG);
	ret = local_connect_to(too_long_path, &slfd);
	assert_true(ret == ENAMETOOLONG);

	ret = snprintf(path, sizeof(path), "%s/socket",
		       path_get(MODULE_INSTANCE_PATH_ID));
	assert_true(ret > 0 && (size_t)ret < sizeof(path));
	systemf("rm -rf %s", path_get(MODULE_INSTANCE_PATH_ID));
	ret = systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID));
	assert_int_equal(ret, 0);
	ret = local_connect_to(path, &cfd);
	assert_true(ret == ENOENT);
	ret = local_listen_on(path, &slfd);
	assert_true(ret == 0);
	assert_true(slfd >= 0);
	ret = local_connect_to(path, &cfd);
	assert_true(ret == 0);
	assert_true(cfd >= 0);

	sfd = accept(slfd, NULL, 0);
	assert_true(sfd >= 0);

	char buf[100];
	const char ctestdata[] = "this is important test data from client";
	const char stestdata[] = "this is useless test data from server";
	ssize_t ssz;
	ssz = write(cfd, ctestdata, sizeof(ctestdata));
	assert_true(ssz == sizeof(ctestdata));
	ssz = write(sfd, stestdata, sizeof(stestdata));
	assert_true(ssz == sizeof(stestdata));
	memset(&buf, 0, sizeof(buf));
	ssz = read(cfd, buf, sizeof(stestdata));
	assert_true(ssz == sizeof(stestdata));
	assert_true(!memcmp(buf, stestdata, sizeof(stestdata)));
	ssz = read(sfd, buf, sizeof(ctestdata));
	assert_true(ssz == sizeof(ctestdata));
	assert_true(!memcmp(buf, ctestdata, sizeof(ctestdata)));
}

int
setup(void **state)
{
	path_init(getenv("EVP_DATA_DIR"));
	return 0;
}

int
teardown(void **state)
{
	path_free();
	return 0;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_local_socket),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
