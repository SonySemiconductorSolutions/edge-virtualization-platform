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

#include "agent_test.h"
#include "fsutil.h"
#include "hub.h"
#include "path.h"
#include "xlog.h"

char *
base(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/fsutil",
		     path_get(MODULE_INSTANCE_PATH_ID));
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

char *
reg(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/a/b/c/reg", base());
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

char *
fifo(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/a/b/c/fifo", base());
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

char *
parent(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/a/b/c/../parent", base());
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

char *
link1(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/a/b/c/link", base());
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

char *
link2(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/a/link/c/reg", base());
	if (r < 0 || (size_t)r >= sizeof(buf))
		return NULL;
	return buf;
}

void
test_fsutil(void **status)
{

	int error;
	int ret;
	int fd = -1;
	error = careful_open(parent(), O_RDONLY, &fd);
	xlog_warning("careful_open PARENT %s %u", parent(), error);
	assert_true(error == EPERM);
	error = careful_open(reg(), O_RDONLY, &fd);
	xlog_warning("careful_open REG %s %u", reg(), error);
	assert_true(error == 0);
	assert_true(fd != -1);
	ret = close(fd);
	assert_true(ret != -1);
	error = careful_open(fifo(), O_RDONLY, &fd);
	xlog_warning("careful_open FIFO O_RDONLY %s %u", fifo(), error);
	assert_true(error == EPERM);
	error = careful_open(fifo(), O_WRONLY, &fd);
	xlog_warning("careful_open FIFO O_WRONLY %s %u", fifo(), error);
	assert_true(error == ENXIO);
	error = careful_open(link1(), O_RDONLY, &fd);
	xlog_warning("careful_open LINK1 %s %u", link1(), error);
	assert_true(error == ELOOP);
	error = careful_open(link2(), O_RDONLY, &fd);
	xlog_warning("careful_open LINK2 %s %u", link2(), error);
	assert_true(error == ENOTDIR);
}

void
test_bigger_max_name(void **status)
{
	int error;
	int fd = -1;
	char *input_test;

	/* Check that a path can not contain a dir or file longer than NAME_MAX
	 */
	char path[NAME_MAX + 1];
	memset(path, 'a', sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';

	xasprintf(&input_test, "%s/%s/my_file.txt", base(), path);

	error = careful_open(input_test, O_RDONLY, &fd);
	xlog_warning("careful_open for a path too long %u", error);
	assert_int_equal(error, ENAMETOOLONG);
	free(input_test);
}

void
test_limit_max_name(void **status)
{
	int error;
	int fd = -1;
	char *input_test;

	/* Check that a path can contain a dir or file until NAME_MAX */
	char path[NAME_MAX];
	memset(path, 'a', sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';

	xasprintf(&input_test, "%s/%s/my_file.txt", base(), path);

	error = careful_open(input_test, O_RDONLY, &fd);
	xlog_warning("careful_open for max name %u", error);
	assert_int_equal(error, ENOENT); // The file doesn't exit actaully
	free(input_test);
}

int
setup(void **state)
{
	path_init(getenv("EVP_DATA_DIR"));

	systemf("rm  -rf %s", base());
	assert_int_equal(0, systemf("mkdir -p `dirname %s`", reg()));
	assert_int_equal(0, systemf("touch %s", reg()));
	assert_int_equal(0, systemf("touch %s", parent()));
	assert_int_equal(0, systemf("mkfifo %s", fifo()));
	assert_int_equal(0, systemf("ln -s reg %s", link1()));
	assert_int_equal(0, systemf("ln -s b %s/a/link", base()));

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
		cmocka_unit_test(test_fsutil),
		cmocka_unit_test(test_bigger_max_name),
		cmocka_unit_test(test_limit_max_name),
	};
	// test run
	return cmocka_run_group_tests(tests, setup, teardown);
}
