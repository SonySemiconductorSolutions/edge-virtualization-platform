/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

static int
make_socket(int *fdp)
{
	int fd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd == -1) {
		return errno;
	}
	*fdp = fd;
	return 0;
}

static void
make_addr(struct sockaddr_un *un, const char *path)
{
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_LOCAL;
	strncpy(un->sun_path, path, sizeof(un->sun_path));
#if !defined(__NuttX__) && !defined(__linux__)
	un->sun_len = SUN_LEN(un);
#endif
}

int
local_listen_on(const char *path, int *fdp)
{
	struct sockaddr_un un0;
	struct sockaddr_un *un = &un0;
	int fd = -1;
	int ret;
	if (strlen(path) > sizeof(un->sun_path) - 1) {
		return ENAMETOOLONG;
	}
	ret = unlink(path);
	if (ret != 0 && errno != ENOENT) {
		return errno;
	}
	ret = make_socket(&fd);
	if (ret != 0) {
		return ret;
	}
	make_addr(un, path);
	ret = bind(fd, (const struct sockaddr *)un, sizeof(*un));
	if (ret == -1) {
		int error = errno;
		close(fd);
		return error;
	}
	ret = listen(fd, 0);
	if (ret == -1) {
		int error = errno;
		close(fd);
		return error;
	}
	*fdp = fd;
	return 0;
}

int
local_connect_to(const char *path, int *fdp)
{
	struct sockaddr_un un0;
	struct sockaddr_un *un = &un0;
	int fd = -1;
	int ret;
	if (strlen(path) > sizeof(un->sun_path) - 1) {
		return ENAMETOOLONG;
	}
	ret = make_socket(&fd);
	if (ret != 0) {
		return ret;
	}
	make_addr(un, path);
	ret = connect(fd, (const struct sockaddr *)un, sizeof(*un));
	if (ret == -1) {
		int error = errno;
		close(fd);
		return error;
	}
	*fdp = fd;
	return 0;
}
