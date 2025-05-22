/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

ssize_t
readall(int fd, void *buf, size_t sz)
{
	size_t done_bytes = 0;
	ssize_t ssz = 0;
	while (true) {
		size_t want = sz - done_bytes;
		if (want == 0) {
			break; /* done */
		}
		ssz = read(fd, (char *)buf + done_bytes, want);
		if (ssz == 0) {
			break; /* EOF */
		}
		if (ssz == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				continue; /* just retry */
			}
			break; /* "real" error */
		}
		done_bytes += ssz;
	}
	if (done_bytes > 0) {
		return done_bytes;
	}
	return ssz;
}

int
discardall(int fd, size_t sz)
{
	size_t total, n;
	ssize_t r;
	char buf[BUFSIZ];

	for (total = 0; total < sz; total += r) {
		n = sz - total;
		if (n > BUFSIZ)
			n = BUFSIZ;
		if ((r = read(fd, buf, n)) == 0)
			break;
		if (r < 0) {
			if (errno != EINTR && errno != EAGAIN)
				break;
			r = 0;
		}
	}

	return total == sz ? 0 : -1;
}
