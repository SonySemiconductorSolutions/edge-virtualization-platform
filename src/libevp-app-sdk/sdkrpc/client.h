/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <internal/record_hdr.h>
#include <internal/request.h>

struct sdk_transport {
	int fd, fds[2];
	int (*on_stream_input)(void *buf, void *user);
	void *user;
};

struct record_reader {
	size_t bytes_read;
	struct record_hdr hdr;
	void *buf;

	void (*dispatch)(void *buf, size_t, sdk_xid_t, void *user);
	void *user;
};

struct record_writer {
	size_t bytes_written;
	struct record_hdr hdr;
	void *buf;

	bool (*has_next)(void *user);
	void *(*get_next)(uint32_t *, sdk_xid_t *, void *user);
	void (*free_buf)(void *);
	void *user;
};

struct sdk_client {
	struct sdk_transport transport;
	struct record_reader reader;
	struct record_writer writer;
};

void sdk_clnt_setup(struct sdk_client *clnt, int fd);
void sdk_clnt_enqueue(struct sdk_client *clnt, struct sdk_request *req);
int sdk_clnt_sync(struct sdk_client *clnt, int timeout_ms);
struct timespec;
int sdk_clnt_sync_ts(struct sdk_client *clnt,
		     const struct timespec *abstimeout);
