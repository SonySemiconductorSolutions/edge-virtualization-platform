/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct sdk_server {
	int fd;
};

void sdk_svr_setup(struct sdk_server *, int fd);

struct sdk_request;
struct sdk_response;
int sdk_svr_process(struct sdk_server *svr,
		    int (*)(const void *, size_t, struct sdk_response **respp,
			    void *),
		    void *);
