/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MSG_H
#define MSG_H

#include <stddef.h>

struct msg_req {
	struct msg_header {
		enum msg_req_type { MSG_REQ_TELEMETRY } type;

		unsigned long long cookie;
		size_t n;
	} h;

	char buf[];
};

struct msg_rsp {
	struct msg_rsp_header {
		unsigned long long cookie;
		size_t n;
	} header;

	char buf[];
};

#endif
