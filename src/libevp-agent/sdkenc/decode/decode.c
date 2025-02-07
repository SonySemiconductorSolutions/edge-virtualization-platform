/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sdk_json_printer.h"
#include "sdk_verifier.h"

#undef ns
#define ns(a) FLATBUFFERS_WRAP_NAMESPACE(EVP_SDK, a)

void
malloc_and_read_stdin(void **bufp, size_t *sizep)
{
	const size_t chunksize = 1024;
	char *buf = NULL;
	size_t bufsize = 0;
	size_t offset = 0;
	ssize_t n;

	do {
		if (offset == bufsize) {
			bufsize += chunksize;
			buf = realloc(buf, bufsize);
			// TODO: Replace assert (runtime error)
			assert(buf != NULL);
		}
		n = read(STDIN_FILENO, buf + offset, bufsize - offset);
		// TODO: Replace assert (runtime error)
		assert(n >= 0);
		offset += n;
	} while (n > 0);

	*bufp = buf;
	*sizep = offset;
}

int
main(int argc, char *argv[])
{
	enum type {
		REQUEST,
		RESPONSE,
	} type;

	if (argc != 2) {
		exit(2);
	}
	if (!strcmp(argv[1], "request")) {
		type = REQUEST;
	} else if (!strcmp(argv[1], "response")) {
		type = RESPONSE;
	} else {
		exit(2);
	}

	void *buffer;
	size_t n;
	malloc_and_read_stdin(&buffer, &n);

	/* verify flatbuffers */

	int ret;
	switch (type) {
	case REQUEST:
		ret = ns(Request_verify_as_root(buffer, n));
		break;
	case RESPONSE:
		ret = ns(Response_verify_as_root(buffer, n));
		break;
	default:
		exit(1);
	}
	if (ret != 0) {
		printf("verify failed: %s\n", flatcc_verify_error_string(ret));
		exit(1);
	}

	/* flatbuffers -> json */

	flatcc_json_printer_t ctx0, *ctx = &ctx0;
	flatcc_json_printer_init(ctx, stdout);
	switch (type) {
	case REQUEST:
		ns(Request_print_json_as_root(ctx, buffer, n, NULL));
		break;
	case RESPONSE:
		ns(Response_print_json_as_root(ctx, buffer, n, NULL));
		break;
	default:
		exit(1);
	}
	flatcc_json_printer_flush(ctx);
	if (flatcc_json_printer_get_error(ctx)) {
		printf("failed to json print\n");
	}
	printf("\n");
}
