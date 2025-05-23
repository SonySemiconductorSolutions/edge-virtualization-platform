/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include "evp/sdk.h"
#include "stream.h"

static EVP_RESULT
init_null_stream(struct stream_impl *si)
{
	/* TODO: implement. */
	fprintf(stderr, "%s: not supported\n", __func__);
	return EVP_NOTSUP;
}

static int
close_null_stream(struct stream_impl *si)
{
	return 0;
}

static int
write_null(const struct stream_impl *si, const void *buf, size_t n)
{
	/* TODO: define if this is an actual error. */
	return -1;
}

static int
read_null(struct stream_impl *si, struct stream_read *sr)
{
	/* TODO: define if this is an actual error. */
	return -1;
}

static void
free_msg_null(void *buf)
{
}

const struct stream_ops stream_null_ops = {
	.init = init_null_stream,
	.close = close_null_stream,
	.write = write_null,
	.read = read_null,
	.free_msg = free_msg_null,
};
