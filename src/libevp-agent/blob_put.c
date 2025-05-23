/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "blob.h"
#include "fsutil.h"

int
blob_noop_write_func(unsigned http_status, char **bufp, int offset, int datend,
		     int *buflen, void *vp)
{
	return 0;
}

int
blob_file_read_func(void *buffer, size_t *sizep, const void **datap,
		    size_t reqsize, void *vp)
{
	int fd = *(int *)vp;
	ssize_t read_bytes = read(fd, buffer, *sizep);
	if (read_bytes == -1) {
		return -errno;
	}
	*sizep = (size_t)read_bytes;
	return 0;
}

unsigned int
blob_put(struct blob_work *wk, unsigned int (*do_put)(struct blob_work *, int))
{

	if ((wk->type != BLOB_TYPE_AZURE_BLOB) &&
	    (wk->type != BLOB_TYPE_HTTP) && (wk->type != BLOB_TYPE_HTTP_EXT) &&
	    (wk->type != BLOB_TYPE_EVP_EXT)) {
		wk->error = EINVAL;
		return BLOB_RESULT_INVALID;
	}
	if (wk->op != BLOB_OP_PUT) {
		wk->error = EINVAL;
		return BLOB_RESULT_INVALID;
	}

	if (wk->wk.status != WORK_STATUS_INPROGRESS) {
		wk->error = EBUSY;
		return BLOB_RESULT_ERROR;
	}
	unsigned int result;
	int fd;

	if (wk->filename != NULL) {
		int error = careful_open(wk->filename, O_RDONLY, &fd);
		if (error != 0) {
			wk->error = error;
			return BLOB_RESULT_ERROR;
		}
	} else {
		fd = -1;
	}

	result = do_put(wk, fd);
	if (fd != -1) {
		close(fd);
	}
	return result;
}
