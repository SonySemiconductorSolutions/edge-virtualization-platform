/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "blob.h"
#include "fsutil.h"

int
blob_file_write_func(unsigned http_status, char **bufp, int offset, int datend,
		     int *buflen, void *vp)
{
	if (http_status / 100 != 2) {
		return 0;
	}

	int fd = *(int *)vp;
	ssize_t written = write(fd, *bufp + offset, datend - offset);
	if (written == -1) {
		return -errno;
	}
	if (written != datend - offset) {
		/* short write */
		return -EIO;
	}
	return 0;
}

static unsigned int
blob_get_file(struct blob_work *wk,
	      unsigned int (*do_get)(struct blob_work *, int))
{
	char *tmp_name = NULL;
	const char *last_delim;
	unsigned int result;
	int fd = -1;
	int ret;

	if (wk->tmpname_template != NULL) {
		last_delim = strrchr(wk->filename, '/');
		if (last_delim == NULL) {
			wk->error = EINVAL;
			result = BLOB_RESULT_ERROR;
			goto fail;
		}
		int len = last_delim - wk->filename;
		ret = xasprintf(&tmp_name, "%.*s/%s", len, wk->filename,
				wk->tmpname_template);
		if (ret == -1) {
			goto fail_with_errno;
		} else if (ret >= PATH_MAX) {
			wk->error = ENAMETOOLONG;
			result = BLOB_RESULT_ERROR;
			goto fail;
		}
		fd = mkstemp(tmp_name);
		if (fd == -1) {
			goto fail_with_errno;
		}
	} else {
		/* XXX who should be the owner of the file? */
		int error = careful_open(wk->filename,
					 O_CREAT | O_TRUNC | O_WRONLY, &fd);
		if (error != 0) {
			wk->error = error;
			result = BLOB_RESULT_ERROR;
			goto fail;
		}
	}
	result = do_get(wk, fd);
	if (result != BLOB_RESULT_SUCCESS) {
		goto fail;
	}
	ret = fsync(fd);
	if (ret == -1) {
		goto fail_with_errno;
	}
	ret = close(fd);
	if (ret == -1) {
		goto fail_with_errno;
	}
	if (wk->tmpname_template != NULL) {
		ret = rename(tmp_name, wk->filename);
		if (ret == -1) {
			goto fail_with_errno;
		}
	}
	ret = sync_parent_dir(wk->filename);
	if (ret == -1) {
		goto fail_with_errno;
	}
	free(tmp_name);
	return BLOB_RESULT_SUCCESS;
fail_with_errno:
	wk->error = errno;
	result = BLOB_RESULT_ERROR;
fail:
	if (fd != -1) {
		close(fd);
		if (tmp_name != NULL) {
			unlink(tmp_name);
		}
	}
	free(tmp_name);
	return result;
}

static unsigned int
blob_get_memory(struct blob_work *wk,
		unsigned int (*do_get)(struct blob_work *, int))
{
	if (wk->buffer == NULL || wk->buffer_size == 0) {
		wk->error = EINVAL;
		return BLOB_RESULT_ERROR;
	}

	return do_get(wk, -1);
}

unsigned int
blob_get(struct blob_work *wk, unsigned int (*do_get)(struct blob_work *, int))
{
	if ((wk->type != BLOB_TYPE_AZURE_BLOB) &&
	    (wk->type != BLOB_TYPE_HTTP) && (wk->type != BLOB_TYPE_HTTP_EXT)) {
		wk->error = EINVAL;
		return BLOB_RESULT_INVALID;
	}
	if (wk->op != BLOB_OP_GET) {
		wk->error = EINVAL;
		return BLOB_RESULT_INVALID;
	}
	if (wk->wk.status != WORK_STATUS_INPROGRESS) {
		wk->error = EBUSY;
		return BLOB_RESULT_ERROR;
	}

	unsigned int result;
	if (wk->filename != NULL) {
		result = blob_get_file(wk, do_get);
	} else {
		result = blob_get_memory(wk, do_get);
	}
	return result;
}
