/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

#include <mbedtls/base64.h>

#include <internal/util.h>

#include "base64.h"
#include "xlog.h"

int
base64_encode(const void *src, size_t srclen, char **dstp, size_t *dstlenp)
{
	char *p = NULL;
	size_t buflen = 0;
	size_t len = 0;
	int ret;

	ret = mbedtls_base64_encode(NULL, 0, &buflen, src, srclen);
	if (ret == 0) {
		/*
		 * This seems like a bug in mbedtls_base64_encode
		 * as it needs 1 byte to store an empty string.
		 */
		p = xstrdup("");
		len = 0;
	} else if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		p = xmalloc(buflen);
		ret = mbedtls_base64_encode((void *)p, buflen, &len, src,
					    srclen);
		if (ret == 0) {
			/* + 1 for NUL */
			if (len + 1 > buflen) {
				xlog_error("base64 encode failed: buf too "
					   "small");
				ret = EINVAL;
			} else {
				p[len] = '\0'; // ensure zero termination
			}
		}
	}

	if (ret) {
		free(p);
		return ret;
	}

	*dstp = p;
	*dstlenp = len;
	return 0;
}

static int
_base64_decode(const char *src, size_t srclen, void **dstp, size_t *dstlenp,
	       bool append_nul)
{
	void *p = NULL;
	size_t buflen;
	size_t len;
	int ret;

	ret = mbedtls_base64_decode(NULL, 0, &buflen, (const void *)src,
				    srclen);
	if (ret == 0) {
		/*
		 * Avoid 0 byte malloc, which might not be portable.
		 */
		*dstp = xmalloc(1);
		*dstlenp = 0;
		return 0;
	} else if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		p = xmalloc(buflen + (int)append_nul);
		ret = mbedtls_base64_decode(p, buflen, &len, (const void *)src,
					    srclen);
	}

	if (ret) {
		free(p);
		return EINVAL;
	}

	if (append_nul) {
		char *cp = p;

		cp[len] = 0;
		len++;
	}
	*dstp = p;
	*dstlenp = len;
	return 0;
}

int
base64_decode(const char *src, size_t srclen, void **dstp, size_t *dstlen)
{
	return _base64_decode(src, srclen, dstp, dstlen, false);
}

/**
 * @brief A dirty hack to avoid a memory allocation in the caller.
 *
 * See blob_type_evp.c.
 */

int
base64_decode_append_nul(const char *src, size_t srclen, void **dstp,
			 size_t *dstlen)
{
	return _base64_decode(src, srclen, dstp, dstlen, true);
}
