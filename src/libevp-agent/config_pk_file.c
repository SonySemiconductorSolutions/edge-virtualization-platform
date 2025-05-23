/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/version.h>

#include <internal/config_impl.h>
#include <internal/util.h>

#include "cdefs.h"
#include "platform.h"
#include "tls.h"
#include "xlog.h"

int
config_load_pk_file(const char *filename, void **vpp, size_t *sizep)
{
	int ret;
	FILE *f = NULL;
	char *buf = NULL;
	long size;

	if ((f = fopen(filename, "rb")) == NULL) {
		ret = errno;
		xlog_error("fopen(3) %s: %d\n", filename, errno);
		goto end;
	}

	/* Ensure no stdio buffering of secrets, as such buffers cannot be
	 * wiped. */
	setbuf(f, NULL);

	if (fseek(f, 0, SEEK_END)) {
		ret = errno;
		xlog_error("fseek(3) %s SEEK_END: %d", filename, errno);
		goto end;
	}

	if ((size = ftell(f)) < 0) {
		ret = errno;
		xlog_error("ftell(3) %s: %d", filename, errno);
		goto end;
	}

	if (fseek(f, 0, SEEK_SET)) {
		ret = errno;
		xlog_error("fseek(3) %s SEEK_SET: %d", filename, errno);
		goto end;
	}

	if ((unsigned long)size > SIZE_MAX - 1) {
		ret = ERANGE;
		xlog_error("%s: file size overflow", filename);
		goto end;
	}

	if ((buf = plat_secure_malloc(size + 1)) == NULL) {
		ret = ENOMEM;
		xlog_error("mbedtls_calloc failed");
		goto end;
	}

	if (fread(buf, size, 1, f) == 0) {
		ret = EIO;
		xlog_error("fread(3) %s failed, feof=%d, ferror=%d", filename,
			   feof(f), ferror(f));
		goto end;
	}

	buf[size] = '\0';
	/* These explicit casts are not required. size is garanteed to be
	 * smaller than SIZE_MAX-1, but we add here to silence Fortify.
	 */
	*sizep = strstr(buf, "-----BEGIN ") ? (unsigned long)size + 1
					    : (unsigned long)size;
	*vpp = buf;
	ret = 0;

end:
	if (f != NULL && fclose(f)) {
		ret = EIO;
		xlog_error("fclose(3) %s: %d", filename, errno);
	}

	if (ret != 0) {
		if (buf) {
			mbedtls_platform_zeroize(buf, size);
		}

		plat_secure_free(buf);
	}

	return ret;
}

void
config_unload_pk_file(void *vp, size_t size)
{
	mbedtls_platform_zeroize(vp, size);
	plat_secure_free(vp);
}
