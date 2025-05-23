/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>

#include <mbedtls/md.h>

#include <internal/util.h>

#include "module_impl.h"
#include "platform.h"
#include "xlog.h"

#include "hash.h"

int
check_hash(struct module *module, const unsigned char *ref, size_t ref_len,
	   char **result)
{
	int ret;

	mbedtls_md_type_t type = MBEDTLS_MD_SHA256;
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(type);
	if (info == NULL) {
		return EINVAL;
	}

	const char *md_name = mbedtls_md_get_name(info);
	const size_t byte_size = mbedtls_md_get_size(info);
	if (ref_len != byte_size) {
		return EINVAL;
	}

	unsigned char *calc = malloc(byte_size);
	if (!calc) {
		return ENOMEM;
	}

	int rv;

	size_t size;
	const void *input = NULL;
	void *handle = NULL;
	int error = 0;
	handle = plat_mod_fs_file_mmap(module, &input, &size, false, &error);
	if (handle == NULL) {
		ret = error ? error : EIO;
		goto finish;
	}
	rv = mbedtls_md(info, input, size, calc);
	plat_mod_fs_file_munmap(handle);
	if (rv != 0) {
		ret = EIO;
		goto finish;
	}

	/* Show hash comparison */
	{
		char *ref_string = malloc(byte_size * 2 + 1);
		char *calc_string = malloc(byte_size * 2 + 1);

		if (!ref_string || !calc_string) {
			free(ref_string);
			free(calc_string);
			ret = ENOMEM;
			goto finish;
		}
		char *r = bin_array_to_hexchar(ref, byte_size, ref_string,
					       sizeof(ref_string));
		char *c = bin_array_to_hexchar(calc, byte_size, calc_string,
					       sizeof(calc_string));

		if (!r || !c) {
			xlog_error("bin_array_to_hexchar failed:%s%s",
				   r ? "" : " (reference)",
				   c ? "" : " (calculated)");
		} else {
			xlog_info("moduleId = %s hash (%s) reference: -%s- "
				  "calculated "
				  "-%s-",
				  module->moduleId, md_name, r, c);
		}

		free(ref_string);
		free(calc_string);
	}

	size_t i;
	for (i = 0; i < byte_size; i++) {
		if (calc[i] != ref[i]) {
			xlog_warning("%s: %s did not match.", __func__,
				     module->moduleId);
			*result = xstrdup("Module hash mismatch");
			ret = 0;
			goto finish;
		}
	}
	xlog_info("%s: %s correct.", __func__, module->moduleId);
	*result = NULL;
	ret = 0;

finish:
	free(calc);
	return ret;
}
