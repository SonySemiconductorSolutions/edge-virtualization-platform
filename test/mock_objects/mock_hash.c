/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module_impl.h"

#include "hash.h"

__attribute__((weak)) int
__wrap_check_hash(struct module *module, const unsigned char *ref,
		  size_t ref_len, char **result)
{
	*result = NULL;
	return 0;
}
