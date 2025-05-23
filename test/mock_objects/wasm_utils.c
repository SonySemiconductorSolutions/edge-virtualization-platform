/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "wasm_export.h"
#include "wasm_utils.h"

uint32_t
evp_wasm_string_create(wasm_module_inst_t module_inst, const char *attr_string)
{
	uint32_t offset;

	if (attr_string == NULL) {
		offset = 0;
	} else {
		char *alloc_string = NULL;
		uint32_t attr_string_sz = strlen(attr_string) + 1;
		offset = module_malloc(attr_string_sz, (void **)&alloc_string);
		memcpy(alloc_string, attr_string, attr_string_sz);
	}
	return offset;
}

uint32_t
evp_wasm_string_array_create(wasm_module_inst_t module_inst,
			     const char *const *attr_array, int len)
{
	uint32_t offset;
	uint32_t *alloc_array = NULL;
	uint32_t attr_string_sz = len * sizeof(uint32_t);
	offset = module_malloc(attr_string_sz, (void **)&alloc_array);
	for (int i = 0; i < len; i++) {
		alloc_array[i] =
			evp_wasm_string_create(module_inst, attr_array[i]);
	}
	return offset;
}
