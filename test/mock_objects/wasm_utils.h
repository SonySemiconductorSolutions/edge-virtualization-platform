/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wasm_export.h"

uint32_t evp_wasm_string_create(wasm_module_inst_t module_inst,
				const char *attr_string);
uint32_t evp_wasm_string_array_create(wasm_module_inst_t module_inst,
				      const char *const *attr_array, int len);
