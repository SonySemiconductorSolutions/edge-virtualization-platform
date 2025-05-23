/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <dlfcn.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>

#include <cmocka.h>
#include <wasm_export.h>

#include "hub.h"
#include "module_api_wasm.h"

void *__real_dlsym(void *, const char *restrict);
void *__real_dlopen(const char *, int);

static int dummy_hdl;
static int library_registered;

static int
foo_native(wasm_exec_env_t exec_env, int a, int b)
{
	return a + b;
}

static void
foo2(wasm_exec_env_t exec_env, char *msg, uint8_t *buffer, int buf_len)
{
	strncpy((char *)buffer, msg, buf_len);
}

static NativeSymbol native_symbols_exp[] = {
	{
		"foo",      // the name of WASM function name
		foo_native, // the native function pointer
		"(ii)i"     // the function prototype signature
	},
	{
		"foo2", // the name of WASM function name
		foo2,   // the native function pointer
		"($*~)" // the function prototype signature
	}};

static uint32_t
mock_get_native_lib(char **namep, NativeSymbol **symbolsp)
{
	*namep = "env";
	*symbolsp = native_symbols_exp;
	return 2;
}

bool
__wrap_wasm_runtime_init(void)
{
	return true;
}

void *
__wrap_dlopen(const char *filename, int flags)
{
	if (strcmp(filename, "wasmlib.so") != 0) {
		return __real_dlopen(filename, flags);
	}
	assert_string_equal(filename, "wasmlib.so");
	assert_int_equal(flags, RTLD_NOW);

	return &dummy_hdl;
}

void *
__wrap_dlsym(void *restrict handle, const char *restrict symbol)
{
	if (handle != &dummy_hdl) {
		return __real_dlsym(handle, symbol);
	}
	assert_ptr_equal(handle, &dummy_hdl);
	assert_string_equal(symbol, "get_native_lib");
	return mock_get_native_lib;
}

bool
__wrap_wasm_runtime_register_natives(const char *module_name,
				     NativeSymbol *native_symbols,
				     uint32_t n_native_symbols)
{
	if (native_symbols == native_symbols_exp) {
		assert_ptr_equal(native_symbols, native_symbols_exp);
		assert_string_equal(module_name, "env");
		assert_int_equal(n_native_symbols, 2);
		library_registered = 1;
	}

	return true;
}

void
test_wasm_add_native_lib(void **arg)
{
	wasm_add_native_lib("wasmlib.so");
	module_api_init_wasm();
	assert_int_equal(library_registered, 1);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_wasm_add_native_lib),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
