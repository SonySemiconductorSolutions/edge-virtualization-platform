/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// these includes are required by cmocka and must precede <cmocka.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>
#include <wasm_export.h>

#include "hub.h"
#include "module_api_wasm.h"

int
foo_native(wasm_exec_env_t exec_env, int a, int b)
{
	return a + b;
}

void
foo2(wasm_exec_env_t exec_env, char *msg, uint8_t *buffer, int buf_len)
{
	strncpy((char *)buffer, msg, buf_len);
}

static NativeSymbol native_symbols[] = {
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

bool
__wrap_wasm_runtime_register_natives(const char *module_name,
				     NativeSymbol *symbols, uint32_t n_symbols)
{
	if (strcmp(module_name, "test-env") == 0) {
		check_expected(n_symbols);
		check_expected(symbols[0].symbol);
		check_expected(symbols[1].symbol);
	}
	return true;
}

uint32_t
get_native_lib(char **namep, NativeSymbol **symbolsp)
{
	*symbolsp = native_symbols;
	*namep = "test-env";
	return 2;
}

void
test_get_native_lib(void **state)
{
	expect_value(__wrap_wasm_runtime_register_natives, n_symbols, 2);
	expect_string(__wrap_wasm_runtime_register_natives, symbols[0].symbol,
		      "foo");
	expect_string(__wrap_wasm_runtime_register_natives, symbols[1].symbol,
		      "foo2");
	module_api_init_wasm();
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_get_native_lib),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, NULL, NULL);
}
