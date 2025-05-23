/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/utsname.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include <parson.h>

#include "cdefs.h"
#include "hub.h"
#include "system_info.h"
#include "version.h"

#define WAMR_TEST_MAJOR_VERSION 1
#define WAMR_TEST_MINOR_VERSION 2
#define WAMR_TEST_PATCH_VERSION 3

#define WAMR_TEST_VERSION                                                     \
	"v" ___STRING(WAMR_TEST_MAJOR_VERSION) "." ___STRING(                 \
		WAMR_TEST_MINOR_VERSION) "." ___STRING(WAMR_TEST_PATCH_VERSION)

static const struct utsname expected = {.sysname = "test-sysname",
					.machine = "test-machine",
					.version = "v" AGENT_VERSION};

int
__wrap_uname(struct utsname *buf)
{
	*buf = expected;
	return 0;
}

void
__wrap_wasm_runtime_get_version(uint32_t *major, uint32_t *minor,
				uint32_t *patch)
{
	*major = WAMR_TEST_MAJOR_VERSION;
	*minor = WAMR_TEST_MINOR_VERSION;
	*patch = WAMR_TEST_PATCH_VERSION;
}

static void
test_system_info(void **state)
{
	JSON_Value *info = hub_evp2_tb_get_system_info();
	assert_non_null(info);

	JSON_Object *o = json_value_get_object(info);
	assert_non_null(o);

	static const struct {
		const char *key, *expected;
	} values[] = {
		{.key = "os", .expected = expected.sysname},
		{.key = "arch", .expected = expected.machine},
		{.key = "evp_agent", .expected = expected.version},
		{.key = "protocolVersion", .expected = "EVP2-TB"},
		{.key = "wasmMicroRuntime", .expected = WAMR_TEST_VERSION}};

	for (size_t i = 0; i < __arraycount(values); i++) {
		const char *s = json_object_get_string(o, values[i].key);

		assert_non_null(s);
		assert_string_equal(s, values[i].expected);
	}

	json_value_free(info);
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_system_info),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, NULL, NULL);
}
