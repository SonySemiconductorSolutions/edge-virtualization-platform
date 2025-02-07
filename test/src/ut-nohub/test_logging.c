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
#include <evp/agent.h>
#include <parson.h>

#include "cdefs.h"
#include "hub.h"
#include "platform.h"
#include "version.h"
#include "xlog.h"

#define FORMAT "this is a format string with int=%d"

static int dummy_user;

static void
vprint_override(int lvl, const char *file, int line, const char *fmt,
		va_list ap, void *user)
{
	check_expected(lvl);
	check_expected(file);
	check_expected(fmt);
	int ap_int = va_arg(ap, int);
	check_expected(ap_int);
	check_expected(user);
}

static int
setup_log_override(void **state)
{
	struct evp_agent_context *ctxt;
	struct evp_agent_platform plat = {
		.user = &dummy_user,
		.dlog = vprint_override,
	};

	ctxt = evp_agent_setup("test_logging");

	evp_agent_platform_register(ctxt, &plat);

	*state = ctxt;

	return 0;
}

static int
teardown_log_override(void **state)
{
	struct evp_agent_context *ctxt = *state;

	evp_agent_free(ctxt);
	*state = NULL;

	return 0;
}

static void
test_log_override(void **state)
{
	expect_value(vprint_override, lvl, XLOG_LEVEL_INFO);
	expect_string(vprint_override, fmt, FORMAT);
	expect_string(vprint_override, file, __FILE__);
	expect_value(vprint_override, ap_int, 123);
	expect_value(vprint_override, user, &dummy_user);

	xlog_info(FORMAT, 123);
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_log_override,
						setup_log_override,
						teardown_log_override),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, NULL, NULL);
}
