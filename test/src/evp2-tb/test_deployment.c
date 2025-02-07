/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <cmocka.h>
#include <parson.h>

#include "deployment.h"
#include "manifest.h"
#include "reconcile.h"

void
test_create_invalid(void **state)
{
	struct Deployment *deployment = NULL;
	const JSON_Object *specs, *modules;
	JSON_Value *val = json_value_init_object();
	const JSON_Object *obj = json_object(val);
	// try to parse a manifest with missing required elements
	int ret = create_deployment(obj, &deployment, &specs, &modules);
	assert_int_equal(ret, EINVAL);
	assert_null(deployment);
	json_value_free(val);
}

void
test_create_empty(void **state)
{
	struct Deployment *deployment = create_empty_deployment();
	assert_non_null(deployment);
	free_deployment(deployment);
}

int
pause_setup(void **state)
{
	static struct deployment deployment;

	deployment_init(&deployment);

	*state = &deployment;
	return 0;
}

void
try_pause_when_deployment_in_progress(void **state)
{
	struct deployment *deployment = *state;
	assert_int_equal(deployment_acquire(deployment), 0);
	assert_int_equal(deployment_request_pause(deployment), EAGAIN);
	assert_int_equal(deployment_resume(deployment), 0);
	deployment_release(deployment);
	assert_int_equal(deployment_request_pause(deployment), 0);
	assert_int_equal(deployment_resume(deployment), 0);
}

void
try_pause_when_deployment_idle(void **state)
{
	struct deployment *deployment = *state;
	assert_int_equal(deployment_request_pause(deployment), 0);
	assert_int_equal(deployment_acquire(deployment), EAGAIN);
	assert_int_equal(deployment_resume(deployment), 0);
	assert_int_equal(deployment_acquire(deployment), 0);
	deployment_release(deployment);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_create_invalid),
		cmocka_unit_test(test_create_empty),
		cmocka_unit_test_setup(try_pause_when_deployment_in_progress,
				       pause_setup),
		cmocka_unit_test_setup(try_pause_when_deployment_idle,
				       pause_setup),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
