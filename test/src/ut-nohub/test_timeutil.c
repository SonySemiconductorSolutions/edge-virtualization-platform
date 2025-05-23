/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <cmocka.h>

#include <internal/util.h>

#include "cdefs.h"
#include "hub.h"
#include "timeutil.h"

void
test_timeutil(void **state)
{
	struct timespec now;
	gettime(&now);

	/*
	 * this test is meant to be loose.
	 * we don't mock gettime.
	 */
	int fudge_ms = 50;
	struct timespec fudge;
	fudge.tv_sec = 0;
	fudge.tv_nsec = fudge_ms * 1000000;

	struct timespec result;
	struct timespec diff;
	struct timespec v;
	struct timespec t;

	int testcases[] = {
		0, 1, 10, 100, 1000,
	};
	unsigned int i;
	for (i = 0; i < __arraycount(testcases); i++) {
		v.tv_sec = testcases[i];
		v.tv_nsec = 0;
		relms2absts(v.tv_sec * 1000, &result);
		/* result >= now */
		assert_true(timespeccmp(&result, &now, >=));
		/* result - now - v <= fudge */
		timespecsub(&result, &now, &diff);
		timespecsub(&diff, &v, &diff);
		assert_true(timespeccmp(&diff, &fudge, <=));
		/* result - now - v + fudge >= 0 */
		timespecadd(&diff, &fudge, &t);
		assert_true(timespeccmp(&t, &fudge, >=));

		int ms = absts2relms_roundup(&result);
		assert_true(ms >= 0);
		assert_true(ms - testcases[i] * 1000 <= fudge_ms);
		assert_true(ms - testcases[i] * 1000 >= -fudge_ms);
	}

	/* past time should be converted to 0 */
	assert_true(absts2relms_roundup(&now) == 0);
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_timeutil),
	};
	// test run
	return cmocka_run_group_tests(tests, NULL, NULL);
}
