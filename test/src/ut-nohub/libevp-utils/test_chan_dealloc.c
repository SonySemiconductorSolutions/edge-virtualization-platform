/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <chan_def.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include <internal/chan.h>

static struct chan ch = {
	.cond = PTHREAD_COND_INITIALIZER,
	.m = PTHREAD_MUTEX_INITIALIZER,
};

int
__wrap_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	assert_ptr_equal(mutex, &ch.m);
	function_called();
	return 0;
}

int
__wrap_pthread_cond_destroy(pthread_cond_t *cv)
{
	assert_ptr_equal(cv, &ch.cond);
	function_called();
	return 0;
}

void
__wrap_free(void *p)
{
	assert_ptr_equal(p, &ch);
	function_called();
}

void
test_chan_dealloc(void **state)
{
	expect_function_call(__wrap_pthread_cond_destroy);
	expect_function_call(__wrap_pthread_mutex_destroy);
	expect_function_call(__wrap_free);
	chan_dealloc(&ch);
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_chan_dealloc),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
