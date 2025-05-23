/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <chan_def.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <cmocka.h>

#include <internal/chan.h>

struct test {
	struct chan *ch;
	unsigned n_dequeued;
} g_test;

int
__wrap_pthread_mutex_lock(pthread_mutex_t *mutex)
{
	return 0;
}

int
__wrap_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
	return 0;
}

int
__wrap_pthread_cond_signal(pthread_cond_t *cond)
{
	return 0;
}

struct chan_item *
__wrap_chan_dequeue(struct chan *ch)
{
	struct chan_item *__real_chan_dequeue(struct chan * ch);

	return __real_chan_dequeue(ch);
}

int
__wrap_sem_wait(sem_t *sem)
{
	/* Sync messages are expected to have been removed from the queue
	 * inside a struct chan instance once sem_wait returns.
	 * Otherwise, chan_dealloc would run into a double-free condition
	 * when deallocating the struct chan_item instances inside it. */
	chan_dequeue(g_test.ch);
	g_test.n_dequeued++;
	function_called();
	return 0;
}

static void
callback(struct chan_msg *msg)
{
}

static void
test_chan_send_sync(void **state)
{
	struct chan *ch = g_test.ch;
	int param, resp;
	struct chan_msg msg = {.fn = callback, .param = &param, .resp = &resp};

	expect_function_call(__wrap_sem_wait);
	assert_int_equal(chan_send(ch, &msg), 1);
	assert_int_equal(g_test.n_dequeued, 1);
}

static void
test_chan_send_async(void **state)
{
	struct chan *ch = g_test.ch;
	int param;
	struct chan_msg msg = {.fn = callback, .param = &param};

	assert_int_equal(chan_send(ch, &msg), 1);
	assert_int_equal(chan_size(ch), 1);
	assert_int_equal(g_test.n_dequeued, 0);
}

static void
test_chan_send_multiple(void **state)
{
	struct chan *ch = g_test.ch;
	struct chan_msg msg = {0};

	assert_int_equal(chan_send(ch, &msg), 1);
	assert_int_equal(chan_send(ch, &msg), 1);
	assert_int_equal(chan_size(ch), 2);
}

static int
setup(void **state)
{
	struct chan *ch = chan_alloc();

	if (!ch) {
		return -1;
	}

	g_test = (struct test){.ch = ch};

	return 0;
}

static int
teardown(void **state)
{
	chan_dealloc(g_test.ch);
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_chan_send_sync, setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_chan_send_async, setup,
						teardown),
		cmocka_unit_test_setup_teardown(test_chan_send_multiple, setup,
						teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
