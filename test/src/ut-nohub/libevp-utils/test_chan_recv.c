/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <chan_def.h>
#include <limits.h>
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

static void
sync_callback(struct chan_msg *msg)
{
	*(int *)msg->resp = 1;
	check_expected(msg->param);
	check_expected(msg->resp);
	check_expected(msg);
	function_called();
}

static void
async_callback(struct chan_msg *msg)
{
	check_expected(msg->param);
	check_expected(msg->resp);
	check_expected(msg);
	function_called();
}

static struct state {
	struct chan *ch;
	struct chan_item *it;
	void *param;
	int resp;
	void (*send_msg)(void);
	unsigned n_locks;
} g_test;

static void
expect_sync(struct chan_msg *msg)
{
	expect_function_call(sync_callback);
	expect_value(sync_callback, msg, msg);
	expect_value(sync_callback, msg->param, &g_test);
	expect_value(sync_callback, msg->resp, &g_test.resp);
	expect_function_call(__wrap_sem_post);
}

static void
expect_async(struct chan_msg *msg)
{
	expect_function_call(async_callback);
	expect_value(async_callback, msg, msg);
	expect_value(async_callback, msg->param, &g_test);
	expect_value(async_callback, msg->resp, NULL);
}

static void
send_sync_msg(void)
{
	struct chan_item *it = chan_item_alloc();
	struct chan_msg msg = {
		.fn = sync_callback,
		.param = &g_test,
		.resp = &g_test.resp,
	};

	assert_non_null(it);
	g_test.it = it;
	chan_enqueue(g_test.ch, it, &msg);
	expect_sync(&it->msg);
}

static void
send_async_msg(void)
{
	struct chan_item *it = chan_item_alloc();
	struct chan_msg msg = {
		.fn = async_callback,
		.param = &g_test,
	};

	assert_non_null(it);
	chan_enqueue(g_test.ch, it, &msg);
	expect_async(&it->msg);
}

static int
setup_with(void (*fn)(void), struct chan_msg *msg)
{
	struct chan *ch = chan_alloc();
	struct chan_item *it = chan_item_alloc();

	if (!ch || !it)
		goto failure;

	chan_enqueue(ch, it, msg);

	g_test = (struct state){
		.ch = ch,
		.it = it,
		.send_msg = fn,
	};

	return 0;

failure:
	chan_item_dealloc(it);
	chan_dealloc(ch);
	return -1;
}

static int
setup_with_async(void **state)
{
	struct chan_msg msg = {
		.fn = async_callback,
		.param = &g_test,
	};

	return setup_with(send_async_msg, &msg);
}

static int
setup_with_sync(void **state)
{
	struct chan_msg msg = {
		.fn = sync_callback,
		.param = &g_test,
		.resp = &g_test.resp,
	};

	return setup_with(send_sync_msg, &msg);
}

static int
setup_without(void (*fn)(void))
{
	struct chan *ch = chan_alloc();

	if (!ch)
		goto failure;

	g_test = (struct state){.ch = ch, .send_msg = fn};

	return 0;

failure:
	chan_dealloc(ch);
	return -1;
}

static int
setup_without_async(void **state)
{
	return setup_without(send_async_msg);
}

static int
setup_without_sync(void **state)
{
	return setup_without(send_sync_msg);
}

int
__wrap_pthread_mutex_unlock(pthread_mutex_t *m)
{
	assert_int_equal(g_test.n_locks--, 1);
	return 0;
}

int
__wrap_pthread_mutex_lock(pthread_mutex_t *m)
{
	assert_int_equal(g_test.n_locks++, 0);
	return 0;
}

int
__wrap_sem_post(sem_t sem)
{
	struct chan_item *it = g_test.it;

	assert_non_null(it);
	chan_item_dealloc(it);
	function_called();
	return 0;
}

int
__wrap_sem_wait(sem_t sem)
{
	function_called();
	return 0;
}

int
__wrap_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	assert_non_null(g_test.send_msg);
	g_test.send_msg();
	function_called();
	return 0;
}

static void
test_chan_recv_sync(void **state)
{
	expect_sync(&g_test.it->msg);

	assert_int_equal(chan_recv(g_test.ch), 1);
	assert_int_equal(g_test.resp, 1);
}

static void
test_chan_recv_async(void **state)
{
	expect_async(&g_test.it->msg);

	assert_int_equal(chan_recv(g_test.ch), 1);
}

static void
test_chan_recv_empty_sync(void **state)
{
	expect_function_call(__wrap_pthread_cond_wait);

	assert_int_equal(chan_recv(g_test.ch), 1);
	assert_int_equal(g_test.resp, 1);
}

static void
test_chan_recv_empty_async(void **state)
{
	expect_function_call(__wrap_pthread_cond_wait);

	assert_int_equal(chan_recv(g_test.ch), 1);
}

static void
test_chan_tryrecv_sync(void **state)
{
	expect_sync(&g_test.it->msg);

	assert_int_equal(chan_tryrecv(g_test.ch), 1);
	assert_int_equal(g_test.resp, 1);
}

static void
test_chan_tryrecv_async(void **state)
{
	expect_async(&g_test.it->msg);

	assert_int_equal(chan_tryrecv(g_test.ch), 1);
}

static void
test_chan_tryrecv_empty_sync(void **state)
{
	assert_int_equal(chan_tryrecv(g_test.ch), 0);
}

static void
test_chan_tryrecv_empty_async(void **state)
{
	assert_int_equal(chan_tryrecv(g_test.ch), 0);
}

static void
test_chan_timedwait_sync(void **state)
{
	expect_sync(&g_test.it->msg);

	assert_int_equal(chan_timedrecv(g_test.ch, INT_MAX), 1);
	assert_int_equal(g_test.resp, 1);
}

static void
test_chan_timedwait_async(void **state)
{
	expect_async(&g_test.it->msg);

	assert_int_equal(chan_timedrecv(g_test.ch, INT_MAX), 1);
}

static void
test_chan_timedwait_empty_sync(void **state)
{
	assert_int_equal(chan_timedrecv(g_test.ch, 0), 0);
}

static void
test_chan_timedwait_empty_async(void **state)
{
	assert_int_equal(chan_timedrecv(g_test.ch, 0), 0);
}

static int
teardown(void **state)
{
	chan_dealloc(g_test.ch);
	return 0;
}

/*
 * chan_timedwait() requires more testing than done here.
 *
 * The following extra cases are missing:
 * 	- chan_timedwait() times out after some time when
 *		calling clock_gettime(3), without a message.
 * 	- chan_timedwait() times out after some time when
 *		calling pthread_cond_timedwait(3), without a message.
 *	- chan_timedwait() waits for some time and receives a message.
 *
 * Since testing the cases above would require significant effort,
 * it was considered that other kinds of tests, such as system tests,
 * would still provide coverage while testing a more realistic scenario.
 *
 * After all, unit testing would require mocking many system functions,
 * so that they would be testing an unrealistic scenario.
 */
int
main(void)
{
	/*
	 * The following test is defined:
	 *	- sync: A synchronous callback (i.e., with a response attached
	 *to it) shall be triggered by the test function once a struct
	 *chan_item is available.
	 *	- async: An asynchronous callback (i.e., with no response
	 *attached to it) shall be triggered by the test function once a struct
	 *chan_item is available.
	 *	- empty: No struct chan_item instances are allocated by the
	 *setup function.
	 *	- non-empty: A struct chan_item is allocated by the setup
	 *function.
	 *
	 * The variants above are then implemented for all chan_*recv
	 *functions:
	 *	- chan_recv
	 *	- chan_tryrecv
	 *	- chan_timedwait
	 */

	/* clang-format off */
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_chan_recv_sync, setup_with_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_recv_empty_sync, setup_without_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_recv_async, setup_with_async, teardown),
		cmocka_unit_test_setup_teardown(test_chan_recv_empty_async, setup_without_async, teardown),
		cmocka_unit_test_setup_teardown(test_chan_tryrecv_sync, setup_with_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_tryrecv_empty_sync, setup_without_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_tryrecv_empty_async, setup_without_async, teardown),
		cmocka_unit_test_setup_teardown(test_chan_tryrecv_async, setup_with_async, teardown),
		cmocka_unit_test_setup_teardown(test_chan_timedwait_sync, setup_with_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_timedwait_empty_sync, setup_without_sync, teardown),
		cmocka_unit_test_setup_teardown(test_chan_timedwait_async, setup_with_async, teardown),
		cmocka_unit_test_setup_teardown(test_chan_timedwait_empty_async, setup_without_async, teardown),
	};
	/* clang-format on */

	return cmocka_run_group_tests(tests, NULL, NULL);
}
