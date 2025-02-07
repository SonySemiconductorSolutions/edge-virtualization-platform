/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <internal/util.h>

#include "agent_test.h"
#include "timeutil.h"
#include "work.h"
#include "xpthread.h"

/***************************************************
 *       Tests for the worker manager at work.c    *
 **************************************************/

enum custom_status { INITIAL, EXECUTING, DONE, DONE_BY_CB };

struct sync_ctxt {
	struct evp_lock lock;
	pthread_cond_t cond;
	enum custom_status predicate;
};

struct work_item {
	struct work wk;
	enum custom_status my_status;
	struct sync_ctxt status_pilot;
	struct sync_ctxt finish_pilot;
	bool wait_for_finish_signal;
};

int
sync_init(struct sync_ctxt *ctxt)
{
	int rv;
	rv = pthread_cond_init(&ctxt->cond, NULL);
	if (rv) {
		return rv;
	}

	rv = pthread_mutex_init(&ctxt->lock.lock, NULL);
	if (rv) {
		return rv;
	}

	return 0;
}

void
sync_set(struct sync_ctxt *ctxt, enum custom_status predicate)
{
	xpthread_mutex_lock(&ctxt->lock);
	ctxt->predicate = predicate;
	xpthread_cond_signal(&ctxt->cond);
	xpthread_mutex_unlock(&ctxt->lock);
}

void
sync_wait_for(struct sync_ctxt *ctxt, enum custom_status expected_predicate)
{
	xpthread_mutex_lock(&ctxt->lock);
	while (ctxt->predicate != expected_predicate) {
		xpthread_cond_wait(&ctxt->cond, &ctxt->lock);
	}
	xpthread_mutex_unlock(&ctxt->lock);
}

struct work *
work_item_done_cb(struct work *gwk)
{
	struct work_item *wk = (void *)gwk;
	wk->my_status = DONE_BY_CB;
	sync_set(&wk->status_pilot, wk->my_status);
	return NULL;
}

void
work_item_init(struct work_item *wk)
{
	work_set_defaults(&wk->wk);
	wk->my_status = INITIAL;
	wk->wk.done = work_item_done_cb;
	sync_init(&wk->status_pilot);
	sync_init(&wk->finish_pilot);
	sync_set(&wk->status_pilot, INITIAL);
	sync_set(&wk->finish_pilot, INITIAL);
	wk->wait_for_finish_signal = true;
}

void
process_work_item(struct worker *worker, struct work *gwk)
{
	struct work_item *wk = (void *)gwk;
	wk->my_status = EXECUTING;
	sync_set(&wk->status_pilot, wk->my_status);
	if (wk->wait_for_finish_signal) {
		sync_wait_for(&wk->finish_pilot, DONE_BY_CB);
	}
}

void
test_start_stop(void **state)
{
	struct worker worker_manager;

	/* worker_manager mini_start */
	worker_manager.name = "mini worker 0";
	worker_manager.process_item = process_work_item;
	worker_manager.max_jobs = 1;
	worker_manager_start(&worker_manager);
	worker_manager_stop(&worker_manager);
	assert_true(true);
}

void
test_work_single_job(void **state)
{
	struct worker worker_manager;
	struct workq *workq;

	/* worker_manager mini_start */
	worker_manager.name = "mini worker 1";
	worker_manager.process_item = process_work_item;
	worker_manager.max_jobs = 1;
	worker_manager_start(&worker_manager);
	workq = &worker_manager.q;

	// create an item
	struct work_item wk0;
	work_item_init(&wk0);

	// push it into the queue
	work_enqueue(workq, &wk0.wk);

	// wait for it signal its 'executing' state
	sync_wait_for(&wk0.status_pilot, EXECUTING);
	assert_true(wk0.my_status == EXECUTING);

	// signal the worker to go to the 'done' state by callback
	sync_set(&wk0.finish_pilot, DONE_BY_CB);
	// then nwait for it signal its 'done' state
	sync_wait_for(&wk0.status_pilot, DONE_BY_CB);
	assert_true(wk0.my_status == DONE_BY_CB);

	worker_manager_stop(&worker_manager);
	assert_true(true);
}

void
test_work_two_jobs(void **state)
{
	struct worker worker_manager;
	struct workq *workq;

	/* worker_manager mini_start */
	worker_manager.name = "mini worker 2";
	worker_manager.process_item = process_work_item;
	worker_manager.max_jobs = 1;
	worker_manager_start(&worker_manager);
	workq = &worker_manager.q;

	// create first item
	struct work_item wk0, wk1;
	work_item_init(&wk0);
	work_item_init(&wk1);
	wk1.wait_for_finish_signal = false;

	// push first one into the queue
	work_enqueue(workq, &wk0.wk);
	work_enqueue(workq, &wk1.wk);

	// wait for it signal its 'executing' state
	sync_wait_for(&wk0.status_pilot, EXECUTING);
	assert_true(wk0.my_status == EXECUTING);

	// signal the worker to go to the 'done' state by callback
	sync_set(&wk0.finish_pilot, DONE_BY_CB);

	// then nwait for it signal its 'done' state
	sync_wait_for(&wk0.status_pilot, DONE_BY_CB);
	assert_true(wk0.my_status == DONE_BY_CB);
	sync_wait_for(&wk1.status_pilot, DONE_BY_CB);
	assert_true(wk1.my_status == DONE_BY_CB);

	worker_manager_stop(&worker_manager);
	assert_true(true);
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_start_stop),
		cmocka_unit_test(test_work_single_job),
		cmocka_unit_test(test_work_two_jobs),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, NULL, NULL);
}
