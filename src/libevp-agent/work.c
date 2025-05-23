/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* for pthread_setname_np */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "main_loop.h"
#include "work.h"
#include "xlog.h"
#include "xpthread.h"

static struct work *
pick_work(struct workq *q, unsigned int status) EVP_REQUIRES(q->lock)
{
	struct work *wk;

	TAILQ_FOREACH (wk, &q->q, q) {
		if (wk->status == status) {
			return wk;
		}
	}
	return NULL;
}

struct worker_job {
	struct worker *worker;
	struct work *wk;
};

static struct work *
worker_notify(struct worker *worker, struct work *wk)
{
	/*
	 * We call wk->done() without holding any locks.
	 *
	 * wk->done() can free the wk.
	 *
	 * It's users' responsibility to serialize with work_trycancel.
	 * For example, sdk the blob stuff uses sdk_lock() to serialize
	 * wk->done() and work_trycancel.
	 */
	if (wk->done != NULL) {
		wk = wk->done(wk);
	} else {
		/*
		 * The user didn't specify the callback.
		 * It usually implies work_trycancel()-based polling
		 * used by the main thread.
		 */
		main_loop_wakeup(worker->name);
	}
	return wk;
}

static void *
worker_job_process(void *vp)
{
	struct worker_job *my_work = (struct worker_job *)vp;

	struct workq *const q = &(my_work->worker->q);
	struct work *wk = my_work->wk;

	/* Only show message when there is parallel execution */
	if (my_work->worker->max_jobs != 1) {
		xlog_debug("Processing work cur/max %d/%d",
			   my_work->worker->cur_jobs,
			   my_work->worker->max_jobs);
	}

	my_work->worker->process_item(my_work->worker, wk);

	xpthread_mutex_lock(&q->lock);
	TAILQ_REMOVE(&q->q, wk, q);
	wk->status = WORK_STATUS_NOTIFICATION;
	xpthread_mutex_unlock(&q->lock);

	wk = worker_notify(my_work->worker, wk);

	xpthread_mutex_lock(&q->lock);
	if (wk != NULL) {
		wk->status = WORK_STATUS_DONE;
	}
	my_work->worker->cur_jobs--;
	int job_num __attribute__((unused)) = my_work->worker->cur_jobs;
	xpthread_mutex_unlock(&q->lock);

	/* Only show message when there is parallel execution */
	if (my_work->worker->max_jobs != 1) {
		xlog_debug("Ending work cur/max %d/%d", job_num,
			   my_work->worker->max_jobs);
	}

	free(my_work);
	return NULL;
}

int
worker_job_start(struct worker_job *wk_ind)
{
	pthread_t thread;
	int ret;
	size_t stack_size = 0;

#if defined(__NuttX__)
	stack_size = CONFIG_EVP_AGENT_WORKER_STACKSIZE;
#endif

	ret = xpthread_create(&thread, worker_job_process, wk_ind,
			      WORKER_PRIORITY, stack_size);
	if (ret != 0) {
		xlog_error("xpthread_create error %d", ret);
		return ret;
	}

	/* This thread ends itself */
	ret = pthread_detach(thread);
	if (ret != 0) {
		xlog_error("pthread_detach error %d", ret);
		return ret;
	}
	return 0;
}

static void
workq_init(struct workq *q)
{
	int ret;
	ret = pthread_mutex_init(&q->lock.lock, NULL);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_init error %d", ret);
	}
	ret = pthread_cond_init(&q->cv, NULL);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_init error %d", ret);
	}
	TAILQ_INIT(&q->q);
}

static void
workq_deinit(struct workq *q)
{
	int ret;

	xpthread_mutex_lock(&q->lock);
	ret = pthread_cond_destroy(&q->cv);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_error("pthread_cond_destroy error %d", ret);
	}
	xpthread_mutex_unlock(&q->lock);
	xpthread_mutex_destroy(&q->lock);
}

static void *
worker_manager_loop(void *vp)
{
	struct worker *worker = vp;
	struct workq *const q = &worker->q;
	worker->cur_jobs = 0;

#if defined(__NuttX__) || defined(__linux__)
	/* NuttX, Linux */
	pthread_setname_np(pthread_self(), worker->name);
#else
	/* macOS */
	pthread_setname_np(worker->name);
#endif

	for (;;) {
		struct work *wk = NULL;

		/* wait until gets new work in common queue */
		xpthread_mutex_lock(&q->lock);
		while (worker->should_live &&
		       ((wk = pick_work(q, WORK_STATUS_QUEUED)) == NULL)) {
			xpthread_cond_wait(&q->cv, &q->lock);
		}
		xpthread_mutex_unlock(&q->lock);
		if (!worker->should_live || !wk) {
			/* Wait for current jobs in progress before exiting
			 * thread.
			 * Job threads are in detached mode, and destroying
			 * lock before the job threads finish is likely to
			 * produce an error while aquiring lock in job thread.
			 *
			 * Timeout is necessary to avoid waiting for a thread
			 * blocked processing some I/O (a bug on webclient)
			 */
			int curr_jobs;
			int i = 0;
			do {
				sleep(1);
				i++;
				xpthread_mutex_lock(&q->lock);
				curr_jobs = worker->cur_jobs;
				xpthread_mutex_unlock(&q->lock);
			} while (curr_jobs && i >= 3);
			return NULL;
		}

		wk->status = WORK_STATUS_INPROGRESS;

		/* Prepare the work to dispatch for separate thread */
		struct worker_job *wk_ind;
		wk_ind = xmalloc(sizeof(*wk_ind));
		wk_ind->worker = worker;
		wk_ind->wk = wk;

		/* If not parallel processing, the same manager process work */
		if (worker->max_jobs <= 1) {
			worker->cur_jobs = 1; /* To show log consistency */
			worker_job_process(wk_ind);
		} else {
			bool should_live = true;
			/* Not use mutex to read this var, due to the only
			 * thread that increment cur_jobs is this (worker
			 * manager) */
			while (should_live &&
			       worker->cur_jobs == worker->max_jobs) {
				xlog_debug(
					"Waiting to get a free thread for %s",
					worker->name);
				/* Simplified wake up system with basic sleep.
				 * If there is not available thread for work,
				 * it already must wait (so add "an extra 1s"
				 * wait is not a real constrain) */
				sleep(1);
				xpthread_mutex_lock(&q->lock);
				should_live = worker->should_live;
				xpthread_mutex_unlock(&q->lock);
			}

			if (!should_live) {
				free(wk_ind);
				xpthread_mutex_lock(&q->lock);
				wk->status = WORK_STATUS_QUEUED;
				xpthread_mutex_unlock(&q->lock);
				continue;
			}

			int ret = worker_job_start(wk_ind);
			if (ret == 0) {
				xpthread_mutex_lock(&q->lock);
				worker->cur_jobs++;
				xpthread_mutex_unlock(&q->lock);
			} else {
				xlog_error("Failed to start worker thread %s",
					   worker->name);
				free(wk_ind);
				xpthread_mutex_lock(&q->lock);
				wk->status = WORK_STATUS_QUEUED;
				xpthread_mutex_unlock(&q->lock);
			}
		}
	}

	return NULL;
}

void
worker_manager_start(struct worker *worker)
{
	int ret = 0;
	size_t stack_size = 0;
#if defined(__NuttX__)
	stack_size = CONFIG_EVP_AGENT_WORKER_STACKSIZE;
#endif

	worker->should_live = true;
	workq_init(&worker->q);
	ret = xpthread_create(&worker->thread, worker_manager_loop, worker,
			      WORKER_MANAGER_PRIORITY, stack_size);
	if (ret != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("xpthread_create error %d", ret);
	}
}

void
worker_manager_stop(struct worker *worker)
{
	struct workq *const q = &worker->q;
	struct work *wk;

	/* Cancel all queued work and request thread to exit */
	xpthread_mutex_lock(&q->lock);
	while (true) {
		wk = pick_work(q, WORK_STATUS_QUEUED);
		if (wk == NULL) {
			break;
		}
		TAILQ_REMOVE(&q->q, wk, q);
		wk->status = WORK_STATUS_CANCELLED;
		xpthread_mutex_unlock(&q->lock);

		worker_notify(worker, wk);

		xpthread_mutex_lock(&q->lock);
	}
	worker->should_live = false;
	xpthread_cond_signal(&q->cv);
	xpthread_mutex_unlock(&q->lock);
	pthread_join(worker->thread, NULL);

	workq_deinit(q);
}

void
work_set_defaults(struct work *wk)
{
	memset(wk, 0, sizeof(*wk));
	wk->status = WORK_STATUS_NEW;
}

void
work_enqueue(struct workq *q, struct work *wk)
{
	wk->status = WORK_STATUS_QUEUED;
	xpthread_mutex_lock(&q->lock);
	TAILQ_INSERT_TAIL(&q->q, wk, q);
	xpthread_cond_signal(&q->cv);
	xpthread_mutex_unlock(&q->lock);
}

int
work_trycancel(struct workq *q, struct work *wk)
{
	xpthread_mutex_lock(&q->lock);
	enum work_status status = wk->status;
	if (status == WORK_STATUS_QUEUED) {
		TAILQ_REMOVE(&q->q, wk, q);
		wk->status = WORK_STATUS_CANCELLED;
	}
	xpthread_mutex_unlock(&q->lock);
	/* NOTE: done callback has not been called */
	if (status == WORK_STATUS_INPROGRESS ||
	    status == WORK_STATUS_NOTIFICATION) {
		return EBUSY;
	}
	if (status == WORK_STATUS_NEW) {
		return ENOENT;
	}
	// TODO: Replace assert (programming error)
	assert(status == WORK_STATUS_QUEUED || status == WORK_STATUS_DONE);
	return 0;
}
