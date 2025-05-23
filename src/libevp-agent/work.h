/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__WORK_H__)
#define __WORK_H__

#include <internal/queue.h>

#include "xpthread.h"

enum work_status {
	WORK_STATUS_NEW = 0,
	WORK_STATUS_QUEUED = 1,
	WORK_STATUS_INPROGRESS = 2,   /* processing the operation */
	WORK_STATUS_NOTIFICATION = 3, /* calling the completion callback */
	WORK_STATUS_DONE = 4,
	WORK_STATUS_CANCELLED = 5,
};

struct work {
	TAILQ_ENTRY(work) q EVP_GUARDED(workq->lock);
	enum work_status status;

	/*
	 * done: completion callback
	 *
	 * This callback is allowed to take the ownership of the `wk`
	 * without calling work_trycancel.
	 * In that case, it should return NULL.
	 * Otherwise, return `wk` as it is.
	 *
	 * This callback is called in the context of a worker thread
	 * managed by work.c.
	 *
	 * This callback is called without holding any locks.
	 *
	 * If necessary, it's users' responsibility to perform serializations
	 * (eg. mutexes) between this callback and work_trycancel on the same
	 * work.
	 */
	struct work *(*done)(struct work *wk);
};

struct workq {
	struct evp_lock lock;
	pthread_cond_t cv EVP_GUARDED(lock);
	TAILQ_HEAD(, work) q EVP_GUARDED(lock);
};

struct worker {
	pthread_t thread;
	struct workq q;
	bool should_live;
	const char *name;
	void (*process_item)(struct worker *, struct work *);
	void *user;
	int max_jobs;
	int cur_jobs;
};

void worker_manager_start(struct worker *);
void worker_manager_stop(struct worker *);

/*
 * work lifecycle and ownership
 *
 * 1. a user prepares the memory for struct work
 *    and initializes it, possibly using work_set_defaults.
 *
 * 2. the user enqueues the work using work_enqueue.
 *    now the work is "owned" by work.c.
 *
 * 3. the user can take back the ownership by one of the following:
 *
 * - a successful work_trycancel. ("successful" means returning 0 here)
 *
 * - wk->done callback returning NULL.
 *
 * 4. User must cancel all pending jobs prior worker termination
 */

/*
 * work_set_defaults: Initialize the structure with the default values.
 */
void work_set_defaults(struct work *wk);

/*
 * work_enqueue: Enqueue the work
 *
 * Once a work is queued, it's considered owned by the framework. (work.c)
 *
 * It's illegal to enqueue a work which is already enqueued.
 */
void work_enqueue(struct workq *, struct work *wk);

/*
 * work_trycancel: Try to remove the work from the queue
 *
 * - It returns non-zero error when it failed to remove it.
 *   It typically means that the work is currently being processed
 *   by the framework. (work.c)
 *
 * - It returns 0 when it successfully removed the work from the queue.
 *   That is, the user successfully took back the ownership of the work and
 *   work.c will no longer access the work.
 *   It means either of the followings:
 *
 *   - work.c has not started processing the work yet.
 *     work_trycancel just undo'ed work_enqueue.
 *     (wk.status != WORK_STATUS_DONE)
 *
 *   - work.c has already completed processing the work.
 *     (wk.status == WORK_STATUS_DONE)
 *
 *   The user can distinguish the above situations by checking
 *   wk.status == WORK_STATUS_DONE.
 */
int work_trycancel(struct workq *, struct work *wk);

#endif /* !defined(__WORK_H__) */
