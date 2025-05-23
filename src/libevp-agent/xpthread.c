/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file contains thin wrappers of pthread functions
 * to check unlikely errors and abort on them.
 *
 * E.g. pthread_mutex_lock is allowed to return an error when
 * it detects a mutex corruption. It usually happens on programming
 * errors like the use of an uninitialized mutex.
 *
 * E.g. EDEADLK should be a programming error for our usage.
 */

#include <sys/resource.h>
#include <sys/types.h>

#include <errno.h>
#include <sched.h>
#include <unistd.h>

#include "xlog.h"
#include "xpthread.h"

void
xpthread_mutex_init(struct evp_lock *lock)
{
	int error = pthread_mutex_init(&lock->lock, NULL);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_init error %d", error);
	}
}

void
xpthread_mutex_destroy(struct evp_lock *lock)
{
	int error = pthread_mutex_destroy(&lock->lock);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_destroy error %d", error);
	}
}

void
xpthread_mutex_lock(struct evp_lock *lock) EVP_NO_THREAD_SAFETY_ANALYSIS
{
	int error = pthread_mutex_lock(&lock->lock);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_lock error %d", error);
	}
}

void
xpthread_mutex_unlock(struct evp_lock *lock) EVP_NO_THREAD_SAFETY_ANALYSIS
{
	int error = pthread_mutex_unlock(&lock->lock);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_mutex_unlock error %d", error);
	}
}

void
xpthread_cond_wait(pthread_cond_t *cv, struct evp_lock *lock)
{
	int error = pthread_cond_wait(cv, &lock->lock);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_wait error %d", error);
	}
}

int
xpthread_cond_timedwait(pthread_cond_t *cv, struct evp_lock *lock,
			const struct timespec *abstime)
{
	int error = pthread_cond_timedwait(cv, &lock->lock, abstime);
	if (error != 0 && error != ETIMEDOUT) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_timedwait error %d", error);
	}
	return error;
}

void
xpthread_cond_signal(pthread_cond_t *cv)
{
	int error = pthread_cond_signal(cv);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_signal error %d", error);
	}
}

void
xpthread_cond_broadcast(pthread_cond_t *cv)
{
	int error = pthread_cond_broadcast(cv);
	if (error != 0) {
		// Exit (xlog_abort): system error
		xlog_abort("pthread_cond_broadcast error %d", error);
	}
}

int
xpthread_create_with_stack(pthread_t *thread, void *(*start_routine)(void *),
			   void *arg, int priority, void *stack,
			   size_t stack_size)
{
	int ret;
	pthread_attr_t attr;

	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		xlog_error("pthread_attr_init error %d", ret);
		goto error;
	}

	if (stack_size > 0) {
		if (stack) {
			ret = pthread_attr_setstack(&attr, stack, stack_size);
			if (ret != 0) {
				xlog_error("pthread_attr_setstack error %d",
					   ret);
				goto error;
			}

		} else {
			ret = pthread_attr_setstacksize(&attr, stack_size);
			if (ret != 0) {
				xlog_error(
					"pthread_attr_setstacksize error %d",
					ret);
				goto error;
			}
		}
	}

	int scheduler = sched_getscheduler(getpid());
	if (scheduler == SCHED_FIFO || scheduler == SCHED_RR) {
		int priority_min = sched_get_priority_min(scheduler);
		int priority_max = sched_get_priority_max(scheduler);
		if (priority < priority_min) {
			xlog_error("Invalid priority %d < min %d", priority,
				   priority_min);
			ret = EINVAL;
			goto error;
		}
		if (priority > priority_max) {
			xlog_error("Invalid priority %d > max %d", priority,
				   priority_max);
			ret = EINVAL;
			goto error;
		}
		/* Specify the priority */
		struct sched_param param;
		param.sched_priority = priority;
		ret = pthread_attr_setschedparam(&attr, &param);
		if (ret != 0) {
			xlog_error("pthread_attr_setschedparam error %d. "
				   "Setting priority to %i",
				   ret, param.sched_priority);
			goto error;
		}
	}
	xlog_info("Creating thread with scheduler %d, priority %d and "
		  "stack_size %zu",
		  scheduler, priority, stack_size);
	ret = pthread_create(thread, &attr, start_routine, arg);
	if (ret != 0) {
		xlog_error("pthread_create error %d", ret);
		goto error;
	}

error:
	pthread_attr_destroy(&attr);
	return ret;
}

int
xpthread_create(pthread_t *thread, void *(*start_routine)(void *), void *arg,
		int priority, size_t stack_size)
{
	return xpthread_create_with_stack(thread, start_routine, arg, priority,
					  NULL, stack_size);
}
