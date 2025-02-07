/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__XPTHREAD_H__)
#define __XPTHREAD_H__

#include <pthread.h>

#if defined(__clang__)
#define EVP_CAPABILITY(x) __attribute__((capability(x)))
#define EVP_GUARDED_BY(x) __attribute__((guarded_by(x)))
/*
 * Note: EVP_GUARDED should only be used where EVP_GUARDED_BY can't be used
 * for some reasons. The argument of EVP_GUARDED is just for documented
 * purpose.
 */
#define EVP_GUARDED(x)    __attribute__((guarded_var))
#define EVP_ACQUIRES(...) __attribute__((acquire_capability(__VA_ARGS__)))
#define EVP_RELEASES(...) __attribute__((release_capability(__VA_ARGS__)))
#define EVP_REQUIRES(...) __attribute__((requires_capability(__VA_ARGS__)))
#define EVP_EXCLUDES(...) __attribute__((locks_excluded(__VA_ARGS__)))
#define EVP_NO_THREAD_SAFETY_ANALYSIS                                         \
	__attribute__((no_thread_safety_analysis))
#else
#define EVP_CAPABILITY(x)
#define EVP_GUARDED_BY(x)
#define EVP_GUARDED(x)
#define EVP_ACQUIRES(...)
#define EVP_RELEASES(...)
#define EVP_REQUIRES(...)
#define EVP_EXCLUDES(...)
#define EVP_NO_THREAD_SAFETY_ANALYSIS
#endif

struct EVP_CAPABILITY("mutex") evp_lock {
	pthread_mutex_t lock;
};

#define EVP_LOCK_INITIALIZER {PTHREAD_MUTEX_INITIALIZER}

#if !defined(SCHED_PRIORITY_DEFAULT)
/* POSIX.1-2001 requires a spread of at least 32 between the maximum and the
 * minimum values for SCHED_FIFO and SCHED_RR. */
#define SCHED_PRIORITY_DEFAULT 31
#endif

enum evp_thread_priority {
	MAIN_PRIORITY = SCHED_PRIORITY_DEFAULT,
	WORKER_MANAGER_PRIORITY = MAIN_PRIORITY,
	WORKER_PRIORITY = MAIN_PRIORITY,
	MODULE_LOG_PRIORITY = MAIN_PRIORITY,
	MODULE_BACKDOOR_INSTANCE_PRIORITY = MAIN_PRIORITY,
	MODULE_INSTANCE_PRIORITY = MAIN_PRIORITY
};

/*
 * pthread wrappers to abort on rare errors.
 */

void xpthread_mutex_init(struct evp_lock *lock);
void xpthread_mutex_destroy(struct evp_lock *lock);

void xpthread_mutex_lock(struct evp_lock *lock) EVP_ACQUIRES(lock);
void xpthread_mutex_unlock(struct evp_lock *lock) EVP_RELEASES(lock);

void xpthread_cond_wait(pthread_cond_t *, struct evp_lock *lock)
	EVP_REQUIRES(lock);
struct timespec;
int xpthread_cond_timedwait(pthread_cond_t *, struct evp_lock *lock,
			    const struct timespec *) EVP_REQUIRES(lock);
void xpthread_cond_signal(pthread_cond_t *);
void xpthread_cond_broadcast(pthread_cond_t *);

/**
 * Start a new thread with given priority and stack size.
 *
 * @param[out] thread		The newly created thread
 * @param[in] start_routine	Thread start function
 * @param[in] arg		Argument to start_routine
 * @param[in] priority		Thread priority
 * @param[in] stack_size	The stack size for the new thread, or 0 for
 * default
 *
 * @return 0 on success, otherwise an error number
 */
int xpthread_create(pthread_t *thread, void *(*start_routine)(void *),
		    void *arg, int priority, size_t stack_size);

/**
 * Start a new thread with given priority and stack.
 *
 * @param[out] thread		The newly created thread
 * @param[in] start_routine	Thread start function
 * @param[in] arg			Argument to start_routine
 * @param[in] priority		Thread priority
 * @param[in] stack			The stack for the new thread.
 if NULL, xpthread_create_with_stack() is same to xpthread_create()
 * @param[in] stack_size	The stack size for the new thread, or 0 for
 * default
 *
 * @return 0 on success, otherwise an error number
 */
int xpthread_create_with_stack(pthread_t *thread,
			       void *(*start_routine)(void *), void *arg,
			       int priority, void *stack, size_t stack_size);

#endif /* !defined(__XPTHREAD_H__) */
