/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This code is used by module SDK implementations local to
 * the agent process.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk.h>

#include <internal/util.h>

#include "sdk_agent.h"
#include "sdk_impl.h"
#include "stream/stream.h"

EVP_RESULT
EVP_impl_getEvent(struct EVP_client *h, int timeout_ms,
		  struct sdk_event **eventp)
{
	sdk_assert_unlocked();
	// TODO: Replace assert (programming error)
	assert(timeout_ms >= 0 || timeout_ms == -1);
	struct sdk_event *event;
	int ret = 0;
	struct timespec abstime0;
	struct timespec *abstime;

	*eventp = NULL;
	if (timeout_ms >= 0) {
		abstime = &abstime0;
		memset(abstime, 0, sizeof(*abstime));
		ret = clock_gettime(CLOCK_REALTIME, abstime);
		// TODO: Replace assert (runtime error)
		assert(ret == 0);
		abstime->tv_nsec += timeout_ms * 1000000ll;
		if (abstime->tv_nsec >= 1000000000ll) {
			abstime->tv_sec += abstime->tv_nsec / 1000000000ll;
			abstime->tv_nsec %= 1000000000ll;
		}
	} else {
		abstime = NULL;
	}

	sdk_lock();

	while (TAILQ_EMPTY(&h->events) && !h->exiting) {
		if (abstime) {
			sdk_mark_unlocked();
			ret = xpthread_cond_timedwait(&h->event_cv,
						      &g_sdk_lock, abstime);
			sdk_mark_locked();
			if (ret == ETIMEDOUT) {
				sdk_unlock();
				return EVP_TIMEDOUT;
			}
		} else {
			sdk_mark_unlocked();
			xpthread_cond_wait(&h->event_cv, &g_sdk_lock);
			ret = 0;
			sdk_mark_locked();
		}
		// TODO: Replace assert (runtime error)
		assert(ret == 0);
	}
	event = TAILQ_FIRST(&h->events);
	if (event != NULL) {
		TAILQ_REMOVE(&h->events, event, q);
	} else {
		// TODO: Replace assert (programming error)
		assert(h->exiting);
		sdk_unlock();
		return EVP_SHOULDEXIT;
	}
	sdk_unlock();
	*eventp = event;
	return EVP_OK;
}

EVP_RESULT
EVP_impl_streamInputOpen_local(struct EVP_client *h, const char *name,
			       EVP_STREAM_READ_CALLBACK cb, void *userData,
			       EVP_STREAM *stream)
{
	EVP_RESULT ret = EVP_OK;
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	ret = EVP_impl_streamInputOpen(h, name, cb, userData, stream);
	error = pthread_mutex_unlock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	return ret;
}

EVP_RESULT
EVP_impl_streamOutputOpen_local(struct EVP_client *h, const char *name,
				EVP_STREAM *stream)
{
	EVP_RESULT ret;
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	ret = EVP_impl_streamOutputOpen(h, name, stream);
	error = pthread_mutex_unlock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	return ret;
}

EVP_RESULT
EVP_impl_streamClose_local(struct EVP_client *h, EVP_STREAM stream)
{
	EVP_RESULT ret;
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	ret = EVP_impl_streamClose(h, stream);
	error = pthread_mutex_unlock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	return ret;
}

EVP_RESULT
EVP_impl_streamWrite_local(struct EVP_client *h, EVP_STREAM stream,
			   const void *buf, size_t n)
{
	EVP_RESULT ret;
	int error = pthread_mutex_lock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	ret = EVP_impl_streamWrite(h, stream, buf, n);
	error = pthread_mutex_unlock(&h->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3) with %d\n",
			__func__, error);
		return EVP_ERROR;
	}

	return ret;
}
