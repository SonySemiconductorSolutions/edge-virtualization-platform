/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <internal/util.h>

#include "main_loop.h"
#include "timeutil.h"
#include "xlog.h"

#define MAIN_LOOP_LOG_VERBOSE

/*
 * XXX unfortunately heath-check stuff still needs periodic wake up.
 */
#define MIN_TIMEOUT_SEC 15

static pthread_t g_main_thread;
static const char *g_timeout_reason;
static struct timespec g_next_timeout;

#define _MAX_POLLFDS 2
static struct pollfd g_pollfds[_MAX_POLLFDS];
static nfds_t g_npollfds;
static int g_fifo;
static char *pipe_name;

void
main_loop_wakeup(const char *name)
{
	int fifo;

	/*
	 * wake up tls_poll()
	 */
#if defined(MAIN_LOOP_LOG_VERBOSE)
	xlog_trace("%s: waking up poll for %s", __func__, name);
#endif

	if (!pipe_name) {
		xlog_error("no name for the agent fifo");
		return;
	}

	char buf[1];
	buf[0] = 1;

	if ((fifo = open(pipe_name, O_WRONLY | O_NONBLOCK)) < 0) {
		xlog_error("open failed with errno %d", errno);
		return;
	}

	ssize_t ssz = write(fifo, buf, sizeof(buf));
	if (ssz == -1) {
		xlog_error("write failed with errno %d", errno);
	} else if (ssz != sizeof(buf)) {
		xlog_error("invalid write size %zd != %zu ", ssz, sizeof(buf));
	}

	if (close(fifo) < 0) {
		xlog_error("close failed with errno %d", errno);
	}
}

static void
clear_next_timeout(void)
{
	gettime(&g_next_timeout);
	struct timespec diff;
	diff.tv_sec = MIN_TIMEOUT_SEC;
	diff.tv_nsec = 0;
	timespecadd(&g_next_timeout, &diff, &g_next_timeout);
	g_timeout_reason = "MIN_TIMEOUT_SEC";
}

void
main_loop_init(void)
{
	g_main_thread = pthread_self();
	clear_next_timeout();
	g_npollfds = 0;

	if ((pipe_name = getenv("EVP_AGENT_FIFO")) == NULL) {
		char buf[] = "/tmp/evp-agent.XXXXXXX";
		char *dirname = mkdtemp(buf);
		if (!dirname) {
			xlog_abort("mkdtemp failed with %d", errno);
		}

		xasprintf(&pipe_name, "%s/pipe", dirname);
	}

	if (mkfifo(pipe_name, 0600) < 0 && errno != EEXIST) {
		xlog_abort("mkfifo failed with errno %d", errno);
	}

	if ((g_fifo = open(pipe_name, O_RDWR)) < 0) {
		xlog_abort("open failed with errno %d", errno);
	}

	xlog_debug("Created agent fifo at %s", pipe_name);
}

void
main_loop_add_timeout_ms(const char *name, unsigned int timeout_ms)
{
	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));
	struct timespec abstimeout;
	relms2absts(timeout_ms, &abstimeout);
	if (timespeccmp(&g_next_timeout, &abstimeout, >)) {
		g_next_timeout = abstimeout;
		g_timeout_reason = name;
#if defined(MAIN_LOOP_LOG_VERBOSE)
		xlog_trace("%s: updated the timeout to %ju.%09ju for %s",
			   __func__, (uintmax_t)g_next_timeout.tv_sec,
			   (uintmax_t)g_next_timeout.tv_nsec, name);
#endif
	}
}

/* TODO: Refactor methods main_loop_add* to call this as end-point*/
static void
main_loop_add_abs_timespec(const char *name, const struct timespec abstimeout)
{

	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));
	if (timespeccmp(&g_next_timeout, &abstimeout, >)) {
		g_next_timeout = abstimeout;
		g_timeout_reason = name;
#if defined(MAIN_LOOP_LOG_VERBOSE)
		xlog_trace("%s: updated the timeout to %ju.%09ju for %s",
			   __func__, (uintmax_t)g_next_timeout.tv_sec,
			   (uintmax_t)g_next_timeout.tv_nsec, name);
#endif
	}
}

void
main_loop_add_abs_timeout_ms(const char *name, uint64_t timeout_ms)
{
	struct timespec abstimeout;
	abstimeout.tv_sec = timeout_ms / 1000;
	abstimeout.tv_nsec = (timeout_ms % 1000) * 1000 * 1000;
	main_loop_add_abs_timespec(name, abstimeout);
}

void
main_loop_add_abs_timeout_sec(const char *name, time_t to)
{
	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));
	struct timespec abstimeout;
	abstimeout.tv_sec = to;
	abstimeout.tv_nsec = 0;
	if (timespeccmp(&g_next_timeout, &abstimeout, >)) {
		g_next_timeout = abstimeout;
		g_timeout_reason = name;
#if defined(MAIN_LOOP_LOG_VERBOSE)
		xlog_trace("%s: updated the timeout to %ju.%09ju for %s",
			   __func__, (uintmax_t)g_next_timeout.tv_sec,
			   (uintmax_t)g_next_timeout.tv_nsec, name);
#endif
	}
}

static unsigned int
main_loop_get_next_timeout_ms(const char **reasonp)
{
	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));
	unsigned int timeout_ms = absts2relms_roundup(&g_next_timeout);
#if defined(MAIN_LOOP_LOG_VERBOSE)
	xlog_trace("%s: returning the timeout \"%s\" %ju.%09ju (abs) %u "
		   "(relative "
		   "ms)",
		   __func__, g_timeout_reason,
		   (uintmax_t)g_next_timeout.tv_sec,
		   (uintmax_t)g_next_timeout.tv_nsec, timeout_ms);
#endif
	*reasonp = g_timeout_reason;
	return timeout_ms;
}

int
main_loop_add_fd(int fd, bool want_write)
{
	// Skip invalid fd
	if (fd == -1) {
		return 0;
	}
	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));

	if (g_npollfds >= _MAX_POLLFDS) {
		xlog_error("invalid count of poll fds: %ju",
			   (uintmax_t)g_npollfds);
		return ENOBUFS;
	}
	struct pollfd *pfd = &g_pollfds[g_npollfds];
	pfd->fd = fd;
	pfd->events = POLLIN;
	if (want_write) {
		pfd->events |= POLLOUT;
	}
	g_npollfds++;
	return 0;
}

int
main_loop_block(void)
{
	const char *reason;
	int ret;
	// TODO: Replace assert (programming error)
	assert(pthread_equal(pthread_self(), g_main_thread));
	unsigned int timeout_ms = main_loop_get_next_timeout_ms(&reason);
	ret = main_loop_add_fd(g_fifo, false);
	if (ret) {
		return ret;
	}
#if defined(MAIN_LOOP_LOG_VERBOSE)
	struct timespec start;
	struct timespec end;
	gettime(&start);
	xlog_trace("%s: blocking", __func__);
#endif
	ret = poll(g_pollfds, g_npollfds, timeout_ms);
	clear_next_timeout();
#if defined(MAIN_LOOP_LOG_VERBOSE)
	gettime(&end);
	struct timespec diff;
	timespecsub(&end, &start, &diff);
	xlog_trace("%s: woken after %ju.%09ju (specified %ju)", __func__,
		   (uintmax_t)diff.tv_sec, (uintmax_t)diff.tv_nsec,
		   (uintmax_t)timeout_ms);
#endif
	if (ret == -1) {
		xlog_error("poll failed with %d", errno);
	} else if (ret == 0) {
		xlog_trace("poll timed out for %s", reason);
	} else if (ret > 0) {
#if defined(MAIN_LOOP_LOG_VERBOSE)
		unsigned int i;
		for (i = 0; i < g_npollfds; i++) {
			/* unused to avoid when log level is not debug */
			const struct pollfd *pfd __unused = &g_pollfds[i];
			xlog_trace("%s: [%u] fd=%d events=0x%x revents=0x%x",
				   __func__, i, pfd->fd, pfd->events,
				   pfd->revents);
		}
#endif
	}
	g_npollfds = 0;

	/* drain the pipe */
	ret = main_loop_add_fd(g_fifo, false);
	if (ret) {
		return ret;
	}
	while (poll(g_pollfds, g_npollfds, 0) == 1) {
		char buf[1];
		ssize_t ssz = read(g_fifo, buf, sizeof(buf));
		if (ssz == -1) {
			xlog_error("read failed with errno %d", errno);
		} else if (ssz != sizeof(buf)) {
			xlog_error("invalid read size %zd != %zu ", ssz,
				   sizeof(buf));
		}
	}
	g_npollfds = 0;
	return 0;
}
