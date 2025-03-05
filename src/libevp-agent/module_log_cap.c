/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* for pthread_setname_np */
#include <sys/ioctl.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "map.h"
#include "module_log_cap.h"
#include "module_log_queue.h"
#include "xlog.h"
#include "xpthread.h"

// This is an arbitrary limit.
// We could make it dynamically allocated in the future if
// we need it to be more flexible.
#define CAPTURE_MAX      30
#define LOG_CAP_MAX_SIZE 4096

#define lock(ctxt)   xpthread_mutex_lock(&ctxt->lock)
#define unlock(ctxt) xpthread_mutex_unlock(&ctxt->lock)

struct log_entry {
	union {
		char *rw;
		const char *ro;
	} instance_id;
	const char *stream;
	int fd_read;
	int fd_write;
	char *line;
	ssize_t line_sz;
	bool enabled;

	void (*instance_id_free)(void *);
};

struct log_cap_context {
	struct evp_lock lock;
	pthread_cond_t cond;
	pthread_t thread;
	struct map *captures;
	int sync[2];
	bool stop;
};

struct poll_context {
	struct pollfd *fds;
	nfds_t nfds;
};

static struct log_cap_context g_capture = {
	.lock = EVP_LOCK_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
};

static void
log_entry_free(struct log_entry *entry)
{
	if (!entry) {
		return;
	}

	free(entry->line);
	if (entry->instance_id_free) {
		entry->instance_id_free(entry->instance_id.rw);
	}
	free(entry);
}

/**
 * capture_flush() is expected to be called with ctxt locked
 * The reason is because it is called from module_log_cap_close
 * and module_log_cap_flush with ctxt locked
 */
static void
capture_flush(struct log_entry *log)
{
	if (!log->line) {
		return;
	}

	log->line = xrealloc(log->line, log->line_sz + 1);
	log->line[log->line_sz] = '\0';
	xlog_info("wasm:%s/%s:%s", log->instance_id.ro, log->stream,
		  log->line);

	if (log->enabled) {
		module_log_queue_put(log->instance_id.ro, log->stream,
				     log->line);
	}

	free(log->line);
	log->line = NULL;
	log->line_sz = 0;
}

static int
log_gc(void *key, void *value)
{
	struct log_cap_context *ctxt = key;
	struct log_entry *entry = value;
	map_del(ctxt->captures, &entry->fd_read);
	capture_flush(entry);
	close(entry->fd_read);
	close(entry->fd_write);
	log_entry_free(entry);
	return 1;
}

static int
pipe_fd_lookup(const void *key, const void *value)
{
	const int *fd = key;
	const struct log_entry *entry = value;

	if (entry->fd_read != *fd) {
		return 1;
	}

	return 0;
}

static int
instance_stream_lookup(const void *key, const void *value)
{
	const struct log_entry *k = key;
	const struct log_entry *entry = value;

	if (k->stream != entry->stream && strcmp(k->stream, entry->stream)) {
		return 1;
	}

	if (strcmp(k->instance_id.ro, entry->instance_id.ro)) {
		return 1;
	}

	return 0;
}

static void
capture_pipe(struct log_cap_context *ctxt, struct log_entry *log)
	EVP_REQUIRES(ctxt->lock)
{
	// TODO: Locking the whole processing block is a simple way to protect
	//       allocated log object to be used after freed, but it may affect
	//       performances.
	//       Find a better sync mechanism.
	// Split lines and enqueue
	int nread;
	char buf[100];

	ioctl(log->fd_read, FIONREAD, &nread);
	if ((unsigned)nread > sizeof(buf)) {
		nread = sizeof(buf);
	}

	int n = read(log->fd_read, buf, nread);
	if (n <= 0) {
		return;
	}

	for (int i = 0; i < n; i++) {
		char ch = buf[i];
		if (ch == '\0') {
			// Ignore string termination
			continue;
		}

		if (log->line_sz >= LOG_CAP_MAX_SIZE) {
			ch = '\n';
			i--;
		}

		if (ch == '\n') {
			capture_flush(log);
		} else {
			log->line = xrealloc(log->line, log->line_sz + 1);
			log->line[log->line_sz] = ch;
			log->line_sz++;
		}
	}
}

/**
 * Fire synchronization with thread to make sure all entries are being
 * polled for.
 */
static void
capture_sync(struct log_cap_context *ctxt) EVP_REQUIRES(ctxt->lock)
{
	// Send sync '\0' byte then wait for thread to acknowledge poll list
	// update.
	ssize_t r = write(ctxt->sync[1], "", 1);
	if (r < 0) {
		xlog_error("Bad return code from write(2): %zd", r);
	}
}

static int
prepare_poll_foreach(const void *key, const void *value)
{
	union {
		const struct poll_context *c;
		struct poll_context *rw;
	} ctxt = {.c = key};
	union {
		const struct log_entry *c;
		struct log_entry *rw;
	} entry = {.c = value};

	nfds_t nfds = ctxt.rw->nfds + 1;
	ctxt.rw->fds = xrealloc(ctxt.rw->fds, sizeof(*ctxt.rw->fds) * nfds);

	struct pollfd *pfd = &ctxt.rw->fds[ctxt.rw->nfds];
	ctxt.rw->nfds = nfds;
	pfd->fd = entry.rw->fd_read;
	pfd->events = POLLIN;
	pfd->revents = 0;
	return 1;
}

static void
capture_prepare_poll(struct log_cap_context *ctxt,
		     struct poll_context *poll_ctxt)
{
	struct log_entry sync = {.fd_read = ctxt->sync[0]};
	poll_ctxt->nfds = 0;
	// Add synchronization pipe to poll list
	prepare_poll_foreach(poll_ctxt, &sync);
	map_foreach(ctxt->captures, prepare_poll_foreach, poll_ctxt);
}

static void *
capture_worker(void *arg)
{
	struct log_cap_context *ctxt = arg;
	struct poll_context poll_ctxt = {NULL, 0};
	int rv;

	lock(ctxt);

	for (;;) {
		capture_prepare_poll(ctxt, &poll_ctxt);
		xpthread_cond_signal(&ctxt->cond);

		unlock(ctxt);
		rv = poll(poll_ctxt.fds, poll_ctxt.nfds, -1);
		lock(ctxt);

		if (ctxt->stop) {
			break;
		}

		if (rv <= 0) {
			xlog_warning("poll: failed with %d", errno);
			continue;
		}

		for (nfds_t i = 0; i < poll_ctxt.nfds; i++) {
			struct pollfd *pfd = &poll_ctxt.fds[i];
			if (pfd->fd == ctxt->sync[0]) {
				// Sync received
				if (pfd->revents & POLLIN) {
					char trash;
					ssize_t r = read(pfd->fd, &trash, 1);
					if (r < 0) {
						xlog_error("Bad return code "
							   "from read(2): %zd",
							   r);
					}
				}
				continue;
			}

			struct log_entry *log;
			log = map_get(ctxt->captures, &pfd->fd);
			if (!log) {
				xlog_warning("No log handler found for fd %d",
					     pfd->fd);
				continue;
			}

			if ((pfd->revents & (POLLERR | POLLHUP))) {
				xlog_debug("poll: (%d) error event %0X",
					   pfd->fd, pfd->revents);
				// An error ocurred on the pipe and will be
				// closed.
				// Flushes and terminates the log entry.
				log_gc(ctxt, log);
			} else if (pfd->revents & POLLIN) {
				capture_pipe(ctxt, log);
			}
		}
	}

	unlock(ctxt);

	free(poll_ctxt.fds);

	return NULL;
}

int
module_log_cap_open(const char *instance_id, const char *stream)
{
	struct log_cap_context *ctxt = &g_capture;

	int fd[2];
	int rv = pipe(fd);
	if (rv) {
		return -1;
	}
	xlog_debug("opening pipe: %d", fd[0]);

	struct log_entry *value = xmalloc(sizeof(*value));
	*value = (struct log_entry){
		.instance_id.rw = strdup(instance_id),
		.instance_id_free = free,
		.stream = stream,
		.fd_read = fd[0],
		.fd_write = fd[1],
		.enabled = false,
	};
	lock(ctxt);
	void *oldval = map_put(ctxt->captures, &fd[0], value);
	free(oldval);
	capture_sync(ctxt);
	xpthread_cond_wait(&ctxt->cond, &ctxt->lock);
	unlock(ctxt);

	return fd[1];
}

void
module_log_cap_flush(const char *instance, const char *stream)
{
	struct log_cap_context *ctxt = &g_capture;
	struct log_entry key = {
		.instance_id.ro = instance,
		.stream = stream,
	};
	struct log_entry *value;

	lock(ctxt);
	value = map_get_with(ctxt->captures, instance_stream_lookup, &key);
	if (value) {
		capture_flush(value);
	}
	unlock(ctxt);
}

void
module_log_cap_close(const char *instance, const char *stream)
{
	struct log_cap_context *ctxt = &g_capture;
	struct log_entry key = {
		.instance_id.ro = instance,
		.stream = stream,
	};
	struct log_entry *value;

	lock(ctxt);
	value = map_get_with(ctxt->captures, instance_stream_lookup, &key);
	if (value) {
		xlog_debug("closing pipe: %dr/%dw", value->fd_read,
			   value->fd_write);
		log_gc(ctxt, value);
		capture_sync(ctxt);
		xpthread_cond_wait(&ctxt->cond, &ctxt->lock);
	}
	unlock(ctxt);
}

int
module_log_cap_set_enable(const char *instance, const char *stream, bool value)
{
	struct log_cap_context *ctxt = &g_capture;
	struct log_entry key = {
		.instance_id.ro = instance,
		.stream = stream,
	};
	struct log_entry *entry;
	int rv = -1;

	lock(ctxt);
	entry = map_get_with(ctxt->captures, instance_stream_lookup, &key);
	if (entry) {
		entry->enabled = value;
		rv = 0;
	}
	unlock(ctxt);

	return rv;
}

int
module_log_cap_get_enable(const char *instance, const char *stream,
			  bool *value)
{
	struct log_cap_context *ctxt = &g_capture;
	struct log_entry key = {
		.instance_id.ro = instance,
		.stream = stream,
	};
	struct log_entry *entry;
	int rv = -1;

	lock(ctxt);
	entry = map_get_with(ctxt->captures, instance_stream_lookup, &key);
	if (entry) {
		*value = entry->enabled;
		rv = 0;
	}
	unlock(ctxt);

	return rv;
}

void
module_log_cap_start(void)
{
	struct log_cap_context *ctxt = &g_capture;
	int ret;

	ret = pipe(ctxt->sync);
	if (ret) {
		xlog_error("Failed to create pipe for capture thread sync");
		return;
	}

	ret = xpthread_create(&ctxt->thread, capture_worker, ctxt,
			      MODULE_LOG_PRIORITY, 0);
	if (ret) {
		xlog_error("Failed to create thread for capture");
	}
	pthread_setname_np(ctxt->thread, "mod_log_capture");
}

void
module_log_cap_stop(void)
{
	struct log_cap_context *ctxt = &g_capture;
	lock(ctxt);
	ctxt->stop = true;
	capture_sync(ctxt);
	unlock(ctxt);
	int error;
	error = pthread_join(ctxt->thread, NULL);
	if (error != 0) {
		xlog_error("Failed to join module_log_cap thread: %d", error);
	}
	map_foreach(ctxt->captures, (void *)log_gc, ctxt);

	if (close(ctxt->sync[0])) {
		xlog_warning("close(2) ctxt->sync[0]: %s\n", strerror(errno));
	}

	if (close(ctxt->sync[1])) {
		xlog_warning("close(2) ctxt->sync[1]: %s\n", strerror(errno));
	}
}

void
module_log_cap_init(void)
{
	struct log_cap_context *ctxt = &g_capture;
	ctxt->captures = map_init(0, pipe_fd_lookup, NULL);
	module_log_queue_init();
}

void
module_log_cap_free(void)
{
	module_log_queue_free();
	struct log_cap_context *ctxt = &g_capture;
	map_free(ctxt->captures);
	ctxt->captures = NULL;
}
