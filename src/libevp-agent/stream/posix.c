/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "evp/sdk.h"
#include "internal/queue.h"
#include "stream.h"

struct request {
	void *buf;
	size_t n;
	struct request *next;
};

struct request_list {
	struct request *head, *tail;
	size_t n_requests;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct out_thread_args {
	struct request_list *requests;
	struct stream_impl *si;
};

struct stream_impl_params {
	union {
		struct read {
			int fd;
			size_t n_clients;

			struct client {
				int fd;
			} *clients;
		} read;

		struct write {
			pthread_t thread;
			bool thread_init;
			struct request_list requests;
		} write;
	} u;
};

static int
close_in(struct stream_impl_params *params)
{
	struct read *r = &params->u.read;

	if (r == NULL) {
		return 0;
	}

	int ret = 0;

	if (r->fd >= 0 && close(r->fd)) {
		fprintf(stderr, "%s: close(2): %s\n", __func__,
			strerror(errno));
		ret = -1;
	}

	free(r->clients);
	return ret;
}

static void
free_request(struct request *req)
{
	if (req) {
		free(req->buf);
	}

	free(req);
}

static void
cleanup_request(void *arg)
{
	struct request **req = arg;

	free_request(*req);
}

static int
free_request_list(struct request_list *list)
{
	int ret = 0, error = pthread_mutex_destroy(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_destroy(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	error = pthread_cond_destroy(&list->cond);

	if (error) {
		fprintf(stderr, "%s: pthread_cond_destroy(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	struct request *req = list->head;

	while (req != NULL) {
		struct request *next = req->next;

		free_request(req);
		req = next;
	}

	return ret;
}

static int
flush(struct request_list *list)
{
	int ret = -1, error = pthread_mutex_lock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	while (list->n_requests) {
		error = pthread_cond_wait(&list->cond, &list->mutex);

		if (error) {
			fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n",
				__func__, strerror(error));
			goto end;
		}
	}

	ret = 0;

end:
	error = pthread_mutex_unlock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	return ret;
}

static int
close_write(struct write *w)
{
	if (w == NULL) {
		return 0;
	}

	int ret = 0;

	if (w->thread_init) {
		if (flush(&w->requests)) {
			fprintf(stderr, "%s: flush failed\n", __func__);
			ret = -1;
		}

		int error = pthread_cancel(w->thread);

		if (error) {
			fprintf(stderr, "%s: pthread_cancel(3): %s\n",
				__func__, strerror(error));
			ret = -1;
		}

		error = pthread_join(w->thread, NULL);

		if (error) {
			fprintf(stderr, "%s: pthread_join(3): %s\n", __func__,
				strerror(error));
			ret = -1;
		}
	}

	if (free_request_list(&w->requests)) {
		fprintf(stderr, "%s: free_request_list failed\n", __func__);
		ret = -1;
	}

	return ret;
}

static int
close_out(struct stream_impl_params *params)
{
	int ret = 0;
	struct write *w = &params->u.write;

	if (close_write(w)) {
		fprintf(stderr, "%s: close_write failed\n", __func__);
		ret = -1;
	}

	return ret;
}

static int
close_internal(const struct Stream *stream, struct stream_impl_params *params)
{
	int ret = 0;
	static int (*const f[])(struct stream_impl_params *) = {
		[STREAM_DIRECTION_IN] = close_in,
		[STREAM_DIRECTION_OUT] = close_out};

	if (f[stream->direction](params)) {
		fprintf(stderr, "%s: close[direction=%d] failed\n", __func__,
			(int)stream->direction);
		ret = -1;
	}

	free(params);
	return ret;
}

static int
close_posix(struct stream_impl *si)
{
	return close_internal(&si->cfg, si->params);
}

static int
accept_ipv4(int fd)
{
	struct sockaddr_in addr;
	socklen_t sz = sizeof(addr);
	int client = accept(fd, (struct sockaddr *)&addr, &sz);

	if (client < 0) {
		fprintf(stderr, "%s: accept(2): %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	if (sz != sizeof(addr)) {
		fprintf(stderr, "%s: got size %zu, expected %zu\n", __func__,
			(size_t)sz, sizeof(addr));
		goto failure;
	}

	return client;

failure:
	if (client >= 0 && close(client)) {
		fprintf(stderr, "%s: close(2): %s\n", __func__,
			strerror(errno));
	}

	return -1;
}

static int
accept_ipv6(int fd)
{
	struct sockaddr_in6 addr;
	socklen_t sz = sizeof(addr);
	int client = accept(fd, (struct sockaddr *)&addr, &sz);

	if (client < 0) {
		fprintf(stderr, "%s: accept(2): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	return client;
}

static int
add_client(struct read *r, int fd)
{
	size_t n = r->n_clients + 1;
	struct client *clients = realloc(r->clients, n * sizeof(*clients));

	if (clients == NULL) {
		fprintf(stderr, "%s: realloc(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	clients[r->n_clients] = (struct client){.fd = fd};
	r->clients = clients;
	r->n_clients = n;
	return 0;
}

static int
process_server_read(const struct StreamPosix *cfg, struct read *r, int fd,
		    struct stream_read *sr)
{
	static int (*const accept_domain[])(int) = {
		[STREAM_POSIX_DOMAIN_IPV4] = accept_ipv4,
		[STREAM_POSIX_DOMAIN_IPV6] = accept_ipv6};
	int client = accept_domain[cfg->domain](fd);

	if (client < 0) {
		fprintf(stderr, "%s: accept_domain failed\n", __func__);
		return -1;
	}

	if (add_client(r, client)) {
		fprintf(stderr, "%s: add_client failed\n", __func__);
		return -1;
	}

	/* Indicate that no read event is available yet. */
	return 1;
}

static int
remove_client(struct read *r, size_t i)
{
	struct client *client = &r->clients[i];
	size_t n = r->n_clients - 1;

	if (n) {
		memmove(client, client + 1, (n - i) * sizeof(*r->clients));

		struct client *clients =
			realloc(r->clients, n * sizeof(*clients));

		if (clients == NULL) {
			fprintf(stderr, "%s: realloc(3): %s\n", __func__,
				strerror(errno));
			return -1;
		}

		r->clients = clients;
	} else {
		free(r->clients);
		r->clients = NULL;
	}

	r->n_clients = n;
	return 0;
}

static int
find_and_remove_client(struct read *r, int fd)
{
	for (size_t i = 0; i < r->n_clients; i++) {
		struct client *client = &r->clients[i];

		if (client->fd == fd) {
			int ret = 0;

			if (close(fd)) {
				fprintf(stderr, "%s: close(2): %s\n", __func__,
					strerror(errno));
				ret = -1;
			}

			if (remove_client(r, i)) {
				fprintf(stderr, "%s: remove_client failed\n",
					__func__);
				ret = -1;
			}

			return ret;
		}
	}

	fprintf(stderr, "%s: no client found with fd %d\n", __func__, fd);
	return -1;
}

static int
process_client_read(const struct StreamPosix *cfg, struct read *r, int fd,
		    struct stream_read *sr)
{
	int ret = -1;
	char *buf = malloc(BUFSIZ);
	ssize_t n;

	pthread_cleanup_push(free, buf);

	ret = -1;

	if (buf == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	n = read(fd, buf, BUFSIZ);

	if (n < 0) {
		fprintf(stderr, "%s: read(2): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	if (!n) {
		/* Client disconnected. */

		if (find_and_remove_client(r, fd)) {
			fprintf(stderr, "%s: find_and_remove_client failed\n",
				__func__);
		} else {
			ret = 1;
		}

		goto end;
	}

	*sr = (struct stream_read){
		.id = fd, .buf = buf, .n = n, .free_args = buf};

	ret = 0;

end:
	pthread_cleanup_pop(ret != 0);
	return ret;
}

static int
process_read(const struct StreamPosix *cfg, struct read *r, int fd,
	     struct stream_read *sr)
{
	return fd == r->fd ? process_server_read(cfg, r, fd, sr)
			   : process_client_read(cfg, r, fd, sr);
}

static int
get_type(const struct StreamPosix *cfg)
{
	switch (cfg->type) {
	case STREAM_POSIX_TYPE_TCP:
		return SOCK_STREAM;
	}

	return -1;
}

static int
getport_ipv4(int fd, unsigned short *port)
{
	struct sockaddr_in in;
	socklen_t sz = sizeof(in);

	if (getsockname(fd, (struct sockaddr *)&in, &sz)) {
		fprintf(stderr, "%s: getsockname(2): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	*port = ntohs(in.sin_port);
	return 0;
}

static int
getport_ipv6(int fd, unsigned short *port)
{
	struct sockaddr_in6 in;
	socklen_t sz = sizeof(in);

	if (getsockname(fd, (struct sockaddr *)&in, &sz)) {
		fprintf(stderr, "%s: getsockname(2): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	*port = ntohs(in.sin6_port);
	return 0;
}

static int
getport(int fd, const struct StreamPosix *cfg, unsigned short *port)
{
	static int (*const getport_domain[])(int, unsigned short *) = {
		[STREAM_POSIX_DOMAIN_IPV4] = getport_ipv4,
		[STREAM_POSIX_DOMAIN_IPV6] = getport_ipv6};

	return getport_domain[cfg->domain](fd, port);
}

static int
try_server_fd(struct stream_impl *si, const struct addrinfo *ai)
{
	const struct StreamPosix *cfg = &si->cfg.params.posix;
	int fd = socket(ai->ai_family, ai->ai_socktype, 0);

	if (fd < 0) {
		fprintf(stderr, "%s: socket(2): %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	if (bind(fd, ai->ai_addr, ai->ai_addrlen)) {
		fprintf(stderr, "%s: bind(2): %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	enum { BACKLOG = 20 };

	if (listen(fd, BACKLOG)) {
		fprintf(stderr, "%s: listen(2): %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	int flags = fcntl(fd, F_GETFL);

	if (flags < 0) {
		fprintf(stderr, "%s: fcntl(2) F_GETFL: %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		fprintf(stderr, "%s: fcntl(2) F_SETFL: %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	unsigned short port;

	if (getport(fd, cfg, &port)) {
		fprintf(stderr, "%s: getport failed\n", __func__);
		goto failure;
	}

	struct notification *n = stream_notification();

	if (n == NULL) {
		fprintf(stderr, "%s: stream_notification failed\n", __func__);
		goto failure;
	}

	struct stream_port p = {.si = si, .port = port};

	if (notification_publish(n, "init/port", &p)) {
		fprintf(stderr, "%s: notification_publish failed\n", __func__);
		goto failure;
	}

	return fd;

failure:
	if (fd >= 0 && close(fd)) {
		fprintf(stderr, "%s: close(2): %s\n", __func__,
			strerror(errno));
	}

	return -1;
}

static int
get_domain(const struct StreamPosix *cfg)
{
	switch (cfg->domain) {
	case STREAM_POSIX_DOMAIN_IPV4:
		return AF_INET;
	case STREAM_POSIX_DOMAIN_IPV6:
		return AF_INET6;
	}

	return -1;
}

static void
cleanup_addrinfo(void *arg)
{
	struct addrinfo **res = arg;

	if (*res != NULL) {
		freeaddrinfo(*res);
	}
}

static int
resolve(struct stream_impl *si,
	int (*try_fd)(struct stream_impl *, const struct addrinfo *))
{
	int ret = -1;
	const struct StreamPosix *cfg = &si->cfg.params.posix;
	struct addrinfo *res = NULL;
	char port[sizeof "65535"];
	int n = snprintf(port, sizeof(port), "%hu", cfg->port);
	int error;

	pthread_cleanup_push(cleanup_addrinfo, &res);

	ret = -1;

	if (n < 0 || (unsigned)n >= sizeof(port)) {
		fprintf(stderr, "%s: snprintf(3) failed with %d\n", __func__,
			n);
		goto end;
	}

	struct addrinfo hints = {.ai_family = get_domain(cfg),
				 .ai_socktype = get_type(cfg)};

	error = getaddrinfo(cfg->hostname, port, &hints, &res);

	if (error) {
		fprintf(stderr, "%s: getaddrinfo(3): %s\n", __func__,
			gai_strerror(error));
		goto end;
	}

	struct addrinfo *ai;

	for (ai = res; ai != NULL; ai = ai->ai_next) {
		int fd = try_fd(si, ai);

		if (fd >= 0) {
			ret = fd;
			break;
		}
	}

	if (ai == NULL) {
		fprintf(stderr, "%s: no suitable socket found for %s:%hu\n",
			__func__, cfg->hostname, cfg->port);
		goto end;
	}

end:
	pthread_cleanup_pop(1);
	return ret;
}

static EVP_RESULT
init_in(struct stream_impl *si, struct stream_impl_params *params)
{
	struct read *r = &params->u.read;
	int fd = resolve(si, try_server_fd);

	*r = (struct read){.fd = -1};

	if (fd < 0) {
		fprintf(stderr, "%s: resolve failed\n", __func__);
		return EVP_ERROR;
	}

	r->fd = fd;
	return EVP_OK;
}

static void
cleanup_fd(void *arg)
{
	int *fd = arg;

	if (*fd >= 0) {
		if (shutdown(*fd, SHUT_WR)) {
			fprintf(stderr, "%s: shutdown(2): %s\n", __func__,
				strerror(errno));
		}

		char b;

		switch (read(*fd, &b, sizeof(b))) {
		case sizeof(b):
			fprintf(stderr, "%s: unexpected input data\n",
				__func__);
			break;

		/* Remote has closed the connection. */
		case 0:
			fprintf(stderr,
				"%s: remote has closed the connection\n",
				__func__);
			break;

		default:
			fprintf(stderr, "%s: read(2): %s\n", __func__,
				strerror(errno));
			break;
		}

		if (close(*fd)) {
			fprintf(stderr, "%s: close(2): %s\n", __func__,
				strerror(errno));
		} else {
			*fd = -1;
		}
	}
}

static int
try_client_fd(struct stream_impl *si, const struct addrinfo *ai)
{
	int ret = -1;
	int fd = socket(ai->ai_family, ai->ai_socktype, 0);

	pthread_cleanup_push(cleanup_fd, &fd);

	ret = -1;

	if (fd < 0) {
		fprintf(stderr, "%s: socket(2): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	if (connect(fd, ai->ai_addr, ai->ai_addrlen)) {
		fprintf(stderr, "%s: connect(2): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	ret = fd;

end:
	pthread_cleanup_pop(ret < 0);
	return ret;
}

struct out_thread {
	int fd;
	struct out_thread_args *args;
};

static int
ensure_socket(struct out_thread *ot)
{
	if (ot->fd >= 0) {
		return 0;
	}

	ot->fd = resolve(ot->args->si, try_client_fd);

	if (ot->fd < 0) {
		fprintf(stderr, "%s: resolve failed\n", __func__);
		return -1;
	}

	return 0;
}

static void
cleanup_mutex(void *arg)
{
	int error = pthread_mutex_unlock(arg);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
	}
}

static int
wait_for_request(const struct out_thread_args *args)
{
	int ret = -1;
	struct request_list *list = args->requests;
	int error = pthread_mutex_lock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		goto unlocked;
	}

	pthread_cleanup_push(cleanup_mutex, &list->mutex);

	ret = -1;

	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now)) {
		fprintf(stderr, "%s: clock_gettime(2): %s\n", __func__,
			strerror(errno));
		goto locked;
	}

	enum { TIMEOUT = 1 };
	struct timespec abstime = {.tv_sec = now.tv_sec + TIMEOUT,
				   .tv_nsec = now.tv_nsec};

	error = pthread_cond_timedwait(&list->cond, &list->mutex, &abstime);

	if (error && error != ETIMEDOUT) {
		fprintf(stderr, "%s: pthread_cond_timedwait(3): %s\n",
			__func__, strerror(error));
		/* Assume the mutex state has not been modified. */
		goto locked;
	}

	ret = 0;

locked:
	error = pthread_mutex_unlock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	pthread_cleanup_pop(0);

unlocked:
	return ret;
}

static int
get_first_request(const struct out_thread_args *args, struct request **out)
{
	int ret = -1;
	struct request_list *list = args->requests;
	int error = pthread_mutex_lock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		goto unlocked;
	}

	pthread_cleanup_push(cleanup_mutex, &list->mutex);

	ret = -1;

	struct request *req = list->head;

	if (req == NULL) {
		error = pthread_cond_wait(&list->cond, &list->mutex);

		if (error) {
			fprintf(stderr, "%s: pthread_cond_wait(3): %s\n",
				__func__, strerror(error));
			/* Assume the mutex state has not been modified. */
			goto locked;
		} else if (list->head == NULL) {
			fprintf(stderr, "%s: unexpected null instance\n",
				__func__);
			goto locked;
		}
	}

	req = list->head;
	*out = req;
	ret = 0;

locked:
	error = pthread_mutex_unlock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

	pthread_cleanup_pop(0);

unlocked:
	return ret;
}

static int
send_request(struct out_thread *ot, const struct request *req)
{
	int ret = -1;

	pthread_cleanup_push(cleanup_fd, &ot->fd);

	ret = -1;
	size_t rem = req->n;
	const void *buf = req->buf;

	while (rem) {
		ssize_t n = write(ot->fd, buf, rem);

		if (n < 0) {
			fprintf(stderr, "%s: write(2): %s\n", __func__,
				strerror(errno));
			goto end;
		}

		buf = (const char *)buf + n;
		rem -= n;
	}

	ret = 0;

end:
	pthread_cleanup_pop(ret != 0);

	if (ret) {
		ot->fd = -1;
	}

	return ret;
}

static int
pop_request(struct request_list *list)
{
	int error = pthread_mutex_lock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	struct request *req = list->head;

	if (list->head == list->tail) {
		list->tail = NULL;
	}

	req = list->head;
	list->head = req->next;
	list->n_requests--;
	error = pthread_cond_signal(&list->cond);

	if (error) {
		fprintf(stderr, "%s: pthread_cond_signal(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	error = pthread_mutex_unlock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	return 0;
}

static int
run_out_thread(struct out_thread *ot)
{
	const struct out_thread_args *args = ot->args;

	if (ensure_socket(ot)) {
		if (wait_for_request(args)) {
			fprintf(stderr, "%s: wait_for_request failed\n",
				__func__);
			return -1;
		}
	} else {
		struct request *req = NULL;

		pthread_cleanup_push(cleanup_request, &req);

		if (!get_first_request(args, &req)) {
			if (send_request(ot, req)) {
				fprintf(stderr, "%s: send_request failed\n",
					__func__);
			}

			if (pop_request(args->requests)) {
				fprintf(stderr, "%s: pop_request failed\n",
					__func__);
			}
		}

		pthread_cleanup_pop(1);
	}

	return 0;
}

static void
free_ot(void *args)
{
	struct out_thread *ot = args;

	if (ot->fd >= 0) {
		cleanup_fd(&ot->fd);
	}

	free(ot->args);
}

static void *
out_thread(void *args)
{
	struct out_thread ot = {.fd = -1, .args = args};

	pthread_cleanup_push(free_ot, &ot);

	for (;;) {
		if (run_out_thread(&ot)) {
			fprintf(stderr, "%s: run_out_thread failed\n",
				__func__);
			goto end;
		}
	}

end:
	pthread_cleanup_pop(1);
	return NULL;
}

static EVP_RESULT
init_out(struct stream_impl *si, struct stream_impl_params *params)
{
	EVP_RESULT result = EVP_ERROR;
	struct write *w = &params->u.write;
	struct out_thread_args *args = malloc(sizeof(*args));

	*w = (struct write){.requests = {.mutex = PTHREAD_MUTEX_INITIALIZER,
					 .cond = PTHREAD_COND_INITIALIZER}};

	if (args == NULL) {
		fprintf(stderr, "%s: malloc(3): %s", __func__,
			strerror(errno));
		result = EVP_NOMEM;
		goto failure;
	}

	*args = (struct out_thread_args){.si = si, .requests = &w->requests};

	pthread_t thread;
	int error = pthread_create(&thread, NULL, out_thread, args);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
		goto failure;
	}

	w->thread_init = true;
	w->thread = thread;
	return EVP_OK;

failure:
	free(args);
	return result;
}

static EVP_RESULT
init_posix(struct stream_impl *si)
{
	EVP_RESULT ret = EVP_ERROR;
	const struct Stream *stream = &si->cfg;
	struct stream_impl_params *params = malloc(sizeof(*params));

	if (params == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	*params = (struct stream_impl_params){0};

	static EVP_RESULT (*const init[])(struct stream_impl *,
					  struct stream_impl_params *) = {
		[STREAM_DIRECTION_IN] = init_in,
		[STREAM_DIRECTION_OUT] = init_out};

	if (init[stream->direction](si, params)) {
		fprintf(stderr, "%s: init direction %d failed\n", __func__,
			(int)stream->direction);
		goto end;
	}

	si->params = params;
	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		close_internal(stream, params);
	}

	return ret;
}

static struct request *
alloc_request(const void *buf, size_t n)
{
	struct request *req = malloc(sizeof(*req));
	void *dup = malloc(n);

	if (req == NULL) {
		fprintf(stderr, "%s: malloc(3) req: %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	if (dup == NULL) {
		fprintf(stderr, "%s: malloc(3) dup: %s\n", __func__,
			strerror(errno));
		goto failure;
	}

	*req = (struct request){.buf = dup, .n = n};

	memcpy(dup, buf, n);
	return req;

failure:
	free(dup);
	free(req);
	return NULL;
}

static int
push_request(struct write *w, const void *buf, size_t n)
{
	int ret = -1;
	struct request_list *list = &w->requests;
	int error = pthread_mutex_lock(&list->mutex);
	struct request *req = NULL;

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_lock(3): %s\n", __func__,
			strerror(error));
		goto unlocked;
	}

	enum { LIMIT = 1000 };

	if (list->n_requests > (size_t)LIMIT) {
		fprintf(stderr,
			"%s: exceeded maximum number of requests (%d)\n",
			__func__, LIMIT);
		goto locked;
	}

	req = alloc_request(buf, n);

	if (req == NULL) {
		fprintf(stderr, "%s: alloc_request failed\n", __func__);
		goto locked;
	}

	if (list->tail) {
		list->tail->next = req;
	} else {
		list->head = req;
	}

	list->tail = req;
	list->n_requests++;
	error = pthread_cond_signal(&list->cond);

	if (error) {
		fprintf(stderr, "%s: pthread_cond_signal(3): %s\n", __func__,
			strerror(error));
		goto locked;
	}

	ret = 0;

locked:
	error = pthread_mutex_unlock(&list->mutex);

	if (error) {
		fprintf(stderr, "%s: pthread_mutex_unlock(3): %s\n", __func__,
			strerror(error));
		ret = -1;
	}

unlocked:
	if (ret) {
		free_request(req);
	}

	return ret;
}

static int
write_posix(const struct stream_impl *si, const void *buf, size_t n)
{
	return push_request(&si->params->u.write, buf, n);
}

static int
prepare_fds(const struct read *r, struct pollfd **fds, nfds_t *nfds)
{
	size_t n = r->n_clients + 1;
	struct pollfd *p = malloc(n * sizeof(*p));

	if (p == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	/* Setup server fd. */
	*p = (struct pollfd){.fd = r->fd, .events = POLLIN};

	for (size_t i = 1; i < n; i++) {
		const struct client *client = &r->clients[i - 1];

		p[i] = (struct pollfd){.fd = client->fd, .events = POLLIN};
	}

	*nfds = n;
	*fds = p;
	return 0;
}

static void
free_fds(void *arg)
{
	struct pollfd **fds = arg;

	free(*fds);
}

static int
get_packet(struct stream_impl *si, struct stream_read *sr)
{
	int ret, result;
	struct read *r = &si->params->u.read;
	struct pollfd *fds = NULL;
	nfds_t nfds;

	pthread_cleanup_push(free_fds, &fds);

	ret = -1;
	fds = NULL;

	if (prepare_fds(r, &fds, &nfds)) {
		fprintf(stderr, "%s: prepare_fds failed\n", __func__);
		goto end;
	}

	result = poll(fds, nfds, -1);

	if (result < 0) {
		fprintf(stderr, "%s: poll(2): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	for (nfds_t i = 0; i < nfds; i++) {
		const struct pollfd *p = &fds[i];

		if (p->revents) {
			const struct StreamPosix *cfg = &si->cfg.params.posix;

			ret = process_read(cfg, r, p->fd, sr);
			/* EVP_stream requires only one event to be treated at
			 * a time. */
			break;
		}
	}

end:
	pthread_cleanup_pop(1);
	return ret;
}

static int
read_posix(struct stream_impl *si, struct stream_read *sr)
{
	int ret;

retry:
	ret = get_packet(si, sr);

	if (ret > 0) {
		/* No packet available. */
		goto retry;
	}

	return ret;
}

static void
free_msg_posix(void *args)
{
	free(args);
}

const struct stream_ops stream_posix_ops = {.init = init_posix,
					    .close = close_posix,
					    .write = write_posix,
					    .read = read_posix,
					    .free_msg = free_msg_posix};
