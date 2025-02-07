/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <nng/nng.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evp/sdk.h"
#include "stream.h"

struct stream_impl_params {
	nng_socket socket;
	union {
		nng_dialer dialer;
		nng_listener listener;
	} dl;
};

static int
close_internal(const struct StreamNng *cfg, struct stream_impl_params *nng)
{
	int ret = 0;

	if (nng != NULL) {
		int error;

		switch (cfg->mode) {
		case STREAM_NNG_MODE_DIAL:
			error = nng_dialer_close(nng->dl.dialer);
			if (error != 0) {
				fprintf(stderr, "nng_dialer_close: %s\n",
					nng_strerror(error));
				ret = -1;
			}
			break;
		case STREAM_NNG_MODE_LISTEN:
			error = nng_listener_close(nng->dl.listener);
			if (error != 0) {
				fprintf(stderr, "nng_listener_close: %s\n",
					nng_strerror(error));
				ret = -1;
			}
			break;
		}

		error = nng_close(nng->socket);
		if (error != 0) {
			fprintf(stderr, "nng_close: %s\n",
				nng_strerror(error));
			ret = -1;
		}
	}

	free(nng);
	return ret;
}

static int
close_nng_stream(struct stream_impl *si)
{
	return close_internal(&si->cfg.params.nng, si->params);
}

static EVP_RESULT
init_nng_stream(struct stream_impl *si)
{
	EVP_RESULT ret = EVP_ERROR;
	const struct StreamNng *cfg = &si->cfg.params.nng;
	struct stream_impl_params *nng = malloc(sizeof(*nng));

	if (nng == NULL) {
		fprintf(stderr, "%s: malloc(3): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	*nng = (struct stream_impl_params){0};

	int error;

	switch (cfg->protocol) {
	case STREAM_NNG_PROTOCOL_PUSH:
		error = nng_push0_open(&nng->socket);
		if (error != 0) {
			fprintf(stderr, "nng_push0_open: %s\n",
				nng_strerror(error));
			goto end;
		}
		break;
	case STREAM_NNG_PROTOCOL_PULL:
		error = nng_pull0_open(&nng->socket);
		if (error != 0) {
			fprintf(stderr, "nng_pull0_open: %s\n",
				nng_strerror(error));
			return EVP_ERROR;
		}
	}

	switch (cfg->mode) {
	case STREAM_NNG_MODE_DIAL:
		error = nng_dialer_create(&nng->dl.dialer, nng->socket,
					  cfg->connection);
		if (error != 0) {
			fprintf(stderr, "nng_dialer_create: %s\n",
				nng_strerror(error));
			return EVP_ERROR;
		}

		error = nng_dialer_start(nng->dl.dialer, 0);
		if (error != 0) {
			fprintf(stderr, "nng_dialer_start: %s\n",
				nng_strerror(error));
			return EVP_ERROR;
		}
		break;
	case STREAM_NNG_MODE_LISTEN:
		{
			error = nng_listener_create(&nng->dl.listener,
						    nng->socket,
						    cfg->connection);
			if (error != 0) {
				fprintf(stderr, "nng_listener_create: %s\n",
					nng_strerror(error));
				return EVP_ERROR;
			}

			error = nng_listener_start(nng->dl.listener, 0);
			if (error != 0) {
				fprintf(stderr, "nng_listener_start: %s\n",
					nng_strerror(error));
				return EVP_ERROR;
			}

			int port;

			error = nng_listener_get_int(nng->dl.listener,
						     NNG_OPT_TCP_BOUND_PORT,
						     &port);

			if (error != 0) {
				fprintf(stderr,
					"%s: nng_dialer_get_int failed: %s\n",
					__func__, nng_strerror(error));
				return EVP_ERROR;
			}

			struct notification *n = stream_notification();

			if (n == NULL) {
				fprintf(stderr,
					"%s: stream_notification failed\n",
					__func__);
				return EVP_ERROR;
			}

			struct stream_port p = {.port = port, .si = si};

			if (notification_publish(n, "init/port", &p)) {
				fprintf(stderr,
					"%s: notification_publish failed\n",
					__func__);
				return EVP_ERROR;
			}
		}
	}

	si->params = nng;
	ret = EVP_OK;
end:
	if (ret != EVP_OK) {
		if (nng != NULL) {
			close_internal(cfg, nng);
		}
	}

	return ret;
}

static int
write_nng(const struct stream_impl *si, const void *buf, size_t n)
{
	const struct stream_impl_params *nng = si->params;
	/* nng_send(3) takes a (void *) only because the buffer is freed when
	 * NNG_FLAG_ALLOC is passed. Otherwise, no modifications are made,
	 * so the explicit cast below is safe. */
	int error = nng_send(nng->socket, (void *)buf, n, 0);
	if (error != 0) {
		fprintf(stderr, "nng_send: %s\n", nng_strerror(error));
		return -1;
	}
	return 0;
}

/*
 * A modified version of nng_recvmsg that disables thread cancellation.
 * This is required since the thread running this function might be
 * cancelled while nng_recv_aio or nng_aio_wait are running, which
 * might have cancellation points. The original function is implemented on
 * src/nng/src/nng.c.
 *
 * Unfortunately, cleanup handlers are not enough here, since mutexes
 * are taken internally by the nng library that cannot be unlocked from
 * userspace, causing a deadlock.
 */
static int
recvmsg_nng_custom(nng_socket s, nng_msg **msgp, nng_duration timeout)
{
	nng_aio *ap = NULL;
	int rv = NNG_EINVAL, oldstate,
	    error = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);

	if (error) {
		fprintf(stderr, "%s: pthread_setcancelstate(3) disable: %s\n",
			__func__, strerror(error));
		goto end;
	}

	rv = nng_aio_alloc(&ap, NULL, NULL);

	if (rv) {
		fprintf(stderr, "%s: nng_aio_alloc: %s\n", __func__,
			nng_strerror(rv));
		goto end;
	}

	nng_aio_set_timeout(ap, timeout);
	nng_recv_aio(s, ap);
	nng_aio_wait(ap);
	rv = nng_aio_result(ap);

	if (rv == 0) {
		*msgp = nng_aio_get_msg(ap);
	} else if (rv == NNG_ETIMEDOUT) {
		rv = NNG_EAGAIN;
	}

end:
	nng_aio_free(ap);
	error = pthread_setcancelstate(oldstate, NULL);

	if (error) {
		fprintf(stderr, "%s: pthread_setcancelstate(3) oldstate: %s\n",
			__func__, strerror(error));
		rv = NNG_EINVAL;
	}

	return rv;
}

static int
read_nng(struct stream_impl *si, struct stream_read *sr)
{
	const struct stream_impl_params *nng = si->params;
	nng_msg *msg = NULL;
	const nng_duration timeout = 1000;
	int error;

retry:
	error = recvmsg_nng_custom(nng->socket, &msg, timeout);

	if (error == NNG_EAGAIN) {
		goto retry;
	}

	if (error != 0) {
		fprintf(stderr, "recvmsg_nng_custom: %s\n",
			nng_strerror(error));
		return -1;
	}

	nng_pipe pipe = nng_msg_get_pipe(msg);

	*sr = (struct stream_read){.id = pipe.id,
				   .buf = nng_msg_body(msg),
				   .n = nng_msg_len(msg),
				   .free_args = msg};

	return 0;
}

static void
free_msg_nng(void *args)
{
	nng_msg_free(args);
}

static int
stream_nng_atexit(void)
{
	return atexit(nng_fini);
}

const struct stream_ops stream_nng_ops = {
	.init = init_nng_stream,
	.close = close_nng_stream,
	.write = write_nng,
	.read = read_nng,
	.free_msg = free_msg_nng,
	.atexit = stream_nng_atexit,
};
