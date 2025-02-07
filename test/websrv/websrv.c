/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <libweb/handler.h>
#include <libweb/http.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xpthread.h>

#include "xlog.h"

static struct websrv {
	pthread_t thread_id;
	struct handler *handler;
	unsigned short port;
} g_websrv;

static int
on_length(unsigned long long len, const struct http_cookie *c,
	  struct http_response *r, void *user)
{
	*r = (const struct http_response){.status = HTTP_STATUS_BAD_REQUEST};

	return 1;
}

static void *
websrv_thread(void *user_data)
{
	struct websrv *ctxt = user_data;

	if (handler_loop(ctxt->handler)) {
		xlog_error("handler_loop failed");
	}

	xlog_info("Web server stopped");
	return NULL;
}

int
websrv_setup(unsigned short port)
{
	struct websrv *ctxt = &g_websrv;
	const struct handler_cfg cfg = {
		.tmpdir = "/tmp",
		.length = on_length,
		/* Arbitrary value*/
		.max_headers = 1000,
	};
	struct handler *h = handler_alloc(&cfg);
	if (h == NULL) {
		xlog_error("handler_alloc failed");
		return -1;
	}

	if (handler_listen(h, port, &ctxt->port)) {
		xlog_error("handler_listen failed");
		handler_free(h);
		return -1;
	}

	ctxt->handler = h;
	return 0;
}

int
websrv_get_port(unsigned short *port)
{
	struct websrv *ctxt = &g_websrv;

	if (!ctxt->handler) {
		xlog_error("Web server not setup. No port attributed.");
		return -1;
	}

	*port = ctxt->port;
	return 0;
}

int
websrv_add_route(const char *url, const enum http_op op, const handler_fn fn,
		 void *const user)
{
	struct websrv *ctxt = &g_websrv;

	assert(ctxt->handler != NULL);

	if (handler_add(ctxt->handler, url, op, fn, user)) {
		xlog_error("handler_add failed");
		return -1;
	}

	return 0;
}

int
websrv_start(void)
{
	struct websrv *ctxt = &g_websrv;

	assert(ctxt->handler != NULL);

	int ret = pthread_create(&ctxt->thread_id, NULL, websrv_thread, ctxt);
	if (ret) {
		xlog_error("pthread_create(3): %s", strerror(ret));
		return -1;
	}

	return 0;
}

int
websrv_stop(void)
{
	struct websrv *ctxt = &g_websrv;

	assert(ctxt->handler != NULL);

	xlog_info("Stopping web server...");

	pthread_kill(ctxt->thread_id, SIGTERM);
	pthread_join(ctxt->thread_id, NULL);

	xlog_info("Webserver stopped");
	return 0;
}

int
websrv_teardown(void)
{
	struct websrv *ctxt = &g_websrv;

	assert(ctxt->handler != NULL);

	handler_free(ctxt->handler);

	return 0;
}

// Default handlers

int
on_get_user_string(const struct http_payload *p, struct http_response *r,
		   void *user)
{
	const char *buf = user;

	xlog_info("%s: handling GET", __func__);

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.buf.ro = buf,
		.n = strlen(buf),
	};

	return 0;
}

int
on_put_default(const struct http_payload *p, struct http_response *r,
	       void *user)
{
	static const char str[] =
		"webclient still needs a body for some reason";

	xlog_info("%s: handling PUT", __func__);

	*r = (struct http_response){.status = p->expect_continue
						      ? HTTP_STATUS_CONTINUE
						      : HTTP_STATUS_OK,
				    .buf.ro = str,
				    .n = strlen(str)};

	return 0;
}
