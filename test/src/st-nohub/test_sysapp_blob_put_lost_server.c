/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <inttypes.h>
#include <libweb/http.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "webclient/webclient.h"

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "websrv/websrv.h"
#include "xlog.h"

#define SYSAPP_LOG(fmt, ...) xlog_info("<SYSAPP> " fmt, ##__VA_ARGS__)
#define SET_VAR_SAFE(var, value)                                              \
	pthread_mutex_lock(&mutex_vars);                                      \
	(var) = (value);                                                      \
	pthread_mutex_unlock(&mutex_vars);

/* Arbitrary number. */
enum { BLOB_LEN = 4096, MAGIC = 'F' };

pthread_mutex_t mutex_vars = PTHREAD_MUTEX_INITIALIZER;
static bool simulate_error = false;
static bool g_next = false;

struct test {
	unsigned short port;
	char *url;
	char *url_error;
	char *url_final;
	struct SYS_client *c;
	struct evp_agent_context *ctxt;
	bool blob_done;
};

int
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	int __real_webclient_perform(FAR struct webclient_context *);

	return __real_webclient_perform(ctx);
}

ssize_t
__wrap_webclient_conn_send(FAR struct webclient_conn_s *conn,
			   FAR const void *buffer, size_t len)
{
	ssize_t __real_webclient_conn_send(FAR struct webclient_conn_s *,
					   FAR const void *, size_t);
	bool send_error = false;
	pthread_mutex_lock(&mutex_vars);
	if (simulate_error) {
		simulate_error = false;
		send_error = true;
	}
	pthread_mutex_unlock(&mutex_vars);

	if (send_error) {
		xlog_info("Generating errno 107 in webclient");
		agent_write_to_pipe("simulate error");
		return -107;
	} else {
		return __real_webclient_conn_send(conn, buffer, len);
	}
}

static enum SYS_result
blob_cb(struct SYS_client *c, struct SYS_blob_data *blob,
	enum SYS_callback_reason reason, void *user)
{
	switch (reason) {
	case SYS_REASON_MORE_DATA:
		memset(blob->blob_buffer, MAGIC, blob->len);
		break;

	case SYS_REASON_FINISHED:
	case SYS_REASON_TIMEOUT:
	case SYS_REASON_ERROR:
		break;
	}

	return SYS_RESULT_OK;
}

static void *
sysapp(void *args)
{
	static const struct SYS_http_header headers[] = {
		{.key = "key1", .value = "value1"},
		{.key = "key2", .value = "value2"},
		{.key = "key3", .value = "value3"},
		NULL};

	struct test *test = args;
	enum SYS_result result;

	char *list[3] = {
		test->url,
		test->url_error,
		test->url_final,
	};

	for (int i = 0; i < 3; i++) {

		char *url = list[i];
		SYSAPP_LOG("blob PUT to %s", url);

		if (strstr(url, "error")) {
			SET_VAR_SAFE(simulate_error, true);
		}
		result = SYS_put_blob(test->c, url, headers, BLOB_LEN, blob_cb,
				      test);
		SYSAPP_LOG("SYS_put_blob result %s", SYS_result_tostr(result));

		while (true) {
			pthread_mutex_lock(&mutex_vars);
			bool next = g_next;
			g_next = false;
			pthread_mutex_unlock(&mutex_vars);
			if (next)
				break;

			result = SYS_process_event(test->c, 1000);
			SYSAPP_LOG("process event done with %s",
				   SYS_result_tostr(result));
		}
	}

	return NULL;
}

/**
 * The goal of this test is validate that when there is an error
 * where the server connection is lost like:
 *  - ENOTCONN 107 Transport endpoint is not connected
 * The agent discards the blob operation but it keeps working
 * as expected an the g_next blobs are well delivered.asm
 *
 * This test does these steps:
 *  1)	performs a blob PUT to /test endpoint
 *  2)	performs a blob PUT to /test_error endpoint, it will fails because
 *  	an errno 107 is injected
 *  3)  performs a valid operation against /test_final
 *
 *
 * The steps are executed in a sequence to be sure that the agent can
 * recover the blob operations after an error
 *
 * ref ADI-2317
 *
 */
static void
test_sysapp_blob_put_lost_server(void **state)
{
	struct test *test = *state;

	pthread_t thread;

	assert_int_equal(pthread_create(&thread, NULL, sysapp, test), 0);

	agent_poll(verify_equals, "on_put:/test");
	SET_VAR_SAFE(g_next, true);

	agent_poll(verify_equals, "simulate error");
	SET_VAR_SAFE(g_next, true);

	agent_poll(verify_equals, "on_put:/test_final");
	SET_VAR_SAFE(g_next, true);

	assert_int_equal(pthread_join(thread, NULL), 0);
}

static int
on_put(const struct http_payload *p, struct http_response *r, void *user)
{
	/* NuttX webclient requires a body for PUT responses, even if
	 * not needed. */
	static const char body[] = "hello!";
	struct expected {
		bool found;
		const char *key, *value;
	} list[] = {
		{
			.key = "key1",
			.value = "value1",
		},
		{
			.key = "key2",
			.value = "value2",
		},
		{
			.key = "key3",
			.value = "value3",
		},
	};

	for (size_t i = 0; i < p->n_headers; i++) {
		const struct http_header *h = &p->headers[i];

		for (size_t i = 0; i < sizeof list / sizeof *list; i++) {
			struct expected *e = &list[i];

			if (!strcmp(h->header, e->key) &&
			    !strcmp(h->value, e->value)) {
				assert(!e->found);

				e->found = true;
				break;
			}
		}
	}

	/* Ensure all expected headers were received. */
	for (size_t i = 0; i < sizeof list / sizeof *list; i++) {
		const struct expected *e = &list[i];

		assert(e->found);
	}

	FILE *f = fopen(p->u.put.tmpname, "rb");
	char b;

	assert(f);

	for (int i = 0; i < BLOB_LEN; i++) {

		assert(fread(&b, 1, 1, f));
		assert(b == MAGIC);
	}

	assert(!fread(&b, 1, 1, f));
	assert(feof(f) && !ferror(f));
	assert(!fclose(f));

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.buf.ro = body,
		.n = strlen(body),
	};

	char *txt;
	/* Notify the test that this callback was actually called */
	asprintf(&txt, "on_put:%s", p->resource);
	agent_write_to_pipe(txt);
	free(txt);

	return 0;
}

static int
setup(void **state)
{
	static struct test test;

	if (websrv_setup(0)) {
		fprintf(stderr, "%s: websrv_setup failed\n", __func__);
		return -1;
	}

	if (websrv_add_route("/test", HTTP_OP_PUT, on_put, NULL)) {
		fprintf(stderr, "%s: websrv_add_route failed\n", __func__);
		return -1;
	}

	if (websrv_add_route("/test_error", HTTP_OP_PUT, on_put, NULL)) {
		fprintf(stderr, "%s: websrv_add_route failed\n", __func__);
		return -1;
	}

	if (websrv_add_route("/test_final", HTTP_OP_PUT, on_put, NULL)) {
		fprintf(stderr, "%s: websrv_add_route failed\n", __func__);
		return -1;
	}

	if (websrv_get_port(&test.port)) {
		fprintf(stderr, "%s: websrv_get_port failed\n", __func__);
		return -1;
	}

	if (websrv_start()) {
		fprintf(stderr, "%s: websrv_start failed\n", __func__);
		return -1;
	}

	if (asprintf(&test.url, "http://localhost:%hu/test", test.port) < 0) {
		fprintf(stderr, "%s: asprintf(3) failed\n", __func__);
		return -1;
	}

	if (asprintf(&test.url_error, "http://localhost:%hu/test_error",
		     test.port) < 0) {
		fprintf(stderr, "%s: asprintf(3) failed\n", __func__);
		return -1;
	}

	if (asprintf(&test.url_final, "http://localhost:%hu/test_final",
		     test.port) < 0) {
		fprintf(stderr, "%s: asprintf(3) failed\n", __func__);
		return -1;
	}

	agent_test_setup();

	test.ctxt = agent_test_start();

	if (!test.ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	test.c = evp_agent_register_sys_client(test.ctxt);

	if (!test.c) {
		fprintf(stderr, "%s: evp_agent_register_sysapp failed\n",
			__func__);
		return -1;
	}

	*state = &test;
	return 0;
}

static int
teardown(void **state)
{
	struct test *test = *state;

	if (evp_agent_unregister_sys_client(test->ctxt, test->c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sysapp failed\n",
			__func__);
	}

	free(test->url);
	free(test->url_error);
	free(test->url_final);
	agent_test_exit();

	if (websrv_stop()) {
		fprintf(stderr, "%s: websrv_stop failed\n", __func__);
		return -1;
	}

	websrv_teardown();
	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sysapp_blob_put_lost_server),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
