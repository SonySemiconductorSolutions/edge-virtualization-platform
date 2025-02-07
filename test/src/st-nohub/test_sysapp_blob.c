/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
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

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "websrv/websrv.h"

struct test {
	unsigned short port;
	char *url;
	struct evp_agent_context *ctxt;
	pthread_t thread;
	enum SYS_result result;
	struct SYS_client *c;
	bool done;
};

struct webclient_context;

void
__wrap_webclient_perform(FAR struct webclient_context *ctx)
{
	void __real_webclient_perform(FAR struct webclient_context *);

	__real_webclient_perform(ctx);
}

static enum SYS_result
blob_cb(struct SYS_client *c, struct SYS_blob_data *blob,
	enum SYS_callback_reason reason, void *user)
{
	struct test *test = user;

	if (reason == SYS_REASON_FINISHED) {
		test->done = true;
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
	struct evp_agent_context *ctxt = test->ctxt;
	struct SYS_client *c = evp_agent_register_sys_client(ctxt);
	enum SYS_result *result = &test->result;

	if (!c) {
		fprintf(stderr, "%s: evp_agent_register_sysapp failed\n",
			__func__);
		*result = SYS_RESULT_ERROR_NO_MEM;
		return NULL;
	}

	*result = SYS_get_blob(c, test->url, headers, blob_cb, test);

	if (*result) {
		fprintf(stderr, "%s: SYS_get_blob failed with %s\n", __func__,
			SYS_result_tostr(*result));
		goto end;
	}

	for (;;) {
		*result = SYS_process_event(c, -1);

		switch (*result) {
		case SYS_RESULT_OK:
			if (test->done) {
				goto end;
			}

			break;
		case SYS_RESULT_TIMEDOUT:
			break;

		default:
			fprintf(stderr,
				"%s: SYS_process_event failed with %s\n",
				__func__, SYS_result_tostr(*result));
			goto end;
		}
	}

end:

	if (evp_agent_unregister_sys_client(ctxt, c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sysapp failed\n",
			__func__);
	}

	return NULL;
}

static void
test_sysapp_blob(void **state)
{
	struct test *test = *state;

	assert_int_equal(pthread_join(test->thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

static int
on_get(const struct http_payload *p, struct http_response *r, void *user)
{
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

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.buf.ro = body,
		.n = strlen(body),
	};

	return 0;
}

static int
setup(void **state)
{
	static struct test test;
	int error;

	if (websrv_setup(0)) {
		fprintf(stderr, "%s: websrv_setup failed\n", __func__);
		return -1;
	}

	if (websrv_add_route("/test", HTTP_OP_GET, on_get, NULL)) {
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

	agent_test_setup();
	test.ctxt = agent_test_start();

	if (!test.ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	error = pthread_create(&test.thread, NULL, sysapp, &test);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	*state = &test;
	return 0;
}

static int
teardown(void **state)
{
	struct test *test = *state;

	free(test->url);
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
		cmocka_unit_test(test_sysapp_blob),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
