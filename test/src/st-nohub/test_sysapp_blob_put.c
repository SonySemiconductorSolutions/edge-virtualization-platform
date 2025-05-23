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

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "websrv/websrv.h"

/* Arbitrary number. */
enum { BLOB_LEN = 4096, MAGIC = 'F' };

struct test {
	unsigned short port;
	char *url;
	enum SYS_result result;
	struct SYS_client *c;
	struct evp_agent_context *ctxt;
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

	switch (reason) {
	case SYS_REASON_MORE_DATA:
		memset(blob->blob_buffer, MAGIC, blob->len);
		break;

	case SYS_REASON_FINISHED:
		test->done = true;
		agent_write_to_pipe("blob_cb");
		break;

	case SYS_REASON_TIMEOUT:
	case SYS_REASON_ERROR:
		abort();
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
	enum SYS_result *result = &test->result;

	*result = SYS_put_blob(test->c, test->url, headers, BLOB_LEN, blob_cb,
			       test);

	if (*result) {
		fprintf(stderr, "%s: SYS_put_blob failed with %s\n", __func__,
			SYS_result_tostr(*result));
		goto end;
	}

	for (;;) {
		*result = SYS_process_event(test->c, -1);

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

	return NULL;
}

static void
test_sysapp_blob_put(void **state)
{
	struct test *test = *state;

	pthread_t thread;

	assert_int_equal(pthread_create(&thread, NULL, sysapp, test), 0);

	agent_poll(verify_equals, "on_put");
	agent_poll(verify_equals, "blob_cb");

	assert_int_equal(pthread_join(thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

static int
on_put(const struct http_payload *p, struct http_response *r, void *user)
{
	/* NuttX webclient requires a body for PUT responses, even if not
	 * needed. */
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

	/* Notify the test that this callback was actually called */

	agent_write_to_pipe("on_put");

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
		cmocka_unit_test(test_sysapp_blob_put),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
