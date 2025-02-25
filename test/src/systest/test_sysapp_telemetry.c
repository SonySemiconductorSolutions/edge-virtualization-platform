/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "agent_test.h"
#include "hub.h"
#include "sys/sys.h"

struct test {
	struct evp_agent_context *ctxt;
	pthread_t thread;
	pthread_mutex_t mtx;
	enum SYS_result result;
	struct SYS_client *c;
	sem_t sem;
	enum SYS_callback_reason reason;
	bool fail, strdup_fail;
} g_test;

static void
telemetry_cb(struct SYS_client *c, enum SYS_callback_reason reason, void *user)
{
	struct test *test = user;

	test->reason = reason;
	assert(!sem_post(&test->sem));
}

static void *
sysapp(void *args)
{
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

	test->c = c;
	*result = SYS_send_telemetry(c, "key", "{\"value\": \"hey\"}",
				     telemetry_cb, test);

	if (*result) {
		fprintf(stderr, "%s: SYS_send_telemetry failed with %s\n",
			__func__, SYS_result_tostr(*result));
		goto end;
	}

	*result = SYS_process_event(c, -1);

	if (*result) {
		fprintf(stderr, "%s: SYS_process_event failed with %s\n",
			__func__, SYS_result_tostr(*result));
		goto end;
	}

end:

	if (evp_agent_unregister_sys_client(ctxt, c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sysapp failed\n",
			__func__);
	}

	return NULL;
}

static void
check_reason(struct test *test, enum SYS_callback_reason reason)
{
	assert_int_equal(sem_wait(&test->sem), 0);
	assert_int_equal(test->reason, reason);
}

static void
test_sysapp_telemetry(void **state)
{
	struct test *test = *state;

	check_reason(test, SYS_REASON_FINISHED);
	agent_poll(verify_json, "$system/key.value=%s", "hey");
	assert_int_equal(pthread_join(test->thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

static void
test_sysapp_telemetry_error(void **state)
{
	struct test *test = *state;

	check_reason(test, SYS_REASON_ERROR);
	assert_int_equal(pthread_join(test->thread, NULL), 0);
	assert_int_equal(test->result, SYS_RESULT_OK);
}

void *
__wrap_strdup(const char *s)
{
	void *__real_strdup(const char *);
	bool fail;

	assert(!pthread_mutex_lock(&g_test.mtx));
	fail = g_test.strdup_fail;
	assert(!pthread_mutex_unlock(&g_test.mtx));

	if (fail)
		return NULL;

	return __real_strdup(s);
}

int
__wrap_sys_collect_telemetry(struct sys_group *gr, sys_telemetry_collect cb,
			     void *user)
{
	int __real_sys_collect_telemetry(struct sys_group *,
					 sys_telemetry_collect, void *);
	int ret;

	assert(!pthread_mutex_lock(&g_test.mtx));
	if (g_test.fail) {
		g_test.strdup_fail = true;
	}

	/* add_sys_telemetry, as called by sys_collect_telemetry, will call
	 * strdup(3). */
	ret = __real_sys_collect_telemetry(gr, cb, user);

	g_test.strdup_fail = false;
	assert(!pthread_mutex_unlock(&g_test.mtx));
	return ret;
}

static int
setup_common(struct test *test)
{
	int error = pthread_create(&test->thread, NULL, sysapp, test);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	return 0;
}

static int
setup(void **state)
{
	struct test *test = *state;

	assert(!pthread_mutex_lock(&g_test.mtx));
	test->fail = false;
	assert(!pthread_mutex_unlock(&g_test.mtx));
	return setup_common(test);
}

static int
setup_error(void **state)
{
	struct test *test = *state;

	assert(!pthread_mutex_lock(&g_test.mtx));
	test->fail = true;
	assert(!pthread_mutex_unlock(&g_test.mtx));
	return setup_common(test);
}

static int
suite_setup(void **state)
{
	struct test *test = &g_test;
	int error;
	pthread_mutexattr_t attr;

	if (sem_init(&test->sem, 0, 0)) {
		fprintf(stderr, "%s: sem_init(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	if ((error = pthread_mutexattr_init(&attr))) {
		fprintf(stderr, "%s: pthread_mutexattr_init(3): %s\n",
			__func__, strerror(error));
		return -1;
	}

	if ((error = pthread_mutexattr_settype(&attr,
					       PTHREAD_MUTEX_RECURSIVE))) {
		fprintf(stderr, "%s: pthread_mutexattr_settype(3): %s\n",
			__func__, strerror(error));
		return -1;
	}

	if ((error = pthread_mutex_init(&test->mtx, &attr))) {
		fprintf(stderr, "%s: pthread_mutex_init(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	agent_test_setup();
	test->ctxt = agent_test_start();

	if (!test->ctxt) {
		fprintf(stderr, "%s: agent_test_start failed\n", __func__);
		return -1;
	}

	*state = test;
	return 0;
}

static int
suite_teardown(void **state)
{
	struct test *test = *state;
	int error;

	if (sem_destroy(&test->sem)) {
		fprintf(stderr, "%s: sem_destroy(3): %s\n", __func__,
			strerror(errno));
		return -1;
	}

	agent_test_exit();

	if ((error = pthread_mutex_destroy(&test->mtx))) {
		fprintf(stderr, "%s: pthread_mutex_destroy(3): %s\n", __func__,
			strerror(error));
		return -1;
	}

	return 0;
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_sysapp_telemetry, setup,
						NULL),
		cmocka_unit_test_setup_teardown(test_sysapp_telemetry_error,
						setup_error, NULL),
	};

	return cmocka_run_group_tests(tests, suite_setup, suite_teardown);
}
