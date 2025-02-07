/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <sys/sys.h>

#include <agent_internal.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <evp/sdk_sys.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "evp/agent.h"
#include "hub.h"
#include "mqtt_custom.h"
#include "path.h"
#include "persist.h"

#define TOPIC         "topic"
#define VALUE         "value"
#define PERSIST_VALUE "persist_value"

static struct test {
	struct evp_agent_context *ctxt;
	pthread_t thread;
	sem_t sem, app_sem;
	char *topic, *value;
	enum SYS_type_configuration type, type2;
	enum SYS_callback_reason reason;
	void *user;
	SYS_config_cb cb, cb2;
	struct SYS_client *c, *exp_c;
} test;

static void
config_cb(struct SYS_client *c, const char *topic, const char *value,
	  enum SYS_type_configuration type, enum SYS_callback_reason reason,
	  void *user)
{
	test.c = c;
	test.topic = strdup(topic);
	test.value = strdup(value);
	test.type = type;
	test.reason = reason;
	test.user = user;
	test.cb = config_cb;
	assert(!sem_post(&test.sem));
}

static void
config_cb2(struct SYS_client *c, const char *topic, const char *value,
	   enum SYS_type_configuration type, enum SYS_callback_reason reason,
	   void *user)
{
	/* Do not care so much about the callback parameters being valid here.
	 * It is assumed config_cb will already check them. */
	test.cb2 = config_cb2;
	test.type2 = type;
	assert(!sem_post(&test.sem));
}

static void
setup_desired(void)
{
	const char *desired = path_get(DESIRED_TWINS_PATH_ID);
	FILE *f;
	static const char json[] =
		"{\"configuration/$system/" TOPIC "\": \"" PERSIST_VALUE "\"}";

	assert_non_null(desired);
	assert_non_null((f = fopen(desired, "wb")));
	assert_int_equal(fwrite(json, strlen(json), 1, f), 1);
	assert_int_equal(fclose(f), 0);
}

static void
test_sysapp_config(void **state)
{
	struct test *test = *state;
	struct evp_agent_context *ctxt = test->ctxt;

	/* Wait for SYS_set_configuration_cb. */
	assert_int_equal(sem_wait(&test->app_sem), 0);

	/* Configuration cached from persistent storage (1/2). */
	assert_int_equal(sem_wait(&test->sem), 0);
	assert_int_equal(test->type, SYS_CONFIG_PERSIST);
	assert_ptr_equal(test->c, test->exp_c);
	assert_string_equal(test->topic, TOPIC);
	assert_string_equal(test->value, PERSIST_VALUE);
	free(test->topic);
	free(test->value);

	/* Configuration cached from persistent storage (2/2). */
	assert_int_equal(sem_wait(&test->sem), 0);
	assert_int_equal(test->type2, SYS_CONFIG_PERSIST);

	/* Trigger new configuration. */
	assert_int_equal(
		sys_notify_config(ctxt->sys, EVP_CONFIG_HUB, TOPIC, VALUE), 0);
	assert_int_equal(sem_wait(&test->sem), 0);
	assert_int_equal(sem_wait(&test->sem), 0);
	assert_ptr_equal(test->c, test->exp_c);
	assert_string_equal(test->topic, TOPIC);
	assert_string_equal(test->value, VALUE);
	assert_int_equal(test->type, SYS_CONFIG_HUB);
	assert_int_equal(test->reason, SYS_REASON_FINISHED);
	assert_ptr_equal(test->user, NULL);
	assert_ptr_equal(test->cb, config_cb);
	assert_ptr_equal(test->cb2, config_cb2);
}

static void *
sysapp(void *args)
{
	struct test *test = args;
	struct evp_agent_context *ctxt = test->ctxt;
	struct SYS_client *c = evp_agent_register_sys_client(ctxt);
	enum SYS_result result;

	if (!c) {
		fprintf(stderr, "%s: evp_agent_register_sys_client failed\n",
			__func__);
		return NULL;
	}

	test->exp_c = c;
	result = SYS_set_configuration_cb(c, TOPIC, config_cb, SYS_CONFIG_ANY,
					  NULL);

	if (result) {
		fprintf(stderr,
			"%s: SYS_set_configuration_cb failed with %d\n",
			__func__, result);
		goto end;
	}

	result = SYS_set_configuration_cb(c, TOPIC, config_cb2, SYS_CONFIG_ANY,
					  NULL);

	if (result) {
		fprintf(stderr,
			"%s: SYS_set_configuration_cb failed with %d\n",
			__func__, result);
		goto end;
	}

	if (sem_post(&test->app_sem)) {
		fprintf(stderr, "%s: sem_post(3): %s\n", __func__,
			strerror(errno));
		goto end;
	}

	result = SYS_process_event(c, -1);

	if (result) {
		fprintf(stderr, "%s: SYS_process_event failed with %d\n",
			__func__, result);
		goto end;
	}

	result = SYS_process_event(c, -1);

	if (result) {
		fprintf(stderr, "%s: SYS_process_event failed with %d\n",
			__func__, result);
		goto end;
	}

	result = SYS_process_event(c, -1);

	if (result) {
		fprintf(stderr, "%s: SYS_process_event failed with %d\n",
			__func__, result);
		goto end;
	}

	result = SYS_process_event(c, -1);

	if (result) {
		fprintf(stderr, "%s: SYS_process_event failed with %d\n",
			__func__, result);
		goto end;
	}

end:

	if (evp_agent_unregister_sys_client(ctxt, c)) {
		fprintf(stderr, "%s: evp_agent_unregister_sys_client failed\n",
			__func__);
	}

	return NULL;
}

static int
setup(void **state)
{
	int error;

	if (sem_init(&test.sem, 0, 0)) {
		fprintf(stderr, "%s: sem_init(3) sem: %s\n", __func__,
			strerror(errno));
	}

	if (sem_init(&test.app_sem, 0, 0)) {
		fprintf(stderr, "%s: sem_init(3) app_sem: %s\n", __func__,
			strerror(errno));
	}

	const char *datadir = getenv("EVP_DATA_DIR");

	assert_non_null(datadir);
	path_init(datadir);
	init_local_twins_db();
	agent_test_setup();
	setup_desired();

	test.ctxt = agent_test_start();
	error = pthread_create(&test.thread, NULL, sysapp, &test);

	if (error) {
		fprintf(stderr, "%s: pthread_create(3): %s\n", __func__,
			strerror(error));
	}

	*state = &test;
	return 0;
}

static int
teardown(void **state)
{
	struct test *test = *state;
	int error = pthread_join(test->thread, NULL);

	if (error) {
		fprintf(stderr, "%s: pthread_join(3): %s\n", __func__,
			strerror(error));
	}

	free(test->topic);
	free(test->value);
	sem_destroy(&test->sem);
	sem_destroy(&test->app_sem);
	agent_test_exit();
	return 0;
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sysapp_config),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}
