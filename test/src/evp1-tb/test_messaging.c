/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Used by run-unit-tests.sh
 */

#include <errno.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <internal/util.h>

#include "evp_hub.h"
#include "main_loop.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "path.h"
#include "sdk_agent.h"
#include "sdk_msg.h"

struct context {
	const struct evp_hub_context *hub;
};

bool g_verbose;

static const char *module_name = "MESSAGING";

struct send_message_cb_data {
	char *topic;
	char *blob;
};

int
setup(void **state)
{
	static struct context ctxt;
	ctxt.hub = evp_hub_setup("EVP1");

	*state = &ctxt;
	return 0;
}

static void
message_cb(const char *topic, const void *msgPayload, size_t msgPayloadLen,
	   void *userData)
{
	check_expected(topic);
	check_expected(msgPayload);
	check_expected(msgPayloadLen);
	check_expected_ptr(userData);
	(*((int *)userData))++;
	if (g_verbose) {
		printf("messaging callback: (topic=%s, datalen=%d, "
		       "data=%.*s)\n",
		       topic, (int)msgPayloadLen, (int)msgPayloadLen,
		       (char *)msgPayload);
	}
}

static void
send_message_cb(EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userData)
{
	printf("%s: send_message_cb\n", module_name);
	struct send_message_cb_data *d = userData;
	assert_true(d != NULL);
	assert_true(d->topic != NULL);
	assert_true(d->blob != NULL);
	free(d->topic);
	free(d->blob);
	free(d);
}

void
test_messaging(void **state)
{
	/* XXX what to do with g_verbose? */

	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"version\": 1,"
		"      \"moduleId\": \"SPL-111\","
		"      \"entryPoint\": \"main\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"version\": 2,"
		"      \"moduleId\": \"PPL-222\","
		"      \"entryPoint\": \"main\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"SPL-111\": {"
		"      \"downloadUrl\": \"foo\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\","
		"      \"moduleImpl\": \"docker\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\","
		"      \"moduleImpl\": \"docker\""
		"    }"
		"  },"
		"  \"publishTopics\": {"
		"    \"local-topic-for-publish\": {"
		"      \"type\": \"local\","
		"      \"topic\": \"spl-to-ppl\""
		"    }"
		"  },"
		"  \"subscribeTopics\": {"
		"    \"local-topic-for-subscribe\": {"
		"      \"type\": \"local\","
		"      \"topic\": \"spl-to-ppl\""
		"    }"
		"  }"
		"}";

	struct Deployment *deploy;
	int ret;

	main_loop_init();

	path_init(getenv("EVP_DATA_DIR"));
	module_init(NULL);
	assert_int_equal(module_instance_init(), 0);
	sdk_init();

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	assert_int_equal(0, ret);

	ret = module_load(deploy->modules);
	assert_int_equal(0, ret);

	do {
		ret = module_instance_start(value, ctxt->hub,
					    deploy->instanceSpecs);
	} while (ret == EAGAIN || ret == EINTR);
	json_value_free(value);
	assert_true(ret == 0);

	sdk_set_publish_topics(deploy->publish_topics);
	sdk_set_subscribe_topics(deploy->subscribe_topics);

	struct EVP_client *h_spl =
		get_module_instance_by_name("SPL")->sdk_handle;
	struct EVP_client *h_ppl =
		get_module_instance_by_name("PPL")->sdk_handle;

	const char *topic = "to-ppl";
	const char *payload1 = "hello ppl!";
	size_t payloadlen1 = strlen(payload1);
	const char *payload2 = "hello ppl again!";
	size_t payloadlen2 = strlen(payload2);

	int count = 0;
	EVP_setMessageCallback(h_ppl, message_cb, &count);

	struct send_message_cb_data *d1 = malloc(sizeof(*d1));
	assert_true(d1 != NULL);
	d1->topic = strdup(topic);
	assert_true(d1->topic != NULL);
	d1->blob = strdup(payload1);
	assert_true(d1->blob != NULL);
	EVP_sendMessage(h_spl, d1->topic, d1->blob, payloadlen1,
			send_message_cb, d1);

	struct send_message_cb_data *d2 = malloc(sizeof(*d2));
	assert_true(d2 != NULL);
	d2->topic = strdup(topic);
	assert_true(d2->topic != NULL);
	d2->blob = strdup(payload2);
	assert_true(d2->blob != NULL);
	EVP_sendMessage(h_spl, d2->topic, d2->blob, payloadlen2,
			send_message_cb, d2);

	sdk_process_outbox_messages();

	/*
	 * Note: check_expected_xxx fails when it runs out expected values.
	 * That is, the test below fails if the third call of message_cb is
	 * made unexpectedly.
	 */

	expect_string(message_cb, topic, "from-spl");
	expect_value(message_cb, msgPayloadLen, payloadlen1);
	expect_memory(message_cb, msgPayload, payload1, payloadlen1);
	expect_value(message_cb, userData, &count);

	expect_string(message_cb, topic, "from-spl");
	expect_value(message_cb, msgPayloadLen, payloadlen2);
	expect_memory(message_cb, msgPayload, payload2, payloadlen2);
	expect_value(message_cb, userData, &count);

	EVP_processEvent(h_ppl, 1000);
	assert_true(count == 1);
	EVP_processEvent(h_ppl, 1000);
	assert_true(count == 2);
	EVP_processEvent(h_ppl, 1000);
	assert_true(count == 2);
	EVP_processEvent(h_ppl, 1000);
	assert_true(count == 2);

	// invoked manually because there is no agent running
	send_message_cb(EVP_MESSAGE_SENT_CALLBACK_REASON_SENT, d1);
	send_message_cb(EVP_MESSAGE_SENT_CALLBACK_REASON_SENT, d2);

	free_deployment(deploy);
	module_instance_deinit();
	module_deinit();
	path_free();
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_messaging),
	};
	return cmocka_run_group_tests(tests, setup, NULL);
}
