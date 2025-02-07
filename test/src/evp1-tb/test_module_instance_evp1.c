/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <cmocka.h>

#include <internal/util.h>

#include "evp_hub.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "path.h"
#include "sdk_agent.h"
#include "sdk_msg.h"

struct context {
	const struct evp_hub_context *hub;
	JSON_Value *deployment;
};

/*
 * json_str produced with evp-onwire-schema v1:
 * $ cat schema/deployment.example.json
 *   | sed 's/"/\\"/g' | awk '{ printf "\"%s\"\n", $0 }'
 */
const char *json_str =
	"{"
	/* "    \"deployment\": {" */
	/* "        \"deploymentId\":
	   \"1C169145-8EB1-45AE-8267-35427323515E\"," */
	"        \"instanceSpecs\": {"
	"            \"sender\": {"
	"                \"version\": 1,"
	"                \"moduleId\": \"messaging1\","
	"                \"entryPoint\": \"main\","
	"                \"publish\": {"
	"                    \"sender-topic\": \"salute-publication\""
	"                },"
	"                \"subscribe\": {}"
	"            },"
	"            \"receiver\": {"
	"                \"version\": 1,"
	"                \"moduleId\": \"messaging2\","
	"                \"entryPoint\": \"main\","
	"                \"publish\": {},"
	"                \"subscribe\": {"
	"                    \"receiver-topic\": \"salute-subscription\""
	"                }"
	"            }"
	"        },"
	"        \"modules\": {"
	"            \"messaging1\": {"
	"                \"downloadUrl\": "
	"\"registry.localhost/evp-module-messaging:latest\","
	"                \"hash\": "
	"\"0000000000000000000000000000000000000000\","
	"                \"moduleImpl\": \"docker\""
	"            },"
	"            \"messaging2\": {"
	"                \"downloadUrl\": "
	"\"registry.localhost/evp-module-messaging:latest\","
	"                \"hash\": "
	"\"0000000000000000000000000000000000000000\","
	"                \"moduleImpl\": \"docker\""
	"            }"
	"        },"
	"        \"publishTopics\": {"
	"            \"salute-publication\": {"
	"                \"type\": \"local\","
	"                \"topic\": \"salute\""
	"            }"
	"        },"
	"        \"subscribeTopics\": {"
	"            \"salute-subscription\": {"
	"                \"type\": \"local\","
	"                \"topic\": \"salute\""
	"            }"
	"        }"
	/* "    }" */
	"}";

struct Deployment *deploy;

int
setup(void **state)
{
	static struct context ctxt;
	ctxt.hub = evp_hub_setup("EVP1");

	*state = &ctxt;
	path_init(getenv("EVP_DATA_DIR"));
	module_init(NULL);
	assert_int_equal(module_instance_init(), 0);
	sdk_init();
	return 0;
}

void
test_parse_deployment(void **state)
{
	struct context *ctxt = *state;
	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	int ret = ctxt->hub->parse_deployment(value, &deploy);
	assert_int_equal(0, ret);
	assert_non_null(deploy);
	ctxt->deployment = value;
}

void
test_module_load(void **state)
{
	assert_non_null(deploy);
	int ret = module_load(deploy->modules);
	assert_int_equal(0, ret);
}

void
test_module_instance_start(void **state)
{
	const struct context *ctxt = *state;

	assert_non_null(deploy);
	int ret;
	do {
		ret = module_instance_start(ctxt->deployment, ctxt->hub,
					    deploy->instanceSpecs);
	} while (ret == EAGAIN || ret == EINTR);
	assert_true(ret == 0);
}

void
test_get_module_instance_by_name(void **state)
{
	struct module_instance *instance;
	instance = get_module_instance_by_name("sender");
	assert_non_null(instance);

	instance = get_module_instance_by_name("receiver");
	assert_non_null(instance);

	instance = get_module_instance_by_name("fake");
	assert_null(instance);
}

int
teardown(void **state)
{
	struct context *ctxt = *state;

	free_deployment(deploy);
	module_instance_deinit();
	module_deinit();
	path_free();
	json_value_free(ctxt->deployment);
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_parse_deployment),
		cmocka_unit_test(test_module_load),
		cmocka_unit_test(test_module_instance_start),
		cmocka_unit_test(test_get_module_instance_by_name)};
	// run tests
	return cmocka_run_group_tests(tests, setup, teardown);
}
