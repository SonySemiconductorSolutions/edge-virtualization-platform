/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
};

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

int
teardown(void **state)
{
	module_instance_deinit();
	module_deinit();
	path_free();
	return 0;
}

void
test_manifest(void **state)
{
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
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
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

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);

	assert_true(ret == 0);
	struct InstanceSpecs *spec = deploy->instanceSpecs;
	assert_true(spec != NULL);
	assert_true(spec->n == 2);
	struct ModuleInstanceSpec *spl;
	struct ModuleInstanceSpec *ppl;
	/* the list of module instances has no particular order. */
	if (!strcmp(spec->instances[0].name, "SPL")) {
		spl = &spec->instances[0];
		ppl = &spec->instances[1];
	} else {
		spl = &spec->instances[1];
		ppl = &spec->instances[0];
	}
	assert_true(!strcmp(spl->name, "SPL"));
	assert_true(!strcmp(spl->moduleId, "SPL-111"));
	assert_true(!strcmp(spl->entryPoint, "main"));
	assert_true(spl->subscribe->n == 0);
	assert_true(spl->publish->n == 1);
	assert_true(!strcmp(spl->publish->aliases[0].alias, "to-ppl"));
	assert_true(!strcmp(spl->publish->aliases[0].topic,
			    "local-topic-for-publish"));
	assert_true(!strcmp(ppl->name, "PPL"));
	assert_true(!strcmp(ppl->moduleId, "PPL-222"));
	assert_true(!strcmp(ppl->entryPoint, "main"));
	assert_true(ppl->subscribe->n == 1);
	assert_true(!strcmp(ppl->subscribe->aliases[0].alias, "from-spl"));
	assert_true(!strcmp(ppl->subscribe->aliases[0].topic,
			    "local-topic-for-subscribe"));
	assert_true(ppl->publish->n == 0);
	struct ModuleList *modules = deploy->modules;
	struct Module *spl_module;
	struct Module *ppl_module;
	/* the list of modules has no particular order. */
	if (!strcmp(modules->modules[0].moduleId, "SPL-111")) {
		spl_module = &modules->modules[0];
		ppl_module = &modules->modules[1];
	} else {
		spl_module = &modules->modules[1];
		ppl_module = &modules->modules[0];
	}
	assert_true(!strcmp(spl_module->moduleId, "SPL-111"));
	assert_true(!strcmp(spl_module->downloadUrl, "foo"));
	assert_true(!strcmp(ppl_module->moduleId, "PPL-222"));
	assert_true(!strcmp(ppl_module->downloadUrl, "bar"));
	struct TopicList *publish_topics = deploy->publish_topics;
	assert_true(!strcmp(publish_topics->topics[0].name,
			    "local-topic-for-publish"));
	assert_true(!strcmp(publish_topics->topics[0].type, "local"));
	assert_true(!strcmp(publish_topics->topics[0].topic, "spl-to-ppl"));
	struct TopicList *subscribe_topics = deploy->subscribe_topics;
	assert_true(!strcmp(subscribe_topics->topics[0].name,
			    "local-topic-for-subscribe"));
	assert_true(!strcmp(subscribe_topics->topics[0].type, "local"));
	assert_true(!strcmp(subscribe_topics->topics[0].topic, "spl-to-ppl"));
	free_deployment(deploy);
}

void
test_manifest_rawContainer(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"version\": 1,"
		"      \"entryPoint\": \"main\","
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"rawContainerSpec\": {},"
		"      \"subscribe\": {},"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
		"    }"
		"  },"
		"  \"publishTopics\": {"
		"  },"
		"  \"subscribeTopics\": {"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	/* Happy path, not much can go wrong */
	JSON_Value *value = json_value_init_string(json_str);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == 0);
}

void
test_manifest_missing_instanceSpecs(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"modules\": {"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
		"    }"
		"  },"
		"  \"publishTopics\": {"
		"  },"
		"  \"subscribeTopics\": {"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_malformed_topic_list_topic(void **state)
{
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
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
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
		"      \"type\": \"local\""
		/* "topic" has been deliberately removed here. */
		"    }"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_malformed_topic_list_type(void **state)
{
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
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
		"    }"
		"  },"
		"  \"publishTopics\": {"
		"    \"local-topic-for-publish\": {"
		/* "type" has been deliberately removed here. */
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

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_missing_modules(void **state)
{
	struct context *ctxt = *state;
	const char *json_str = "{"
			       "  \"instanceSpecs\": {"
			       "    \"PPL\": {"
			       "      \"version\": 1,"
			       "      \"entryPoint\": \"main\","
			       "      \"moduleId\": \"PPL-222\","
			       "      \"restartPolicy\": \"Always\","
			       "      \"rawContainerSpec\": {},"
			       "      \"subscribe\": {},"
			       "      \"publish\": {}"
			       "    }"
			       "  },"
			       "  \"publishTopics\": {"
			       "  },"
			       "  \"subscribeTopics\": {"
			       "  }"
			       "}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_additional_properties(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		/* An extra field, not defined by the JSON schema, is added
		   here. */
		"  \"test\": {"
		"    \"key\": \"value\""
		"  },"
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
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
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

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_value_init_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == 0);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_manifest),
		cmocka_unit_test(test_manifest_rawContainer),
		cmocka_unit_test(test_manifest_missing_instanceSpecs),
		cmocka_unit_test(test_manifest_missing_modules),
		cmocka_unit_test(test_manifest_malformed_topic_list_topic),
		cmocka_unit_test(test_manifest_malformed_topic_list_type),
		cmocka_unit_test(test_manifest_additional_properties),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
