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
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "evp_hub.h"
#include "hub.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "path.h"
#include "sdk_agent.h"
#include "sdk_msg.h"

#if defined(RAW_CONTAINER_SPEC)
#include "container_spec.h"
#endif

struct context {
	const struct evp_hub_context *hub;
};

int convert_module_list_evp2(JSON_Object *obj, struct ModuleList **resultp);
int convert_module_evp2(JSON_Object *, struct Module *);

const struct module_impl_ops *
__wrap_module_impl_ops_get_by_name(const char *name)
{
	if (strcmp(name, "docker") == 0) {
		return (const struct module_impl_ops
				*)"docker"; /* a valid pointer */
	}
	return NULL;
}

void
test_convert_module_list(void **state)
{
	const char *modules_json_str =
		"{"
		"    \"SPL-111\": {"
		"      \"downloadUrl\": \"foo\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
		"      \"hash\": \"c3139b37db08d5890ecd8925774e738494eabbd0\""
		"    }"
		"}";
	JSON_Value *value;
	JSON_Object *obj;
	int ret;

	value = json_parse_string(modules_json_str);
	obj = json_value_get_object(value);

	struct Deployment *deploy;
	deploy = xcalloc(1, sizeof(*deploy));
	ret = convert_module_list_evp2(obj, &deploy->modules);
	assert_true(ret == 0);
	json_value_free(value);
	free_deployment(deploy);
}

/**
 * Test that an invalid deployment has to be detected
 */
void
test_manifest_invalid(void **state)
{
	struct context *ctxt = *state;
	struct Deployment *deploy;
	int ret;
	JSON_Value *value = json_value_init_string("1");
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	assert_true(ret == EINVAL);
}

void
test_manifest_rawContainer_valid(void **state)
{
	struct context *ctxt = *state;
	/* Good case, both fields present and public key set */
	const char *json_str_deploy_valid =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"rawContainerSpecSignature\": "
		"\"MDUCGDqhmqlIOlLcEKVBEl6UE4LHh3G+yt9uoQIZAI8r4epuF9SY2S/Mm"
		"HPr5pV1mVM9Ze3yww==\","
		"      \"rawContainerSpec\": "
		"\"eyJJbWFnZSI6Im15LnVybC5jb20vc29tZXRoaW5nIiwiSG9zdENvbmZpZ"
		"yI6eyJOZXR3b3JrTW9kZSI6ImRlZmF1bHQiLCJCaW5kcyI6W119LCJFbnRy"
		"eXBvaW50IjoibWFpbiJ9Cg==\","
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

	static char *pub_key_env =
		"EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY="
		"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEM0jdqRiOQtrcPuryo4II6qEB/"
		"Rp+px8bTVVeItbLV/wUb7bUHQ+oYOl8e/VTppv8";

	struct Deployment *deploy;
	int ret;

	putenv(pub_key_env);
	JSON_Value *value = json_parse_string(json_str_deploy_valid);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == 0);
}

void
test_manifest_rawContainer_error(void **state)
{
	struct context *ctxt = *state;
	/* Bad case, rawContainerSpecs is present but signature not */
	/* rawContainerSpec present but not rawContainerSpecSignature */
	const char *json_str_deploy_inv_no_sig =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"rawContainerSpec\": \"e30=\","
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

	struct Deployment *deploy;
	int ret;
	JSON_Value *value = json_parse_string(json_str_deploy_inv_no_sig);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == 0);
}

void
test_manifest(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	struct Deployment *deploy;
	int ret;

	JSON_Value *value = json_parse_string(json_str);
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
	assert_true(spl->subscribe->n == 0);
	assert_true(spl->publish->n == 1);
	assert_true(!strcmp(spl->publish->aliases[0].alias, "to-ppl"));
	assert_true(!strcmp(spl->publish->aliases[0].topic,
			    "local-topic-for-publish"));
	assert_true(!strcmp(ppl->name, "PPL"));
	assert_true(!strcmp(ppl->moduleId, "PPL-222"));
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
	assert_true(!strcmp(spl_module->entryPoint, "main"));
	assert_true(!strcmp(spl_module->moduleImpl, "docker"));
	assert_true(!strcmp(ppl_module->moduleId, "PPL-222"));
	assert_true(!strcmp(ppl_module->downloadUrl, "bar"));
	assert_true(!strcmp(ppl_module->entryPoint, "init"));
	assert_true(!strcmp(ppl_module->moduleImpl, "docker"));
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
test_manifest_entryPoint_missing(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"wasm\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_entryPoint_null(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"wasm\","
		"      \"entryPoint\": null,"
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

// En
void
test_manifest_entryPoint_empty(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"wasm\","
		"      \"entryPoint\": \"\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_missing_instanceSpecs(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"modules\": {"
		"    \"SPL-111\": {"
		"      \"downloadUrl\": \"foo\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
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
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_missin_module_info(void **state)
{
	/* This example is from a bug ticket see issue EVP-3553
	 * This is a regression test to ensure that no attempt is made to apply
	 * this manifest.
	 */
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"deploymentId\": \"1C169145-8EB1-45AE-8267-35427323515E\","
		"  \"instanceSpecs\": {"
		"    \"890f2984-5747-4580-80b7-70f2b59629ea\": {"
		"      \"moduleId\": \"8803d93e-08c3-4cc6-ac5d-8f138fa69145\","
		"      \"publish\": {},"
		"      \"subscribe\": {}"
		"    }"
		"  },"
		"  \"modules\": {"
		"    \"a979d641-30db-4fa1-91df-f8ab01b9b552\": {"
		"      \"downloadUrl\": "
		"\"file:///home/xavier/we/test_modules/evp-3528.wasm\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": "
		"\"a81f7b1a964a8b69f9be6d89b633730ba99693fa4f4376f0a12488673c0"
		"2b176\","
		"      \"moduleImpl\": \"wasm\""
		"    }"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_parse_string(json_str);
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
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
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
		/* "topic" is deliberately removed here. */
		"    }"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_parse_string(json_str);
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
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {"
		"        \"from-spl\": \"local-topic-for-subscribe\""
		"      },"
		"      \"publish\": {}"
		"    }"
		"  },"
		"  \"publishTopics\": {"
		"    \"local-topic-for-publish\": {"
		/* "type" is deliberately removed here. */
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_malformed_topic_list_topic_wrong_type(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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
		/* A wrong type (bool) has been deliberately inserted here. */
		"      \"topic\": true"
		"    }"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == EINVAL);
}

void
test_manifest_malformed_topic_list_type_wrong_type(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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
		/* A wrong type (bool) has been deliberately inserted here. */
		"      \"type\": true,"
		"      \"topic\": \"spl-to-ppl\""
		"    }"
		"  }"
		"}";

	struct Deployment *deploy = NULL;
	int ret;

	JSON_Value *value = json_parse_string(json_str);
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
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_true(ret == 0);
}

void
test_manifest_wrong_stream_type(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		/* A wrong stream type has been inserted here. */
		"          \"type\": \"this-shall-never-exist\","
		"          \"direction\": \"in\""
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_wrong_stream_direction(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		/* A wrong stream direction has been inserted here. */
		"          \"direction\": \"this-shall-never-exist\""
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_stream_posix_missing_parameters(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		"          \"direction\": \"out\","
		"          \"parameters\": {"
		"              \"hostname\": \"localhost\""
		/* Missing parameters type, domain and port. */
		"          }"
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_stream_posix_invalid_domain(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		"          \"direction\": \"out\","
		"          \"parameters\": {"
		"              \"hostname\": \"localhost\","
		"              \"port\": \"5555\","
		"              \"type\": \"tcp\","
		/* A wrong domain is given below. */
		"              \"domain\": \"IPv4typo\""
		"          }"
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_stream_posix_invalid_type(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		"          \"direction\": \"out\","
		"          \"parameters\": {"
		"              \"hostname\": \"localhost\","
		"              \"port\": \"5555\","
		"              \"domain\": \"IPv4\","
		/* A wrong type is given below. */
		"              \"type\": \"tcptypo\""
		"          }"
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_stream_posix_invalid_port(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		"          \"direction\": \"out\","
		"          \"parameters\": {"
		"              \"hostname\": \"localhost\","
		"              \"type\": \"tcp\","
		"              \"domain\": \"IPv4\","
		/* A wrong port is given below. */
		"              \"port\": \"5555a\""
		"          }"
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

void
test_manifest_stream_posix_toobig_port(void **state)
{
	struct context *ctxt = *state;
	const char *json_str =
		"{"
		"  \"instanceSpecs\": {"
		"    \"SPL\": {"
		"      \"moduleId\": \"SPL-111\","
		"      \"restartPolicy\": \"Always\","
		"      \"subscribe\": {},"
		"      \"publish\": {"
		"        \"to-ppl\": \"local-topic-for-publish\""
		"      },"
		"      \"streams\": {"
		"        \"test-stream\": {"
		"          \"type\": \"posix\","
		"          \"direction\": \"out\","
		"          \"parameters\": {"
		"              \"hostname\": \"localhost\","
		"              \"type\": \"tcp\","
		"              \"domain\": \"IPv4\","
		/* A port larger than 65535 is given below. */
		"              \"port\": \"123456789\""
		"          }"
		"        }"
		"      }"
		"    },"
		"    \"PPL\": {"
		"      \"moduleId\": \"PPL-222\","
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
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"main\","
		"      \"hash\": \"21211ef38543ba0b34e7424b41ee970c92aad8d8\""
		"    },"
		"    \"PPL-222\": {"
		"      \"downloadUrl\": \"bar\","
		"      \"moduleImpl\": \"docker\","
		"      \"entryPoint\": \"init\","
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

	JSON_Value *value = json_parse_string(json_str);
	assert_non_null(value);
	ret = ctxt->hub->parse_deployment(value, &deploy);
	json_value_free(value);
	free_deployment(deploy);
	assert_int_equal(ret, EINVAL);
}

int
setup(void **state)
{
	static struct context ctxt;
	ctxt.hub = evp_hub_setup("TB");

	*state = &ctxt;
	return 0;
}

int
teardown(void **state)
{
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_convert_module_list),
		cmocka_unit_test(test_manifest_invalid),
		cmocka_unit_test(test_manifest),
		cmocka_unit_test(test_manifest_rawContainer_valid),
		cmocka_unit_test(test_manifest_rawContainer_error),
		cmocka_unit_test(test_manifest_missing_instanceSpecs),
		cmocka_unit_test(test_manifest_missing_modules),
		cmocka_unit_test(test_manifest_missin_module_info),
		cmocka_unit_test(test_manifest_malformed_topic_list_topic),
		cmocka_unit_test(test_manifest_malformed_topic_list_type),
		cmocka_unit_test(
			test_manifest_malformed_topic_list_topic_wrong_type),
		cmocka_unit_test(
			test_manifest_malformed_topic_list_type_wrong_type),
		cmocka_unit_test(test_manifest_additional_properties),
		cmocka_unit_test(test_manifest_wrong_stream_type),
		cmocka_unit_test(test_manifest_wrong_stream_direction),
		cmocka_unit_test(test_manifest_stream_posix_invalid_domain),
		cmocka_unit_test(test_manifest_stream_posix_invalid_type),
		cmocka_unit_test(test_manifest_stream_posix_invalid_port),
		cmocka_unit_test(test_manifest_stream_posix_toobig_port),
		cmocka_unit_test(test_manifest_entryPoint_missing),
		cmocka_unit_test(test_manifest_entryPoint_null),
		cmocka_unit_test(test_manifest_entryPoint_empty),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
