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
#include <string.h>

#include <cmocka.h>

#include <internal/util.h>

#include "container_spec.h"
#include "path_docker.h"

static const char
	pubkey_key[] = "EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY",
	pubkey_value[] =
		"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEM0jdqRiOQtrcPuryo4II6qEB/"
		"Rp+px8bTVVeItbLV/wUb7bUHQ+oYOl8e/VTppv8";

void
test_container_bind_inject(void **state)
{
	static const char json[] = "{"
				   "	\"Image\": \"test-image:rev\","
				   "	\"HostConfig\": {"
				   "		\"NetworkMode\": \"default\","
				   "		\"Binds\": ["
				   "		]"
				   "	},"
				   "	\"Env\": ["
				   "		\"TEST_VAR=HELLO\""
				   "	]"
				   "}";

	JSON_Value *v = json_parse_string(json);
	assert_non_null(v);
	static const char instance_name[] =
		"c8fba53c-ffd9-439b-849d-000000000001",
			  dir[] = "test-dir";
	char *error = NULL;
	char *host_dir = NULL;
	char *exp = NULL;
	xasprintf(&host_dir, "%s/%s", dir, instance_name);
	int ret = container_spec_extra_assign_mounts(v, &error, instance_name,
						     host_dir);
	assert_int_equal(ret, 0);

	const JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);

	const JSON_Object *h = json_object_get_object(o, "HostConfig");
	assert_non_null(h);

	const JSON_Array *b = json_object_get_array(h, "Binds");
	assert_non_null(b);

	xasprintf(&exp, "%s:%s", host_dir, EVP_SHARED_DIR);
	assert_string_equal(json_array_get_string(b, 0), exp);

	free(host_dir);
	free(exp);
	free(error);
	json_value_free(v);
}

void
test_no_spec_passthrough(void **state)
{
	/* An instance spec that has no raw container spec */
	const char *instance_spec_json = "{"
					 "  \"moduleId\": \"dummy\","
					 "  \"restartPolicy\": \"Always\","
					 "  \"subscribe\": {},"
					 "  \"publish\": {}"
					 "}";

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	assert_true(ret == 0);
	assert_null(failureMessage);
	json_value_free(v);
}

void
test_spec_without_signature(void **state)
{
	/* rawContainerSpec present but not rawContainerSpecSignature */
	const char *instance_spec_json = "{"
					 "  \"moduleId\": \"dummy\","
					 "  \"restartPolicy\": \"Always\","
					 "  \"rawContainerSpec\": \"e30=\","
					 "  \"subscribe\": {},"
					 "  \"publish\": {}"
					 "}";

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	json_value_free(v);
	assert_true(ret == ECONTSPEC);
	assert_string_equal(failureMessage,
			    "No raw container spec signature provided for "
			    "module instance 'PPL'");
	free(failureMessage);
}

void
test_spec_invalid_signature(void **state)
{
	/* rawContainerSpec present but not rawContainerSpecSignature */
	const char *instance_spec_json =
		"{"
		"  \"moduleId\": \"dummy\","
		"  \"restartPolicy\": \"Always\","
		"  \"rawContainerSpec\": \"e30=\","
		"  \"rawContainerSpecSignature\": "
		"\"bDMzdCBoNHgwciAxcyB0cjBsbDFuZyB5NCE=\","
		"  \"subscribe\": {},"
		"  \"publish\": {}"
		"}";

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	assert_int_equal(setenv(pubkey_key, pubkey_value, 1), 0);
	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	json_value_free(v);
	assert_true(ret == ECONTSPEC);
	assert_string_equal(failureMessage,
			    "Signature verification of rawContainer spec for "
			    "module instance 'PPL' has failed");
	free(failureMessage);
}

void
test_no_spec_with_signature(void **state)
{
	/* rawContainerSpec present but not rawContainerSpecSignature */
	const char *instance_spec_json =
		"{"
		"  \"moduleId\": \"dummy\","
		"  \"restartPolicy\": \"Always\","
		"  \"rawContainerSpecSignature\": "
		"\"dGhlIHNpZ25hdHVyZSBnb2VzIGhlcmUhCg==\","
		"  \"subscribe\": {},"
		"  \"publish\": {}"
		"}";

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	json_value_free(v);
	assert_true(ret == ECONTSPEC);
	assert_string_equal(failureMessage,
			    "Signature provided but no actual container spec "
			    "for module instance 'PPL'");
	free(failureMessage);
}

void
test_no_public_key_set(void **state)
{
	/* valid raw container spec*/
	const char *instance_spec_json = *state;

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	assert_int_equal(unsetenv(pubkey_key), 0);
	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	json_value_free(v);
	assert_int_equal(ret, ECONTSPEC);
	assert_string_equal(failureMessage,
			    "Public key for verifying signature of module "
			    "instance 'PPL' is not provided");
	free(failureMessage);
}

void
test_valid(void **state)
{
	/* valid raw container spec*/
	char *instance_spec_json = *state;

	struct ModuleInstanceSpec spec = {
		.name = "PPL",
		.moduleId = "dummy",
	};

	char *failureMessage = NULL;
	int ret;

	JSON_Value *v = json_parse_string(instance_spec_json);
	JSON_Object *o = json_value_get_object(v);

	assert_int_equal(setenv(pubkey_key, pubkey_value, 1), 0);
	ret = container_spec_extra_parse_evp2(&spec, o, &failureMessage);
	assert_true(ret == 0);
	assert_null(failureMessage);

	JSON_Object *decoded = json_value_get_object(spec.rawContainerSpec);
	json_value_free(v);
	assert_non_null(decoded);
	assert_true(json_object_has_value_of_type(decoded, "HostConfig",
						  JSONObject));
	json_value_free(spec.rawContainerSpec);
}

static int
setup(void **state)
{
	/* Valid raw container spec, used on several tests */
	char *valid_instance_spec_json =
		"{"
		"  \"moduleId\": \"dummy\","
		"  \"restartPolicy\": \"Always\","
		"  \"rawContainerSpecSignature\": "
		"\"MDUCGDqhmqlIOlLcEKVBEl6UE4LHh3G+yt9uoQIZAI8r4epuF9SY2S/Mm"
		"HPr5pV1mVM9Ze3yww==\","
		"  \"rawContainerSpec\": "
		"\"eyJJbWFnZSI6Im15LnVybC5jb20vc29tZXRoaW5nIiwiSG9zdENvbmZpZ"
		"yI6eyJOZXR3b3JrTW9kZSI6ImRlZmF1bHQiLCJCaW5kcyI6W119LCJFbnRy"
		"eXBvaW50IjoibWFpbiJ9Cg==\","
		"  \"subscribe\": {},"
		"  \"publish\": {}"
		"}";

	*state = valid_instance_spec_json;
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_container_bind_inject),
		cmocka_unit_test(test_no_spec_passthrough),
		cmocka_unit_test(test_spec_without_signature),
		cmocka_unit_test(test_spec_invalid_signature),
		cmocka_unit_test(test_no_spec_with_signature),
		cmocka_unit_test(test_no_public_key_set),
		cmocka_unit_test(test_valid),
	};
	// run tests
	return cmocka_run_group_tests(tests, setup, NULL);
}
