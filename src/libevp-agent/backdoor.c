/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <parson.h>

#include "xlog.h"

bool
is_backdoor_prefixed(const char *entry_point)
{
	static const char *prefix = "backdoor-";
	return entry_point && !strncmp(prefix, entry_point, strlen(prefix));
}

static int
get_url(const JSON_Object *root, const char *moduleId, const char **out)
{
	const JSON_Object *modules = json_object_get_object(root, "modules");

	if (modules == NULL) {
		xlog_error("json_object_get_object modules failed");
		return -1;
	}

	const JSON_Object *m = json_object_get_object(modules, moduleId);

	if (m == NULL) {
		xlog_error("json_object_get_object moduleId failed");
		return -1;
	}

	const char *url = json_object_get_string(m, "downloadUrl");

	if (url == NULL) {
		xlog_error("json_object_get_string failed");
		return -1;
	}

	*out = url;
	return 0;
}

int
hub_evp2_check_backdoor(const JSON_Value *v, const char *instanceId, bool *out)
{
	/* Backdoor instances use this prefix before the dummy
	 * deployment is received. */
	if (is_backdoor_prefixed(instanceId)) {
		*out = true;
		return 0;
	}

	const JSON_Object *deployment = json_value_get_object(v);

	if (deployment == NULL) {
		xlog_error("json_value_get_object failed");
		return -1;
	}

	const JSON_Object *instances =
		json_object_get_object(deployment, "instanceSpecs");

	if (instances == NULL) {
		xlog_error("json_object_get_object instanceSpecs failed");
		return -1;
	}

	const JSON_Object *instance =
		json_object_get_object(instances, instanceId);

	if (instance == NULL) {
		/* This might be due to an empty deploymentManifest. */
		*out = false;
		return 0;
	}

	const char *moduleId = json_object_get_string(instance, "moduleId");

	if (moduleId == NULL) {
		xlog_error("json_object_get_string failed");
		return -1;
	}

	const char *url;

	if (get_url(deployment, moduleId, &url)) {
		xlog_error("get_url failed");
		return -1;
	}

	/* After dummy deployment. */
	*out = url == NULL ||
	       !strcmp(url, "")
	       /* Before dummy deployment. */
	       || !strcmp(url, "EVP-BACKDOOR");

	return 0;
}

int
hub_evp1_check_backdoor(const JSON_Value *v, const char *instanceId, bool *out)
{
	int ret = -1;
	JSON_Value *root = NULL;

	/* Backdoor instances use this prefix. */
	if (is_backdoor_prefixed(instanceId)) {
		*out = true;
		ret = 0;
		goto end;
	}

	const char *s = json_value_get_string(v);

	if (s == NULL) {
		xlog_error("json_value_get_string failed");
		goto end;
	}

	root = json_parse_string(s);

	if (root == NULL) {
		xlog_error("json_parse_string failed");
		goto end;
	}

	const JSON_Object *o = json_value_get_object(root);

	if (o == NULL) {
		xlog_error("json_value_get_object failed");
		goto end;
	}

	const JSON_Object *instances =
		json_object_get_object(o, "instanceSpecs");

	if (instances == NULL) {
		xlog_error("json_object_get_object instanceSpecs failed");
		goto end;
	}

	const JSON_Object *instance =
		json_object_get_object(instances, instanceId);

	if (instance == NULL) {
		/* This might be due to an empty deploymentManifest. */
		*out = false;
		ret = 0;
		goto end;
	}

	const char *moduleId = json_object_get_string(instance, "moduleId");

	if (moduleId == NULL) {
		*out = true;
		ret = 0;
		goto end;
	}

	const char *url;

	if (get_url(o, moduleId, &url)) {
		xlog_error("get_url failed");
		goto end;
	}

	*out = url == NULL || !*url || !strcmp(url, "EVP-BACKDOOR");
	ret = 0;

end:
	json_value_free(root);
	return ret;
}
