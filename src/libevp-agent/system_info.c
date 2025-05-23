/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/utsname.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <version.h>

#include "config.h"

#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
#include <wasm_export.h>
#endif

#include <parson.h>

#include <internal/util.h>

#include "system_info.h"

JSON_Value *
hub_evp1_get_system_info(void)
{
	struct utsname u;
	int ret;

	ret = uname(&u);
	if (ret != 0)
		return NULL;

	JSON_Value *v = json_value_init_object();
	if (v == NULL)
		return NULL;

	JSON_Object *o = json_value_get_object(v);
	JSON_Status j_ret = JSONSuccess;
	j_ret |= json_object_dotset_string(o, "utsname.sysname", u.sysname);
	j_ret |= json_object_dotset_string(o, "utsname.nodename", u.nodename);
	j_ret |= json_object_dotset_string(o, "utsname.release", u.release);
	j_ret |= json_object_dotset_string(o, "utsname.version", u.version);
	j_ret |= json_object_dotset_string(o, "utsname.machine", u.machine);
	j_ret |= json_object_set_string(o, "protocolVersion", "EVP1");

	if (j_ret != JSONSuccess) {
		json_value_free(v);
		v = NULL;
	}

	return v;
}

static int
add_runtime_information(JSON_Object *o)
{
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	char version[sizeof "v4294967295.4294967295.4294967295"];
	uint32_t major, minor, patch;

	wasm_runtime_get_version(&major, &minor, &patch);

	int n = snprintf(version, sizeof(version),
			 "v%" PRIu32 ".%" PRIu32 ".%" PRIu32, major, minor,
			 patch);

	if (n < 0 || (unsigned)n >= sizeof(version)) {
		return -1;
	}

	JSON_Status status =
		json_object_set_string(o, "wasmMicroRuntime", version);

	if (status != JSONSuccess) {
		return -1;
	}
#endif

	return 0;
}

static JSON_Value *
hub_evp2_get_system_info(void)
{
	struct utsname u;
	int ret;

	ret = uname(&u);
	if (ret != 0)
		return NULL;

	JSON_Value *v = json_value_init_object();
	if (v == NULL)
		return NULL;

	JSON_Object *o = json_value_get_object(v);
	JSON_Status jstatus = JSONSuccess;
	jstatus |= json_object_set_string(o, "os", u.sysname);
	jstatus |= json_object_set_string(o, "arch", u.machine);

	jstatus |= json_object_set_string(o, "evp_agent", "v" AGENT_VERSION);

	jstatus |= json_object_set_string(o, "evp_agent_commit_hash",
					  AGENT_COMMIT_HASH);

	if (add_runtime_information(o)) {
		jstatus = JSONFailure;
	}

	if (jstatus != JSONSuccess) {
		json_value_free(v);
		v = NULL;
	}

	return v;
}

JSON_Value *
hub_evp2_tb_get_system_info(void)
{
	JSON_Value *v = hub_evp2_get_system_info();
	if (v == NULL)
		return NULL;

	JSON_Object *o = json_value_get_object(v);
	JSON_Status jstatus;
	jstatus = json_object_set_string(o, "protocolVersion", "EVP2-TB");

	if (jstatus != JSONSuccess) {
		json_value_free(v);
		v = NULL;
	}

	return v;
}
