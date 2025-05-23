/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "backdoor.h"
#include "fsutil.h"
#include "global.h"
#include "hub.h"
#include "path.h"
#include "persist.h"
#include "xlog.h"

void
init_local_twins_db(void)
{
	const char *path = path_get(TWINS_PATH_ID);
	int ret = mkdir(path, 0700);
	if (ret != 0 && errno != EEXIST)
		/* Abort assessment:
		 * This is likely a FS error. The directory should be created
		 * or, if existing, the error should be ignored. This error
		 * could occur during agent startup and aborting should not be
		 * an issue.
		 */
		// TODO: Review exit (xerr) (config error)
		//       Prefer xlog_abort[if]
		xerr(1, "Failed to create TWINS_DIR %s", path);
}

void
deinit_local_twins_db(void)
{
	json_value_free(g_evp_global.desired);
	g_evp_global.desired = NULL;
	json_value_free(g_evp_global.current);
	g_evp_global.current = NULL;
}

static void
update_file(const char *filename, const void *buf, size_t sz)
{
	char *tmp_name;
	int fd;
	int ret;
	ssize_t ssz;

	ret = xasprintf(&tmp_name, "%s.tmp", filename);
	if (ret == -1) {
		// TODO: Review exit (xlog_abort)
		//       use asprintf and return
		xlog_abort("Failed to generate a temp file name for %s with "
			   "error %d",
			   filename, errno);
	}
	fd = open(tmp_name, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if (fd < 0) {
		// TODO: Review exit (xlog_abort)
		//       return
		xlog_abort("Failed to open a temp file for %s with error %d",
			   filename, errno);
	}
	ssz = write(fd, buf, sz);
	if (ssz < 0 || (size_t)ssz != sz) {
		// TODO: Review exit (xlog_abort)
		//       close and return
		xlog_abort("Failed to write a temp file for %s with ret %zd "
			   "error %d",
			   filename, ssz, errno);
	}
	ret = fsync(fd);
	if (ret != 0) {
		// TODO: Review exit (xlog_abort)
		//       may be ignored
		xlog_abort("Failed to fsync a temp file for %s with error %d",
			   filename, errno);
	}
	ret = close(fd);
	if (ret != 0) {
		// TODO: Review exit (xlog_abort)
		//       return
		xlog_abort("Failed to close a temp file for %s with error %d",
			   filename, errno);
	}
	ret = rename(tmp_name, filename);
	if (ret != 0) {
		// TODO: Review exit (xlog_abort)
		//       free and return
		xlog_abort("Failed to rename a temp file for %s with error %d",
			   filename, errno);
	}
	free(tmp_name);
	ret = sync_parent_dir(filename);
	if (ret != 0) {
		// TODO: Review exit (xlog_abort)
		//       ignore
		xlog_abort("Failed to sync the parent dir of %s with error %d",
			   filename, errno);
	}
}

void
save_json(const char *filename, const JSON_Value *v)
{
	char *str = json_serialize_to_string(v);
	update_file(filename, str, strlen(str));
	json_free_serialized_string(str);
	xlog_info("DB updated: %s", filename);
}

static JSON_Value *
trim_object(const struct evp_agent_context *agent, JSON_Value *orig_v,
	    bool (*cb)(const struct evp_agent_context *, const char *))
{
	JSON_Value *copy_v = json_value_init_object();
	JSON_Object *copy = json_value_get_object(copy_v);
	JSON_Object *orig = json_value_get_object(orig_v);
	if (copy == NULL || orig == NULL) {
		goto fail;
	}
	size_t sz = json_object_get_count(orig);
	size_t i;
	for (i = 0; i < sz; i++) {
		const char *k = json_object_get_name(orig, i);

		if (cb(agent, k)) {
			JSON_Value *v = json_object_get_value_at(orig, i);
			JSON_Value *c = json_value_deep_copy(v);
			if (c == NULL) {
				goto fail;
			}
			json_object_set_value(copy, k, c);
		} else {
			xlog_info("skipping %s", k);
		}
	}
	return copy_v;
fail:
	// Exit (xlog_abort): Out of memory
	xlog_abort("Failed to trim object");
}

/* This function returns true if the key should be kept.
 * It returns false if we want to filter-out the key
 */
static bool
desired_trim_cb(const struct evp_agent_context *agent, const char *k)
{
	const char *prefix = "configuration/";
	if (!strncmp(k, prefix, strlen(prefix))) {
		/* For SSS backdoor modules the configuration is not persist.
		 * Because this module needs fresh data.
		 */

		const char *start = k + strlen(prefix);
		const char *slash = strchr(start, '/');

		if (!slash)
			return true;

		const JSON_Object *o =
			json_value_get_object(g_evp_global.desired);

		if (o == NULL) {
			xlog_error("json_value_get_object failed");
			return false;
		}

		const JSON_Value *v = json_object_get_value(o, "deployment");

		if (v == NULL) {
			xlog_error("json_object_get_value failed");
			return false;
		}

		char *instance_id = strndup(start, slash - start);

		if (!instance_id) {
			xlog_error("strdup(3) failed with %d", errno);
			return false;
		}

		// if error, assume this is not backdoor
		bool is_backdoor = false;
		agent->hub->check_backdoor(v, instance_id, &is_backdoor);

		free(instance_id);
		return !is_backdoor;
	}
	if (!strcmp(k, "desiredDeviceConfig")) {
		return true;
	}
	if (!strcmp(k, "deployment")) {
		return true;
	}
	return false;
}

void
save_desired(const struct evp_agent_context *agent)
{
	const char *desired_path = path_get(DESIRED_TWINS_PATH_ID);
	JSON_Value *v = g_evp_global.desired;

	// TODO: Replace assert (programming error)
	assert(v != NULL);
	/*
	 * Trim unnecessary attibutes before saving to the DB.
	 *
	 */
	JSON_Value *trimmed = trim_object(agent, v, desired_trim_cb);
	save_json(desired_path, trimmed);
	json_value_free(trimmed);
}

static bool
current_trim_cb(const struct evp_agent_context *agent, const char *k)
{
	const char *prefix = "state/$agent/";

	if (!strncmp(k, prefix, strlen(prefix))) {
		return true;
	}
	return false;
}

void
save_current(const struct evp_agent_context *agent)
{
	const char *current_path = path_get(CURRENT_TWINS_PATH_ID);
	JSON_Value *v = g_evp_global.current;
	// TODO: Replace assert (programming error)
	assert(v != NULL);
	/*
	 * Trim unnecessary attibutes before saving to the DB.
	 * (eg. "deploymentStatus", "systemInfo")
	 */
	JSON_Value *trimmed = trim_object(agent, v, current_trim_cb);
	save_json(current_path, trimmed);
	json_value_free(trimmed);
}

static JSON_Value *
load_json(const char *filename)
{
	JSON_Value *v;
	char *json_str;
	size_t sz;

	json_str = read_file(filename, &sz, true);
	if (json_str == NULL) {
		if (errno != ENOENT) {
			// Exit (xlog_abort): config error
			xlog_abort("read_file on %s failed with error %d",
				   filename, errno);
		}
		xlog_info("DB not found: %s", filename);
		v = json_value_init_object();
	} else {
		v = json_parse_string(json_str);
		free(json_str);
		xlog_info("DB loaded: %s", filename);
	}
	if (v == NULL) {
		// TODO: Review exit (xlog_abort)
		//       remove DB and continue
		xlog_abort("Corrupted DB?");
	}
	return v;
}

void
load_desired(struct evp_agent_context *ctxt)
{
	const char *desired_path = path_get(DESIRED_TWINS_PATH_ID);
	// TODO: Replace assert (programming error)
	assert(g_evp_global.desired == NULL);
	JSON_Value *v;

	g_evp_global.desired = json_value_init_object();
	if (!g_evp_global.desired) {
		// Exit (xlog_abort): Out of memory
		xlog_abort("error initializing desired");
	}
	v = load_json(desired_path);
	dispatch_persist(v, ctxt);
	json_value_free(v);
}

void
load_current(struct evp_agent_context *agent)
{
	const char *current_path = path_get(CURRENT_TWINS_PATH_ID);
	// TODO: Replace assert (programming error)
	assert(g_evp_global.current == NULL);

	JSON_Value *v = load_json(current_path);

	if (v) {
		g_evp_global.current = trim_object(agent, v, current_trim_cb);
		json_value_free(v);
	}
}
