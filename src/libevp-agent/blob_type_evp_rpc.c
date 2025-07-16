/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "base64.h"
#include "blob.h"
#include "blob_type_evp.h"
#include "evp/agent.h"
#include "hub.h"
#include "mstp_schema.h"
#include "path.h"
#include "persist.h"
#include "req.h"
#include "sdk_agent.h"
#include "timeutil.h"
#include "xlog.h"

#define BLOB_EVP_RPC_TIMEOUT_MS 5000

struct evp_agent_context;

static void
notify_done(struct blob_work *wk, enum blob_work_result result, int error)
{
	/* Note: the wk has not been handed off to the blob worker yet */
	wk->result = result;
	wk->error = error;
	if (wk->wk.done != NULL) {
		wk->wk.done(&wk->wk);
	}
}

struct cstr_args {
	struct blob_work *wk;
	struct evp_agent_context *agent;
};

static bool
is_expired(const struct storagetoken_response *resp)
{
	return resp->expiration_ms < gettime_ms();
}

static JSON_Value *
load_cache(void)
{
	const char *path = path_get(CACHE_PATH_ID);

	if (path == NULL) {
		xlog_error("path_get failed");
		return NULL;
	}

	return json_parse_file(path);
}

static bool
cache_matches(const JSON_Object *o, const struct blob_work *wk)
{
	const char *instance_name = json_object_get_string(o, "instanceName"),
		   *storage_name = json_object_get_string(o, "storageName");

	if (instance_name == NULL) {
		xlog_error("missing field \"instanceName\"");
		return false;
	}

	if (storage_name == NULL) {
		xlog_error("missing field \"storageName\"");
		return false;
	}

	if (wk->module_instance_name == NULL || wk->storage_name == NULL ||
	    wk->remote_name == NULL) {
		xlog_warning("Incomplete worker key");
		return false;
	}

	return !strcmp(instance_name, wk->module_instance_name) &&
	       !strcmp(storage_name, wk->storage_name);
}

static int
process_entry(const struct evp_agent_context *agent, const JSON_Object *o,
	      const struct blob_work *wk, struct storagetoken_response *r)
{
	int error = agent->hub->storagetoken_response_parse(o, r);

	if (error != 0) {
		xlog_error("parse failed with %d", error);
		return -1;
	}

	if (r->resp_type != STORAGETOKEN_RESPONSE_TYPE_MULTI_FILE) {
		xlog_error("Token is not meant for multi-file");
		return -1;
	}

	if (is_expired(r)) {
		xlog_warning("token expired");
		return -1;
	}

	return 0;
}

int
blob_type_evp_load(const struct evp_agent_context *agent,
		   const struct blob_work *wk,
		   struct storagetoken_response *resp)
{
	if (transport_is_connected(agent->transport_ctxt)) {
		return 1;
	}

	int ret = -1;
	JSON_Value *v = load_cache();

	if (v == NULL) {
		xlog_error("load_cache failed");
		goto end;
	}

	JSON_Array *a = json_value_get_array(v);
	if (a == NULL) {
		xlog_error("json_value_get_array failed");
		goto end;
	}

	const JSON_Object *entry_obj = NULL;
	size_t i;
	for (i = 0; i < json_array_get_count(a); i++) {
		const JSON_Object *o = json_array_get_object(a, i);
		if (o == NULL) {
			xlog_error("json_array_get_object i=%zu failed", i);
			goto end;
		}

		if (cache_matches(o, wk)) {
			entry_obj = o;
			break;
		}
	}

	if (!entry_obj) {
		xlog_info("No cache hit for "
			  "instanceName=%s, remoteName=%s, storageName=%s",
			  wk->module_instance_name, wk->remote_name,
			  wk->storage_name);
		goto end;
	}

	struct storagetoken_response entry = {0};
	if (!process_entry(agent, entry_obj, wk, &entry)) {
		*resp = entry;
		ret = 0;
		goto end;
	}

	storagetoken_response_dtor(&entry);

	// Token entry is either expired or invalid. Remove it.
	if (json_array_remove(a, i) != JSONSuccess) {
		xlog_error("json_array_remove i=%zu failed", i);
		goto end;
	}

	const char *path = path_get(CACHE_PATH_ID);
	if (path == NULL) {
		xlog_error("path_get failed");
		goto end;
	}

	save_json(path, v);

end:
	json_value_free(v);
	return ret;
}

static int
remove_existing(const struct blob_work *wk, JSON_Array *a)
{
	for (size_t i = 0; i < json_array_get_count(a); i++) {
		const JSON_Object *o = json_array_get_object(a, i);

		if (o == NULL) {
			xlog_error("json_array_get_object i=%zu failed", i);
			return -1;
		}

		if (cache_matches(o, wk)) {
			if (json_array_remove(a, i) != JSONSuccess) {
				xlog_error("json_array_remove i=%zu failed",
					   i);
				return -1;
			}

			break;
		}
	}

	return 0;
}

static int
insert(const struct blob_work *wk, const JSON_Value *v, JSON_Array *a)
{
	JSON_Value *newv = json_value_deep_copy(v);

	if (newv == NULL) {
		xlog_error("json_value_deep_copy failed");
		goto failure;
	}

	JSON_Object *o = json_value_get_object(newv);

	if (o == NULL) {
		xlog_error("json_value_get_object failed");
		goto failure;
	}

	const struct entry {
		const char *key, *value;
	} entries[] = {
		{.key = "instanceName", wk->module_instance_name},
		{.key = "storageName", wk->storage_name},
	};

	for (size_t i = 0; i < __arraycount(entries); i++) {
		const struct entry *e = &entries[i];

		if (json_object_set_string(o, e->key, e->value) !=
		    JSONSuccess) {
			xlog_error("json_object_set_string %s failed", e->key);
			goto failure;
		}
	}

	if (json_array_append_value(a, newv)) {
		xlog_error("json_array_append_value failed");
		goto failure;
	}

	return 0;

failure:
	json_value_free(newv);
	return -1;
}

static JSON_Value *
update_cache(const struct blob_work *wk, const JSON_Value *v)
{
	JSON_Value *cache = load_cache();

	if (cache == NULL) {
		xlog_warning("load_cache failed: creating new DB");
		cache = json_value_init_array();
	}

	JSON_Array *a = json_value_get_array(cache);

	if (a == NULL) {
		xlog_error("json_value_get_array failed");
		goto failure;
	}

	if (remove_existing(wk, a)) {
		xlog_error("remove_existing failed");
		goto failure;
	}

	if (insert(wk, v, a)) {
		xlog_error("insert failed");
		goto failure;
	}

	return cache;

failure:
	json_value_free(cache);
	return NULL;
}

int
blob_type_evp_store(const struct blob_work *wk, const JSON_Value *v)
{
	int ret = -1;
	JSON_Value *updated = update_cache(wk, v);

	if (updated == NULL) {
		xlog_error("update_cache failed");
		goto end;
	}

	const char *path = path_get(CACHE_PATH_ID);

	if (path == NULL) {
		xlog_error("path_get failed");
		goto end;
	}

	save_json(path, updated);
	ret = 0;

end:
	json_value_free(updated);
	return ret;
}

static char
rfc3986_encode(char c)
{
	if (isalnum(c)) {
		return c;
	}

	if (strchr("~-._", c)) {
		return c;
	}

	return 0;
}

static char *
url_escape(const char *s)
{
	size_t enc_len = 1;
	char *enc = NULL;

	for (;; s++) {
		size_t pos = enc_len - 1;
		char e = rfc3986_encode(*s);
		enc_len += e ? 1 : 3;

		char *new_enc = realloc(enc, enc_len);
		if (!new_enc) {
			xlog_error("realloc failed with %d", errno);
			break;
		}
		enc = new_enc;

		if (*s == '\0') {
			enc[pos] = '\0';
			return enc;
		}

		if (e) {
			enc[pos] = e;
			continue;
		}

		int n = snprintf(&enc[pos], enc_len - pos, "%%%02X", *s);
		if (n < 0) {
			xlog_error("snprintf failed with %d", n);
			break;
		}
	}

	free(enc);
	return NULL;
}

int
craft_url_azure(struct blob_work *wk, const char *url)
{
	int ret = -1;
	char *params = strchr(url, '?');
	if (!params) {
		params = strchr(url, '#');
	}
	if (!params) {
		xlog_error("Malformed Azure SAS (does not contain params)");
		return -1;
	}

	// Verify minimum param position in URL
	if (params < (url + strlen("X://x?"))) {
		xlog_error("Malformed Azure SAS (wrong param ? position)");
		return -1;
	}

	// Look for '/' before '?' position
	char *c = params[-1] == '/' ? &params[-1] : &params[0];

	// Extract base URL without `/`
	size_t base_len = c - url;
	char *base = strndup(url, base_len);
	if (!base) {
		xlog_error("strndup failed with %d", errno);
		return -1;
	}

	// Encode remote name
	char *remote_name = url_escape(wk->remote_name);
	if (!remote_name) {
		xlog_error("url_escape failed with %d", errno);
		goto end;
	}

	// Reconstruct URL as `<SCHEMA>://<HOST_PATH>/<REMOTE_NAME>?<PARAMS>`
	free(wk->url_rw);
	wk->url_rw = NULL;
	ret = asprintf(&wk->url_rw, "%s/%s%s", base, remote_name, params);
	if (ret < 0) {
		xlog_error("asprintf failed with %d", ret);
		goto end;
	}

	ret = 0;

end:
	free(remote_name);
	free(base);

	return ret;
}

int
craft_url_default(struct blob_work *wk, const char *url)
{
	wk->url = strdup(url);
	if (!wk->url) {
		xlog_error("strdup failed with %d", errno);
		return -1;
	}
	return 0;
}

static void
apply_work(struct blob_work *wk, struct storagetoken_response *resp,
	   int (*crafter)(struct blob_work *, const char *))
{
	if (crafter(wk, resp->url)) {
		xlog_error("url crafting failed");
		notify_done(wk, BLOB_RESULT_ERROR, -1);
		return;
	}

	wk->headers_rw = calloc(resp->headers_len, sizeof(wk->headers[0]));
	if (!wk->headers) {
		xlog_error("calloc failed with %d", errno);
		notify_done(wk, BLOB_RESULT_ERROR, ENOMEM);
		return;
	}

	for (unsigned int i = 0; i < resp->headers_len; i++) {
		wk->headers_rw[i] = strdup(resp->headers[i]);
		if (!wk->headers[i]) {
			xlog_error("strdup failed with %d", errno);
			notify_done(wk, BLOB_RESULT_ERROR, ENOMEM);
			return;
		}
	}

	wk->nheaders = resp->headers_len;

#if defined(CONFIG_EVP_BLOB_GET_UPLOAD_URL)
	if ((wk->op) == BLOB_OP_GET_BLOB_URL) {
		xlog_debug("get_blob_url_done request for %s",
			   wk->remote_name);
		notify_done(wk, BLOB_RESULT_SUCCESS, 0);
		return;
	}
#endif

	blob_work_enqueue(wk); /* hand off to the blob worker */
}

static void
complete_storage_token_request(EVP_RPC_ID id, void *cb_data, void *payload,
			       uint32_t delay, int error)
{
	// TODO: Replace assert (programming error)
	assert(cb_data != NULL);
	struct cstr_args *args = cb_data;
	struct blob_work *wk = args->wk;
	struct evp_agent_context *agent = args->agent;
	JSON_Value *json = NULL;
	struct storagetoken_response resp = {0};
	struct evp_agent_notification_stp_error notification = {0};

	xlog_debug(
		"complete_storage_token_request called for %s, delay=%" PRIu32
		", error=%d",
		wk->remote_name, delay, error);

	if (error != 0) {
		/* Error completing the request means timeout */
		xlog_error("Timeout response: %d. Delay time is %" PRIu32,
			   error, delay);

		notification.error = error;

		goto end;
	}

	/* try to parse the response */
	json = json_parse_string(payload);
	if (json == NULL) {
		error = EINVAL;
		xlog_error("json_parse_string failed");
		goto end;
	}

	const JSON_Object *o = json_value_get_object(json);
	if (o == NULL) {
		error = EINVAL;
		xlog_error("json_value_get_object failed");
		goto end;
	}

	error = agent->hub->storagetoken_response_parse(o, &resp);
	if (error != 0) {
		xlog_error("Error parsing the response: %d. Delay time "
			   "is %" PRIu32,
			   error, delay);
		goto end;
	}

	/* If the response is valid, check the content */
	if (resp.status != 0) {
		error = resp.status;
		xlog_error("Error from hub: %d (%s). Delay time is %" PRIu32,
			   resp.status, resp.error, delay);

		notification.error = resp.status;
		notification.error_msg = resp.error;

		goto end;
	}

	int (*crafter)(struct blob_work *, const char *) = craft_url_default;
	if (resp.resp_type == STORAGETOKEN_RESPONSE_TYPE_MULTI_FILE) {
		blob_type_evp_store(wk, json);

		// TODO: handle different providers
		crafter = craft_url_azure;
	}

	apply_work(wk, &resp, crafter);

end:
	if (error) {
		notify_done(wk, BLOB_RESULT_ERROR, error);
	}

	if (notification.error != 0) {
		evp_agent_notification_publish(agent, "stp/error",
					       &notification);
	}

	storagetoken_response_dtor(&resp);
	json_value_free(json);
	free(args);
}

void
blob_type_evp_start_rpc(struct evp_agent_context *agent, struct blob_work *wk)
{
	// TODO: Replace assert (programming error)
	assert(wk->type == BLOB_TYPE_EVP_EXT);

	struct storagetoken_response entry = {0};
	if (blob_type_evp_load(agent, wk, &entry) == 0) {
		apply_work(wk, &entry, craft_url_azure);
		storagetoken_response_dtor(&entry);
		return;
	}

	xlog_debug("Sending storage token request for %s", wk->remote_name);

	struct cstr_args *args = xmalloc(sizeof(*args));

	*args = (struct cstr_args){.agent = agent, .wk = wk};

	struct request *req = request_alloc();
	struct storagetoken_data st_data = {.remote_name = wk->remote_name,
					    .instance_name =
						    wk->module_instance_name,
					    .storage_name = wk->storage_name,
					    .reqid = req->id};

	JSON_Value *v =
		agent->hub->storagetoken_request_payload_create(&st_data);

	req->callback = complete_storage_token_request;
	req->callback_data = args;
	req->timeout_ms = BLOB_EVP_RPC_TIMEOUT_MS;
	if (evp_send_storagetoken_request(agent, req, v)) {
		request_free(req);
		free(args);
		xlog_error("Could not send request");
		notify_done(wk, BLOB_RESULT_DENIED, -1);
	}
	json_value_free(v);
}
