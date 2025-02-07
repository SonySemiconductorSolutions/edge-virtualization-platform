/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* asprintf */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blob_config.h"
#include "evp/sdk.h"
#include "log.h"
#include "parson.h"
#include "timer.h"

enum {
	TIMER_ID_TELEMETRY,
	TIMER_ID_UPLOAD_FILE,
	TIMER_ID_HEARTBEAT,

	NUM_TIMERS
};

struct test {
	struct EVP_client *h;
	TIMER_handle_t th;
	char *name;

	struct telemetry {
		size_t size;
		unsigned period;
	} telemetry;

	struct blob {
		size_t size;
		char *storage_name, *prefix, *remote_dir;
	} blob;
};

struct state {
	char *topic;
	void *state;
};

/* Minimum size required by set_date. */
#define DATELEN          sizeof("20241231000000")
#define MODULE_NAME_BASE "HUB-SCALABILITY-TEST"

static char *module_name = MODULE_NAME_BASE;

static char
get_rand_char(void)
{
	static const char charset[] =
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRST"
		"UVWXYZ0123456789";

	return charset[rand() % (sizeof(charset) - 1)];
}

static char *
alloc_rand_string(size_t n, bool quotes)
{
	/*
	 * The returned string has to be finished with '\0'
	 * and might start and end with ".
	 */
	size_t totalsz = quotes ? n + 2 + 1 : n + 1;
	char *ret = malloc(totalsz);

	if (ret == NULL) {
		log_module(module_name, "%s: malloc(3): %s\n", __func__,
			   strerror(errno));
		return NULL;
	}

	for (size_t start = quotes ? 1 : 0, end = quotes ? n + 1 : n,
		    i = start;
	     i < end; i++) {
		ret[i] = get_rand_char();
	}

	if (quotes) {
		ret[0] = '"';
		ret[n + 1] = '"';
	}

	ret[totalsz - 1] = '\0';
	return ret;
}

static void
rpc_response_cb(EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData)
{
	if (reason != EVP_RPC_RESPONSE_CALLBACK_REASON_SENT) {
		log_module(module_name,
			   "%s: RPC response not sent, reason %d\n", __func__,
			   reason);
	}

	free(userData);
}

static int
set_date(char *s, size_t n)
{
	time_t now = time(NULL);

	if (now == (time_t)-1) {
		log_module(module_name, "%s: time(3) failed: %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	struct tm *tm = localtime(&now);

	if (tm == NULL) {
		log_module(module_name, "%s: localtime(3): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	size_t res = strftime(s, n, "%Y%m%d%H%M%S", tm);

	if (!res) {
		log_module(module_name, "%s: strftime(3) failed\n", __func__);
		return -1;
	}

	return 0;
}

static char *
get_filename(const char *prefix)
{
	char *ret = NULL, *randstr = alloc_rand_string(16, false);

	if (randstr == NULL) {
		log_module(module_name, "%s: alloc_rand_string failed\n",
			   __func__);
		goto end;
	}

	char date[DATELEN];

	if (set_date(date, sizeof(date))) {
		log_module(module_name, "%s: set_date failed\n", __func__);
		goto end;
	}

	char *tmp;
	int n = asprintf(&tmp, "%s-%s-%s", prefix, date, randstr);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) filename failed\n",
			   __func__);
		goto end;
	}

	ret = tmp;

end:
	free(randstr);
	return ret;
}

static char *
get_url(const char *dir, const char *filename)
{
	char *ret;
	int n = asprintf(&ret, "%s%s", dir, filename);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) failed\n", __func__);
		return NULL;
	}

	return ret;
}

static char *
get_abspath(struct EVP_client *h, const char *filename)
{
	const char *workspace =
		EVP_getWorkspaceDirectory(h, EVP_WORKSPACE_TYPE_DEFAULT);

	if (workspace == NULL) {
		log_module(module_name,
			   "%s: EVP_getWorkspaceDirectory failed\n", __func__);
		return NULL;
	}

	char *ret;
	int n = asprintf(&ret, "%s/%s", workspace, filename);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) failed\n", __func__);
		return NULL;
	}

	return ret;
}

static int
write_file(const char *path, size_t sz)
{
	int ret = -1;
	FILE *f = fopen(path, "wb");

	if (f == NULL) {
		log_module(module_name, "%s: fopen(3) %s: %s\n", __func__,
			   path, strerror(errno));
		goto end;
	}

	for (size_t i = 0; i < sz; i++) {
		char b = get_rand_char();

		if (!fwrite(&b, sizeof(b), 1, f)) {
			fprintf(stderr,
				"%s: fwrite(3) failed, ferror=%d, feof=%d\n",
				__func__, ferror(f), feof(f));
			goto end;
		}
	}

	ret = 0;

end:
	if (f != NULL && fclose(f)) {
		log_module(module_name, "%s: fclose(3): %s\n", __func__,
			   strerror(errno));
		ret = -1;
	}

	return ret;
}

struct upload {
	char *url, *abspath;
};

static void
free_upload(struct upload *u)
{
	free(u->abspath);
	free(u->url);
	free(u);
}

static void
blob_cb(EVP_BLOB_CALLBACK_REASON reason, const void *vp, void *userData)
{
	struct upload *u = userData;

	if (reason != EVP_BLOB_CALLBACK_REASON_DONE) {
		log_module(module_name, "%s: blob not done, reason %d\n",
			   __func__, reason);
	}

	free_upload(u);
}

static int
upload(struct EVP_client *h, const char *storage_name, struct upload *u)
{
	struct EVP_BlobLocalStore ls = {.filename = u->abspath};
	struct EVP_BlobRequestEvpExt req = {.remote_name = u->url,
					    .storage_name = storage_name};

	EVP_RESULT result =
		EVP_blobOperation(h, EVP_BLOB_TYPE_EVP_EXT, EVP_BLOB_OP_PUT,
				  &req, &ls, blob_cb, u);

	if (result != EVP_OK) {
		log_module(module_name,
			   "%s: EVP_blobOperation failed with %d\n", __func__,
			   result);
		return -1;
	}

	return 0;
}

static void
timer_upload_file_cb(void *userData)
{
	int result = -1;
	const struct test *t = userData;
	const struct blob *b = &t->blob;
	struct EVP_client *h = t->h;
	struct upload *u = NULL;
	char *url = NULL, *abspath = NULL, *filename = get_filename(b->prefix);

	if (filename == NULL) {
		log_module(module_name, "%s: get_filename failed\n", __func__);
		goto end;
	}

	url = get_url(b->remote_dir, filename);

	if (url == NULL) {
		log_module(module_name, "%s: get_url failed\n", __func__);
		goto end;
	}

	abspath = get_abspath(h, filename);

	if (abspath == NULL) {
		log_module(module_name, "%s: get_abspath failed\n", __func__);
		goto end;
	}

	if (write_file(abspath, b->size)) {
		log_module(module_name, "%s: write_file failed\n", __func__);
		goto end;
	}

	u = malloc(sizeof(*u));

	if (u == NULL) {
		log_module(module_name, "%s: malloc(3): %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	*u = (struct upload){.abspath = abspath, .url = url};

	if (upload(h, b->storage_name, u)) {
		log_module(module_name, "%s: upload failed\n", __func__);
		goto end;
	}

	result = 0;

end:

	if (result) {
		free(u);
		free(abspath);
		free(url);
	}

	free(filename);
}

struct method_in {
	struct test *t;
	const char *method, *params;
};

struct method_out {
	char *response;
	EVP_RPC_RESPONSE_STATUS status;
};

static int
do_dummy(const struct method_in *in, struct method_out *out)
{
	char *response = strdup("\"\"");

	if (response == NULL) {
		log_module(module_name, "%s: strdup(3): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	*out = (struct method_out){.status = EVP_RPC_RESPONSE_STATUS_OK,
				   .response = response};

	return 0;
}

static void
cleanup_state(EVP_STATE_CALLBACK_REASON reason, void *userData)
{
	struct state *s = userData;

	if (reason != EVP_STATE_CALLBACK_REASON_SENT) {
		log_module(module_name, "%s: state not sent, reason %d\n",
			   __func__, reason);
	}

	free(s->topic);
	free(s->state);
	free(s);
}

static int
do_echo(const struct method_in *in, struct method_out *out)
{
	int ret = -1;
	const char *params = in->params;
	JSON_Value *v = json_parse_string(params);

	if (v == NULL) {
		log_module(module_name, "%s: json_parse_string failed\n",
			   __func__);
		goto end;
	}

	char *paramsdup = strdup(params);

	if (paramsdup == NULL) {
		log_module(module_name, "%s: strdup(3): %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	*out = (struct method_out){.status = EVP_RPC_RESPONSE_STATUS_OK,
				   .response = paramsdup};
	ret = 0;

end:
	json_value_free(v);
	return ret;
}

struct upload_cfg {
	const char *prefix;
	size_t size;
	unsigned period;
};

static int
check_upload_cfg(const JSON_Value *v, struct upload_cfg *out)
{
	const JSON_Object *o = json_value_get_object(v);

	if (o == NULL) {
		log_module(module_name, "%s: json_value_get_object failed\n",
			   __func__);
		return -1;
	}

	const char *prefix = json_object_get_string(o, "namePrefix");

	if (prefix == NULL) {
		log_module(module_name, "%s: missing prefix\n", __func__);
		return -1;
	}

	/* json_object_get_number fails with 0.0, but we are not interested
	 * on double-precision floating point numbers here. So, the explicit
	 * cast to an integer type would allow us to easily check for errors.
	 */
	intmax_t size = json_object_get_number(o, "size"),
		 period = json_object_get_number(o, "period");

	if (size == 0) {
		log_module(module_name, "%s: missing size\n", __func__);
		return -1;
	}

	if (size < 0) {
		log_module(module_name, "%s: invalid negative size\n",
			   __func__);
		return -1;
	}

	if ((uintmax_t)size > SIZE_MAX) {
		log_module(module_name, "%s: invalid size %ju\n", __func__,
			   (uintmax_t)size);
		return -1;
	}

	if (period == 0) {
		log_module(module_name, "%s: missing period\n", __func__);
		return -1;
	}

	if (period < 0) {
		log_module(module_name, "%s: invalid negative period\n",
			   __func__);
		return -1;
	}

	if ((uintmax_t)period > UINT_MAX) {
		log_module(module_name, "%s: invalid period %ju\n", __func__,
			   (uintmax_t)period);
		return -1;
	}

	*out = (struct upload_cfg){
		.prefix = prefix, .size = size, .period = period};

	return 0;
}

static int
do_upload_start(const struct method_in *in, struct method_out *out)
{
	int ret = -1;
	char *response = NULL, *prefix = NULL, *remote_dir = NULL,
	     *dirsuffix = NULL;
	struct test *t = in->t;
	struct blob *b = &t->blob;
	JSON_Value *v = json_parse_string(in->params);
	static const char dir[] = "scalability-test";

	if (v == NULL) {
		log_module(module_name, "%s: json_parse_string failed\n",
			   __func__);
		goto end;
	}

	struct upload_cfg u;

	if (check_upload_cfg(v, &u)) {
		log_module(module_name, "%s: check_upload failed\n", __func__);
		goto end;
	}

	dirsuffix = alloc_rand_string(16, false);

	if (dirsuffix == NULL) {
		log_module(module_name, "%s: alloc_rand_string failed\n",
			   __func__);
		goto end;
	}

	char *tmp;
	int n = asprintf(&tmp, "%s/%s", dir, dirsuffix);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) 1 failed\n",
			   __func__);
		goto end;
	}

	remote_dir = tmp;
	n = asprintf(&tmp, "\"%s\"", remote_dir);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) 2 failed\n",
			   __func__);
		goto end;
	}

	response = tmp;
	prefix = strdup(u.prefix);

	if (prefix == NULL) {
		log_module(module_name, "%s: strdup(3) prefix: %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	free(b->prefix);
	free(b->remote_dir);
	b->prefix = prefix;
	b->remote_dir = remote_dir;
	b->size = u.size;
	TIMER_start_timer(t->th, TIMER_ID_UPLOAD_FILE, u.period,
			  timer_upload_file_cb, t);
	*out = (struct method_out){.response = response,
				   .status = EVP_RPC_RESPONSE_STATUS_OK};
	ret = 0;

end:

	if (ret) {
		free(prefix);
		free(response);
		free(remote_dir);
	}

	free(dirsuffix);
	json_value_free(v);
	return ret;
}

static int
do_upload_stop(const struct method_in *in, struct method_out *out)
{
	char *response = strdup("\"ok\"");

	if (response == NULL) {
		log_module(module_name, "%s: strdup(3): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	TIMER_stop_timer(in->t->th, TIMER_ID_UPLOAD_FILE);
	*out = (struct method_out){.response = response,
				   .status = EVP_RPC_RESPONSE_STATUS_OK};
	return 0;
}

static int
run_method(const struct method_in *in, struct method_out *out)
{
	static const struct method {
		const char *method;
		int (*f)(const struct method_in *, struct method_out *);
	} methods[] = {
		{.method = "dummy", .f = do_dummy},
		{.method = "echo", .f = do_echo},
		{.method = "upload_start", .f = do_upload_start},
		{.method = "upload_stop", .f = do_upload_stop},
	};

	for (size_t i = 0; i < sizeof(methods) / sizeof(*methods); i++) {
		const struct method *m = &methods[i];

		if (!strcmp(in->method, m->method)) {
			if (m->f(in, out)) {
				fprintf(stderr,
					"%s: callback for method %s failed\n",
					__func__, in->method);
				return -1;
			}

			return 0;
		}
	}

	log_module(module_name, "%s: method %s not found\n", __func__,
		   in->method);
	*out = (struct method_out){
		.status = EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND};
	return 0;
}

static void
rpc_cb(EVP_RPC_ID id, const char *method, const char *params, void *userData)
{
	EVP_RESULT result;
	struct test *t = userData;
	struct method_in in = {.t = t, .method = method, .params = params};
	struct method_out out = {0};

	if (run_method(&in, &out)) {
		log_module(module_name, "%s: run_method failed\n", __func__);
		goto failure;
	}

	result = EVP_sendRpcResponse(t->h, id, out.response, out.status,
				     rpc_response_cb, out.response);

	if (result != EVP_OK) {
		log_module(module_name,
			   "%s: EVP_sendRpcResponse 1 failed with %d\n",
			   __func__, result);
		goto failure;
	}

	return;

failure:
	result = EVP_sendRpcResponse(t->h, id, "\"\"",
				     EVP_RPC_RESPONSE_STATUS_ERROR,
				     rpc_response_cb, NULL);

	if (result != EVP_OK) {
		log_module(module_name,
			   "%s: EVP_sendRpcResponse 2 failed with %d\n",
			   __func__, result);
	}

	free(out.response);
}

struct telemetry_cb {
	struct EVP_telemetry_entry entry;
	char *value;
};

static void
telemetry_cb(EVP_TELEMETRY_CALLBACK_REASON reason, void *userData)
{
	struct telemetry_cb *cb = userData;

	if (reason != EVP_TELEMETRY_CALLBACK_REASON_SENT) {
		log_module(module_name, "%s: telemetry not sent, reason %d\n",
			   __func__, reason);
	}

	free(cb->value);
}

static void
timer_telemetry_cb(void *userData)
{
	const struct test *t = userData;
	const struct telemetry *tm = &t->telemetry;
	struct telemetry_cb *cb = NULL;
	char *value = alloc_rand_string(tm->size, true);

	if (value == NULL) {
		log_module(module_name, "%s: alloc_rand_string failed\n",
			   __func__);
		goto failure;
	}

	cb = malloc(sizeof(*cb));

	if (cb == NULL) {
		log_module(module_name, "%s: malloc(3): %s\n", __func__,
			   strerror(errno));
		goto failure;
	}

	*cb = (struct telemetry_cb){
		.entry = {.key = "reports", .value = value}, .value = value};

	EVP_RESULT result =
		EVP_sendTelemetry(t->h, &cb->entry, 1, telemetry_cb, cb);

	if (result != EVP_OK) {
		log_module(module_name,
			   "%s: EVP_sendTelemetry failed with %d\n", __func__,
			   result);
		goto failure;
	}

	return;

failure:
	free(cb);
	free(value);
}

static int
get_ulong_from_blob(const void *blob, size_t len, unsigned long *out)
{
	int ret = -1;
	/* Unfortunately, we need a null-terminated string. */
	char *s = strndup(blob, len);

	if (s == NULL) {
		log_module(module_name, "%s: strndup(3): %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	errno = 0;

	char *end;
	unsigned long value = strtoul(s, &end, 10);

	if (errno) {
		log_module(module_name, "%s: strtoul(3) %s: %s\n", __func__, s,
			   strerror(errno));
		goto end;
	}

	if (*end) {
		log_module(module_name, "%s: invalid number %s\n", __func__,
			   s);
		goto end;
	}

	*out = value;
	ret = 0;

end:
	free(s);
	return ret;
}

static void
telemetry_treat_config_change(struct test *t)
{
	const struct telemetry *tm = &t->telemetry;

	if (tm->period && tm->size) {
		TIMER_start_timer(t->th, TIMER_ID_TELEMETRY, tm->period,
				  timer_telemetry_cb, t);
	}
}

static int
report_period(const char *topic, const void *config, size_t configlen,
	      struct test *t)
{
	unsigned long period;

	if (get_ulong_from_blob(config, configlen, &period)) {
		log_module(module_name, "%s: get_ulong_from_blob failed\n",
			   __func__);
		return -1;
	}

	if (period > UINT_MAX) {
		log_module(module_name, "%s: invalid period %lu\n", __func__,
			   period);
		return -1;
	}

	t->telemetry.period = period;
	telemetry_treat_config_change(t);
	return 0;
}

static int
report_size(const char *topic, const void *config, size_t configlen,
	    struct test *t)
{
	unsigned long size;

	if (get_ulong_from_blob(config, configlen, &size)) {
		log_module(module_name, "%s: get_ulong_from_blob failed\n",
			   __func__);
		return -1;
	}

	if (size > SIZE_MAX) {
		log_module(module_name, "%s: invalid size %lu\n", __func__,
			   size);
		return -1;
	}

	t->telemetry.size = size;
	telemetry_treat_config_change(t);
	return 0;
}

static int
get_storage(const char *topic, const void *config, size_t configlen,
	    struct test *t)
{
	char *storage_name = strndup(config, configlen);

	if (storage_name == NULL) {
		log_module(module_name, "%s: strndup(3): %s\n", __func__,
			   strerror(errno));
		return -1;
	}

	struct blob *b = &t->blob;

	free(b->storage_name);
	b->storage_name = storage_name;
	return 0;
}

static int
refresh(const char *topic, const void *config, size_t configlen,
	struct test *t)
{
	int ret = -1;
	struct state *s = NULL;
	void *state = NULL;
	char *topicdup = strdup(topic);

	if (topicdup == NULL) {
		log_module(module_name, "%s: strdup(3): %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	state = malloc(configlen);

	if (state == NULL) {
		log_module(module_name, "%s: malloc(3) state: %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	memcpy(state, config, configlen);
	s = malloc(sizeof(*s));

	if (s == NULL) {
		log_module(module_name, "%s: malloc(3) s: %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	*s = (struct state){.state = state, .topic = topicdup};

	EVP_RESULT result = EVP_sendState(t->h, s->topic, s->state, configlen,
					  cleanup_state, s);

	if (result != EVP_OK) {
		log_module(module_name, "%s: EVP_sendState failed with %d\n",
			   __func__, result);
		goto end;
	}

	ret = 0;

end:

	if (ret != 0) {
		free(state);
		free(topicdup);
		free(s);
	}

	return ret;
}

static void
config_cb(const char *topic, const void *config, size_t configlen,
	  void *userData)
{
	static const struct config {
		const char *topic;
		int (*f)(const char *, const void *, size_t, struct test *);
	} configs[] = {{.topic = "reports_period", .f = report_period},
		       {.topic = "reports_size", .f = report_size},
		       {.topic = TOPIC_STORAGE_NAME_DEF, .f = get_storage},
		       {.topic = "refresh", .f = refresh}};

	for (size_t i = 0; i < sizeof(configs) / sizeof(*configs); i++) {
		const struct config *c = &configs[i];

		if (!strcmp(topic, c->topic)) {
			if (c->f(topic, config, configlen, userData)) {
				fprintf(stderr,
					"%s: callback for topic %s failed\n",
					__func__, topic);
			}

			return;
		}
	}

	log_module(module_name, "%s: ignoring unknown topic %s\n", __func__,
		   topic);
}

static char *
get_module_name(const char *prefix)
{
	char *ret = NULL, *rand_str = alloc_rand_string(5, false);

	if (rand_str == NULL) {
		log_module(module_name, "%s: alloc_rand_string failed\n",
			   __func__);
		goto end;
	}

	char *name;
	int n = asprintf(&name, "%s%s", prefix, rand_str);

	if (n < 0) {
		log_module(module_name, "%s: asprintf(3) failed\n", __func__);
		goto end;
	}

	ret = name;

end:
	free(rand_str);
	return ret;
}

static void
heartbeat(void *userData)
{
	FILE *stream = userData;

	/* E2E tests rely on *any* information to be written to the stream. */
	fprintf(stream, "%s\n", __func__);

again:

	if (fflush(stream)) {
		switch (errno) {
		case EAGAIN:
			goto again;

		default:
			log_module(module_name, "%s: fflush(3): %s\n",
				   __func__, strerror(errno));
		}
	}
}

static int
init(struct test *out, FILE *stream)
{
	int ret = -1;
	module_name = get_module_name("HUB_SCALABILITY_TEST");

	if (module_name == NULL) {
		log_module(module_name, "%s: get_module_name failed\n",
			   __func__);
		goto end;
	}

	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts)) {
		log_module(module_name, "%s: clock_gettime(3): %s\n", __func__,
			   strerror(errno));
		goto end;
	}

	srand(ts.tv_nsec);

	struct EVP_client *h = EVP_initialize();

	if (h == NULL) {
		log_module(module_name, "%s: EVP_initialize failed\n",
			   __func__);
		goto end;
	}

	enum { TIMEOUT = 1000 };
	TIMER_handle_t th =
		TIMER_init_timers(module_name, NUM_TIMERS, TIMEOUT);

	if (th == NULL) {
		log_module(module_name, "%s: TIMER_init_timers failed\n",
			   __func__);
		goto end;
	}

	EVP_RESULT result = EVP_setRpcCallback(h, rpc_cb, out);

	if (result != EVP_OK) {
		log_module(module_name,
			   "%s: EVP_setRpcCallback failed with %d\n", __func__,
			   result);
		goto end;
	}

	result = EVP_setConfigurationCallback(h, config_cb, out);

	if (result != EVP_OK) {
		fprintf(stderr,
			"%s: EVP_setConfigurationCallback failed with %d\n",
			__func__, result);
		goto end;
	}

	enum { PERIOD = 1000 };

	TIMER_start_timer(th, TIMER_ID_HEARTBEAT, PERIOD, heartbeat, stream);
	*out = (struct test){.h = h, .th = th, .name = module_name};
	ret = 0;

end:
	if (ret != 0) {
		free(module_name);
		module_name = MODULE_NAME_BASE;
	}

	return ret;
}

static void
free_test(struct test *t)
{
	free(t->name);
	free(t->blob.prefix);
	free(t->blob.storage_name);
	free(t->blob.remote_dir);
}

int
hub_scalability_test(FILE *stream)
{
	int ret = EXIT_FAILURE;
	struct test t = {0};

	if (init(&t, stream)) {
		log_module(module_name, "%s: init failed\n", __func__);
		goto end;
	}

	for (;;) {
		int timeout = TIMER_get_max_sleep_time(t.th);
		EVP_RESULT result = EVP_processEvent(t.h, timeout);

		switch (result) {
		case EVP_SHOULDEXIT:
			ret = EXIT_SUCCESS;
			goto end;

		case EVP_TIMEDOUT:
		case EVP_OK:
			TIMER_execute_expired_timers(t.th);
			break;

		default:
			fprintf(stderr,
				"%s: EVP_processEvent failed with %d\n",
				__func__, result);
			goto end;
		}
	}

	ret = EXIT_SUCCESS;

end:
	free_test(&t);
	return ret;
}
