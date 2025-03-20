/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE /* for pthread_setname_np */

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_test.h"
#include "hub.h"
#include "path.h"
#include "timeutil.h"
#include "xlog.h"
#include "xpthread.h"

#define AGENT_TEST_MAX_PAYLOAD_ID 15

#define JSONSTACKSZ 16

struct jverifier {
	int nvals, nobjs;
	JSON_Value *values[JSONSTACKSZ];
	JSON_Object *objects[JSONSTACKSZ];
};

static struct {
	pthread_t thread_id;
	int running;
	bool connected;
	bool offline_hub;
	int pipe[2];
	struct evp_lock lock;
	evp_agent_loop_fn_t agent_loop_fn;
	const char
		*payloads[EVP_HUB_TYPE_UNKNOWN][AGENT_TEST_MAX_PAYLOAD_ID + 1];
} g_agent_test = {.lock = EVP_LOCK_INITIALIZER, .pipe = {-1, -1}};

void
message_log(enum message_log_level level, const char *func, const char *file,
	    int line, const char *fmt, ...)
{
	static const char *levels[] = {
		"INFO",
		"ERROR",
	};

	assert_true(level <= MESSAGE_LOG_ERROR);

	fprintf(stderr, "[%8s  ] ", levels[level]);
	if (level != MESSAGE_LOG_INFO) {
		fprintf(stderr, "in %s (%s:%d): ", func, file, line);
	}

	va_list va;
	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);

	fprintf(stderr, "\n");
}

int
vpopenf(popen_parser_t cb, void *user, const char *fmt, va_list va)
{
	char *cmd;
	int rv = vasprintf(&cmd, fmt, va);
	if (rv < 0) {
		return rv;
	}

	message_info("cmd: %s\n", cmd);

	int ret = 0;
	FILE *fp;
	if ((fp = popen(cmd, "r")) == NULL) {
		rv = -1;
		goto err;
	}

	if (cb) {
		ret = cb(fp, user);
	}
	rv = pclose(fp);
	if (rv) {
		message_error("cmd '%s' returned %d\n", cmd, rv);
		ret = rv;
	}
err:
	free(cmd);
	return ret;
}

int
popenf(popen_parser_t cb, void *user, const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	int rv = vpopenf(cb, user, fmt, va);
	va_end(va);
	return rv;
}

int
popen_parse_int(FILE *fp, void *user)
{
	int *value = user;
	if (fscanf(fp, "%d", value) < 0) {
		return -1;
	}
	return 0;
}

int
popen_strcpy(FILE *fp, void *user)
{
	char *str = NULL;
	size_t len = 0;
	size_t n;

	do {
		size_t next_len = len + BUFSIZ;
		str = xrealloc(str, next_len);
		n = fread(&str[len], 1, BUFSIZ, fp);
		len += n;
		if (n != BUFSIZ) {
			int err = ferror(fp);
			if (err) {
				xlog_error("fread error: %d", err);
				return err;
			}
			// If no error, then assert EOF.
			assert_int_not_equal(feof(fp), 0);
			break;
		}
	} while (true);
	while (len > 0 && str[len - 1] == '\n') {
		len--;
	}
	str[len] = '\0';

	char **pstr = user;
	*pstr = str;
	return 0;
}

int
popen_print(FILE *fp, void *user)
{
	size_t n;
	size_t n_write;

	do {
		char str[BUFSIZ];
		n = fread(str, 1, BUFSIZ, fp);
		n_write = write(1, str, n);
		assert_int_equal(n, n_write);
		if (n != BUFSIZ) {
			int err = ferror(fp);
			if (err) {
				xlog_error("fread error: %d", err);
				return err;
			}
			// If no error, then assert EOF.
			assert_int_not_equal(feof(fp), 0);
			break;
		}
	} while (true);
	return 0;
}

int
systemf(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	int rv = vpopenf(popen_print, NULL, fmt, va);
	va_end(va);
	return rv;
}

int
vasconfigf(char **pvalue, const char *fmt, va_list va)
{
	char *value;
	int rv = 0;

	rv = vasprintf(&value, fmt, va);
	if (rv < 0) {
		return rv;
	}

	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		char *old_value = value;
		rv = popenf(popen_strcpy, &value, "echo -n '%s' | base64",
			    value);
		message_info("bases64 encode '%s' -> '%s'\n", old_value,
			     value);
		free(old_value);
	}
	*pvalue = value;
	return rv;
}

int
asconfigf(char **pvalue, const char *fmt, ...)
{
	int rv = 0;
	va_list va;
	va_start(va, fmt);
	rv = vasconfigf(pvalue, fmt, va);
	va_end(va);
	return rv;
}

struct test_instance_config *
test_instance_config_create(const char *id, const char *topic, const char *fmt,
			    ...)
{
	struct test_instance_config *config = xcalloc(sizeof(*config), 1);
	int rv;
	rv = asprintf(&config->key, "%s/%s", id, topic);
	if (rv < 0) {
		xlog_error("asprintf failed: %s", strerror(errno));
		goto error;
	}

	rv = asprintf(&config->state_key, "state/%s", config->key);
	if (rv < 0) {
		xlog_error("asprintf failed: %s", strerror(errno));
		goto error;
	}

	rv = asprintf(&config->config_key, "configuration/%s", config->key);
	if (rv < 0) {
		xlog_error("asprintf failed: %s", strerror(errno));
		goto error;
	}

	va_list va;
	va_start(va, fmt);
	rv = vasprintf(&config->value_noenc, fmt, va);
	va_end(va);
	if (rv < 0) {
		xlog_error("vasprintf failed: %s", strerror(errno));
		goto error;
	}

	rv = asconfigf(&config->value, "%s", config->value_noenc);
	if (rv < 0) {
		xlog_error("asconfigf failed: %s", strerror(errno));
		goto error;
	}
	return config;

error:
	test_instance_config_free(config);
	return NULL;
}

void
test_instance_config_free(struct test_instance_config *config)
{
	free(config->config_key);
	free(config->state_key);
	free(config->key);
	free(config->value_noenc);
	free(config->value);
	free(config);
}

JSON_Object *
object_create(const char *in)
{
	JSON_Value *v;
	if (in) {
		v = json_parse_string(in);
	} else {
		v = json_value_init_object();
	}
	assert_non_null(v);

	JSON_Object *o = json_value_get_object(v);
	assert_non_null(o);
	return o;
}

char *
object_serialize(JSON_Object *o)
{
	JSON_Value *v = json_object_get_wrapping_value(o);
	assert_non_null(v);

	char *payload = json_serialize_to_string(v);
	assert_non_null(payload);
	char *out = strdup(payload);
	json_free_serialized_string(payload);
	return out;
}

void
object_free(JSON_Object *o)
{
	json_value_free(json_object_get_wrapping_value(o));
}

int
object_add_instance_config(JSON_Object *o, struct test_instance_config *config)
{
	if (json_object_set_string(o, config->config_key, config->value) !=
	    JSONSuccess) {
		xlog_error("json_object_set_string failed");
		return -1;
	}
	return 0;
}

JSON_Object *
manifest_create(const char *manifest_in, const char *deployment_id)
{
	JSON_Status status;
	JSON_Object *m = object_create(manifest_in);
	assert_non_null(m);

	JSON_Object *o = json_object_get_object(m, "deployment");
	if (!o) {
		JSON_Value *v = json_value_init_object();
		assert_int_equal(json_object_set_value(m, "deployment", v),
				 JSONSuccess);
		o = json_value_get_object(v);
	}

	if (deployment_id) {
		status = json_object_set_string(o, "deploymentId",
						deployment_id);
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(o, "instanceSpecs")) {
		status = json_object_set_value(o, "instanceSpecs",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(o, "modules")) {
		status = json_object_set_value(o, "modules",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(o, "publishTopics")) {
		status = json_object_set_value(o, "publishTopics",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(o, "subscribeTopics")) {
		status = json_object_set_value(o, "subscribeTopics",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}

	return m;
}

JSON_Object *
manifest_add_instance_spec(JSON_Object *o, const char *name,
			   const char *module, const char *ep, int version)
{
	JSON_Status status;

	o = json_object_get_object(o, "deployment");
	assert_non_null(o);

	o = json_object_get_object(o, "instanceSpecs");
	assert_non_null(o);

	JSON_Object *io = json_object_get_object(o, name);
	if (!io) {
		JSON_Value *iv = json_value_init_object();
		io = json_value_get_object(iv);
		assert_non_null(io);
		status = json_object_set_value(o, name, iv);
		assert_int_equal(status, JSONSuccess);
	}

	status = json_object_set_string(io, "moduleId", module);
	assert_int_equal(status, JSONSuccess);

	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		status = json_object_set_string(io, "entryPoint", ep);
		assert_int_equal(status, JSONSuccess);

		status =
			json_object_set_number(io, "version", (double)version);
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(io, "subscribe")) {
		status = json_object_set_value(io, "subscribe",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}

	if (!json_object_get_object(io, "publish")) {
		status = json_object_set_value(io, "publish",
					       json_value_init_object());
		assert_int_equal(status, JSONSuccess);
	}
	return io;
}

JSON_Object *
manifest_add_module_spec(JSON_Object *o, const char *name, const char *impl,
			 const char *hash, const char *url, const char *ep)
{
	JSON_Status status;

	o = json_object_get_object(o, "deployment");
	assert_non_null(o);

	o = json_object_get_object(o, "modules");
	assert_non_null(o);

	JSON_Object *mo = json_object_get_object(o, name);
	if (!mo) {
		JSON_Value *mv = json_value_init_object();
		mo = json_value_get_object(mv);
		assert_non_null(mo);
		status = json_object_set_value(o, name, mv);
		assert_int_equal(status, JSONSuccess);
	}
	assert_non_null(mo);

	status = json_object_set_string(mo, "moduleImpl", impl);
	assert_int_equal(status, JSONSuccess);

	status = json_object_set_string(mo, "hash", hash);
	assert_int_equal(status, JSONSuccess);

	status = json_object_set_string(mo, "downloadUrl", url);
	assert_int_equal(status, JSONSuccess);

	if (agent_test_get_hub_type() != EVP_HUB_TYPE_EVP1_TB) {
		status = json_object_set_string(mo, "entryPoint", ep);
		assert_int_equal(status, JSONSuccess);
	}

	return mo;
}

void
manifest_finalize(JSON_Object *o)
{
	// Wrap for EVP1 schema
	if (agent_test_get_hub_type() == EVP_HUB_TYPE_EVP1_TB) {
		JSON_Value *v = json_object_get_value(o, "deployment");
		assert_non_null(v);
		char *str = json_serialize_to_string(v);
		assert_non_null(str);
		assert_int_equal(json_object_set_string(o, "deployment", str),
				 JSONSuccess);
		json_free_serialized_string(str);
	}
}

char *
manifest_serialize_deployment(JSON_Object *o)
{
	JSON_Value *d = json_object_get_value(o, "deployment");

	char *deployment = json_serialize_to_string(d);
	char *out = strdup(deployment);
	json_free_serialized_string(deployment);
	return out;
}

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that there is a data item with identical string value.
 * Ignores non-matching items.
 */
bool
verify_equals(const char *data, const void *user_data, va_list va)
{
	const char *expected = (const char *)user_data;
	if (strcmp(data, expected) == 0) {
		message_info("Got expected data %s", expected);
		return true;
	}
	xlog_warning("Missing expected data %s in %s", expected, data);
	return false;
}

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that there is a data item with matching substring value.
 * Ignores non-matching items.
 */
bool
verify_contains(const char *data, const void *user_data, va_list va)
{
	const char *expected = (const char *)user_data;
	if (strstr(data, expected) != NULL) {
		message_info("Got expected data %s", expected);
		return true;
	}
	xlog_warning("Missing expected data %s in %s", expected, data);
	return false;
}

/**
 * Utility callback function to verify agent_poll() data.
 * Checkt that data contains expect and not contains unexpect values
 *
 * @param data pointer to string to check
 * @param user_data user_data is a type expect_unexpect_t
 */
bool
verify_contains_except(const char *data, const void *user_data, va_list va)
{
	expect_unexpect_t *checks = (expect_unexpect_t *)user_data;

	const char *expected = (const char *)checks->expect;
	const char *unexpected = (const char *)checks->unexpect;

	if (strstr(data, expected) != NULL) {
		message_info("Got expected data %s", expected);
	} else {
		xlog_warning("Missing expected data %s in %s", expected, data);
		return false;
	}

	if (strstr(data, unexpected) == NULL) {
		xlog_warning("Not found unexpected %s", unexpected);
	} else {
		xlog_error("Found unexpected data %s in %s", unexpected, data);
		return false;
	}
	return true;
}

bool
push_value(JSON_Value *v, struct jverifier *jv)
{

	if (jv->nvals == JSONSTACKSZ) {
		xlog_error("value stack overflow");
		return false;
	}
	jv->values[jv->nvals++] = v;

	return true;
}

bool
push_object(JSON_Object *o, struct jverifier *jv)
{
	if (jv->nobjs == JSONSTACKSZ) {
		xlog_error("object stack overflow");
		return false;
	}
	jv->objects[jv->nobjs++] = o;

	return true;
}

bool
pop_object(JSON_Object **op, struct jverifier *jv)
{
	if (jv->nobjs == 0) {
		xlog_error("value stack underflow");
		return false;
	}
	*op = jv->objects[--jv->nobjs];

	return true;
}

bool
push_string_value(const char *s, JSON_Object **op, struct jverifier *jv)
{
	JSON_Value *v;
	JSON_Object *o;

	if ((v = json_parse_string(s)) == NULL) {
		xlog_error("invalid json string '%s'", s);
		return false;
	}
	if (!push_value(v, jv)) {
		json_value_free(v);
		return false;
	}

	if ((o = json_value_get_object(v)) == NULL) {
		xlog_error("not object in the json value");
		return false;
	}
	if (!push_object(o, jv))
		return false;
	*op = o;

	return true;
}

void
free_values(struct jverifier *jv)
{
	int i;

	for (i = 0; i < jv->nvals; ++i)
		json_value_free(jv->values[i]);
}

bool
verify_json(const char *text, const void *user_data, va_list va)
{
	bool r = false;
	double farg, faux;
	const char *sarg, *saux;
	int n, iarg, barg, targ, baux;
	JSON_Value *v;
	JSON_Object *o;
	JSON_Value_Type t;
	char dot[BUFSIZ], *s;
	struct jverifier jv;
	const char *field, *fmt = user_data;

	message_info("verify_json: checking '%s' with '%s'", text, fmt);

	jv.nobjs = jv.nvals = 0;
	if (!push_string_value(text, &o, &jv))
		goto err;

	for (;;) {
		for (s = dot; s < &dot[BUFSIZ] && *fmt; s++) {
			if (*fmt == '=')
				break;
			*s = *fmt++;
		}
		if (s == &dot[BUFSIZ]) {
			xlog_error("too long dot expression");
			goto err;
		}
		if (*fmt++ != '=') {
			xlog_error("dot expression must be followed by =");
			goto err;
		}
		*s = '\0';

		switch (*fmt++) {
		case '$':
			if (*fmt++ != '#') {
				xlog_error("# is mandatory after $");
				goto err;
			}
			if (strcmp(dot, ".") == 0) {
				n = json_object_get_count(o);
			} else {
				v = json_object_dotget_value(o, dot);
				if (!v) {
					xlog_error("value %s not found", dot);
					goto err;
				}
				t = json_value_get_type(v);
				if (t == JSONObject) {
					xlog_error("$# applied to something "
						   "not an object");
					goto err;
				}
				n = json_object_get_count(
					json_value_get_object(v));
			}
			iarg = va_arg(va, int);
			if (n != iarg) {
				xlog_error("invalid number of children for %s",
					   dot);
				goto err;
			}
			goto final_checks;
		case '#':
			if (*fmt++ != '{') {
				xlog_error("brace is mandatory after #");
				goto err;
			}
			field = json_object_dotget_string(o, dot);
			if (!field) {
				xlog_error("'%s' is not a string", dot);
				goto err;
			}
			if (!push_string_value(field, &o, &jv))
				goto err;
			continue;
		case '{':
			o = json_object_dotget_object(o, dot);
			if (!o) {
				xlog_error("not valid nested object");
				goto err;
			}
			if (!push_object(o, &jv))
				goto err;
			continue;
		case '%':
			v = json_object_dotget_value(o, dot);
			if (!v) {
				xlog_error("value %s not found", dot);
				goto err;
			}
			t = json_value_get_type(v);
			break;
		default:
			xlog_error("missed %% for dot '%s'", dot);
			goto err;
		}

		switch (*fmt++) {
		case 't':
			targ = va_arg(va, int);
			if (t != targ) {
				xlog_error(
					"expected %d but got %d for %s type",
					targ, t, dot);
				goto err;
			}
			break;
		case 's':
			if (t != JSONString) {
				xlog_error("%s is not a string", dot);
				goto err;
			}
			saux = json_value_get_string(v);
			sarg = va_arg(va, char *);
			if (strcmp(sarg, saux)) {
				xlog_error("expected '%s' but got '%s' for %s",
					   sarg, saux, dot);
				goto err;
			}
			break;
		case 'f':
			if (t != JSONNumber) {
				xlog_error("'%s' is not a number", dot);
				goto err;
			}
			faux = json_value_get_number(v);
			farg = va_arg(va, double);
			if (farg != faux) {
				xlog_error("expected %f but got %f for %s",
					   farg, faux, dot);
				goto err;
			}
			break;
		case 'b':
			if (t != JSONBoolean) {
				xlog_error("'%s' is not a boolean", dot);
				goto err;
			}
			baux = json_value_get_boolean(v);
			barg = va_arg(va, int);
			if (barg != baux) {
				xlog_error("expected %d but got %d for %s",
					   barg, baux, dot);
				goto err;
			}
			break;
		default:
			xlog_error("invalid specifier in verify_json");
			goto err;
		}

	final_checks:
		if (*fmt == '}') {
			if (!pop_object(&o, &jv))
				goto err;
			fmt++;
		}
		if (*fmt == '\0')
			break;
		if (*fmt++ != ',') {
			xlog_error("garbage at the end of specifier");
			goto err;
		}
	}
	r = true;
	message_info("Got expected data %s in %s", (char *)user_data, text);

err:
	free_values(&jv);

	return r;
}

/**
 * Utility callback function to verify agent_poll() data.
 * Checks that all items in set are contained in data wichever the order.
 * Ignores non-matching items.
 */
bool
verify_contains_in_unordered_set(const char *data, const void *user_data,
				 va_list va)
{
	struct multi_check *set = (struct multi_check *)user_data;
	int found = 0;
	int count = 0;
	for (count = 0; set->value; count++, set++) {
		if (strstr(data, set->value) != NULL) {
			message_info("Got expected data %s", set->value);
			set->found = true;
		}

		if (set->found) {
			found++;
		}
	}
	return found == count;
}

/**
 * Utility callback function to verify agent_poll() data.
 * Verifies data with cmocka check_expected().
 * To use, call cmocka expect_...(verify_expected, data, ...) before invoking
 * agent_poll().
 * Fails on non-matching items.
 */
bool
verify_expected(const char *data, const void *user_data, va_list va)
{
	check_expected(data);
	return true;
}

static void
start_run(void)
{
	xpthread_mutex_lock(&g_agent_test.lock);
	g_agent_test.running = 1;
	xpthread_mutex_unlock(&g_agent_test.lock);
}

static int
is_running(void)
{
	int r;

	xpthread_mutex_lock(&g_agent_test.lock);
	r = g_agent_test.running;
	xpthread_mutex_unlock(&g_agent_test.lock);

	return r;
}

bool
get_connected(void)
{
	bool r;

	xpthread_mutex_lock(&g_agent_test.lock);
	r = g_agent_test.connected;
	xpthread_mutex_unlock(&g_agent_test.lock);

	return r;
}

void
set_connected(bool connect)
{
	xpthread_mutex_lock(&g_agent_test.lock);
	g_agent_test.connected = connect;
	xpthread_mutex_unlock(&g_agent_test.lock);
}

static void
stop_run(void)
{
	xpthread_mutex_lock(&g_agent_test.lock);
	g_agent_test.running = 0;
	xpthread_mutex_unlock(&g_agent_test.lock);
}

static void *
agent_thread(void *vp)
{
	int ret;
	struct evp_agent_context *ctxt = vp;
	ret = pthread_setname_np(pthread_self(), "agent_test_thrd");
	assert_int_equal(ret, 0);

	start_run();
	ret = evp_agent_start(ctxt);
	assert_int_equal(ret, 0);
	// Connect agent if test setup is not configured in offline mode
	if (!g_agent_test.offline_hub) {
		ret = evp_agent_connect(ctxt);
		assert_int_equal(ret, 0);
	}
	while (is_running()) {
		ret = g_agent_test.agent_loop_fn(ctxt);
		assert_int_equal(ret, 0);
	}

	ret = evp_agent_disconnect(ctxt);
	assert_int_equal(ret, 0);
	ret = evp_agent_stop(ctxt);
	evp_agent_free(ctxt);
	assert_int_equal(ret, 0);

	return NULL;
}

int
agent_test_call_count(int inc)
{
	static int count = 0;
	int rv;

	xpthread_mutex_lock(&g_agent_test.lock);
	if (inc < 0) {
		count = 0;
	} else {
		count += inc;
	}
	rv = count;
	xpthread_mutex_unlock(&g_agent_test.lock);

	return rv;
}

void
agent_init_instance_workspace_file(const char *instance_id,
				   const char *filename, const char *command)
{
	char *workspace;
	const char *mi_path = path_get(MODULE_INSTANCE_PATH_ID);
	xasprintf(&workspace, "%s/%s/default_workspace", mi_path, instance_id);
	systemf("mkdir -p %s", workspace);
	assert_int_equal(systemf("%s > %s/%s", command, workspace, filename),
			 0);
	free(workspace);
}
/**
 * Configure environment for running an EVP Agent system test
 */
void
agent_test_setup(void)
{
	putenv("EVP_MQTT_HOST=test.mqtt.host.value");
	putenv("EVP_MQTT_PORT=1234");
	putenv("EVP_DOCKER_HOST=http://dockerd");
	putenv("EVP_MQTT_CLIENTID=10001");
	putenv("EVP_MQTT_DEVICE_ID=10001");
	putenv("EVP_REPORT_STATUS_INTERVAL_MIN_SEC=1");
	putenv("EVP_REPORT_STATUS_INTERVAL_MAX_SEC=1");

	/* This expects "EVP_IOT_PLATFORM" to not be null */
	char *iot_platform = getenv("EVP_IOT_PLATFORM");
	assert_non_null(iot_platform);

	/* Use the default agent loop function */
	g_agent_test.agent_loop_fn = evp_agent_loop;
	path_init(getenv("EVP_DATA_DIR"));

	/*
	 * ignore errors because we only want to
	 * be sure that the environment in clean
	 */
	remove(path_get(DESIRED_TWINS_PATH_ID));
	remove(path_get(CURRENT_TWINS_PATH_ID));
	systemf("rm -rf %s", path_get(MODULE_PATH_ID));
	systemf("rm -rf %s", path_get(MODULE_INSTANCE_PATH_ID));
}

void
agent_test_enable_capture_mode(void)
{
	g_agent_test.offline_hub = true;
}

/**
 * Override the agent loop function
 */
void
agent_set_loop_function(evp_agent_loop_fn_t loop_fun)
{
	assert_int_equal(is_running(), 0);
	g_agent_test.agent_loop_fn = loop_fun;
}

/**
 * Get a valid evp_hub_type from environment
 *
 * @return A valid evp_hub_type. In case off error an assert is raised
 */
const enum evp_hub_type
agent_test_get_hub_type(void)
{
	char *iot_platform = config_get_string(EVP_CONFIG_IOT_PLATFORM);
	const enum evp_hub_type hub_type = get_hub_type(iot_platform);
	free(iot_platform);
	assert_true(hub_type != EVP_HUB_TYPE_UNKNOWN);
	return hub_type;
}

/**
 * Instantiate an EVP Agent and run it in its own thread.
 * agent_test_start() also creates a pipe that can be used to collect and poll
 * for test data. The Agent thread is exited by calling agent_test_exit().
 */
struct evp_agent_context *
agent_test_start(void)
{
	int ret;

	// create pipe for test data
#ifdef O_DIRECT
	ret = pipe2(g_agent_test.pipe, O_DIRECT);
#else
	ret = pipe(g_agent_test.pipe);
#endif
	assert_int_equal(0, ret);

	// instantiate EVP Agent context
	struct evp_agent_context *ctxt;
	ctxt = evp_agent_setup("evp_agent_main");
	assert_non_null(ctxt);

	// spin up agent thread
	ret = pthread_create(&g_agent_test.thread_id, NULL, agent_thread,
			     ctxt);
	assert_int_equal(ret, 0);

	// wait for agent to be ready
	while (!evp_agent_ready(ctxt)) {
		xlog_info("waiting for the agent");
		sleep(1);
	}

	if (g_agent_test.offline_hub) {
		return ctxt;
	}

	// wait until the agent is connected to the hub
	while (evp_agent_get_status(ctxt) != EVP_AGENT_STATUS_CONNECTED) {
		xlog_info("waiting to be connected to the hub");
		sleep(1);
	}
	return ctxt;
}

/**
 * Stop the agent thread
 */
void
agent_test_exit(void)
{
	int ret = 0, running;
	void *value;

	/* Call get_connected just to avoid the unused function warning
	 * on tests that don't use the *_connected() methods yet.
	 */
	get_connected();
	running = is_running();
	stop_run();
	if (running) {
		ret = pthread_join(g_agent_test.thread_id, &value);
		assert_int_equal(ret, 0);
		assert_null(value);
	}
	path_free();
	set_connected(false);
}

/**
 * Write to test data pipe.
 * Usually invoked from a callback that may be called from a separate thread
 * from the test.
 */
void
agent_write_to_pipe(const char *data)
{
	size_t remain = strlen(data) + 1;
	int fd = g_agent_test.pipe[1];
	if (fd == -1) {
		return;
	}
	while (remain) {
		xlog_debug("write pipe %s", data);
		ssize_t ret;
		ret = write(fd, data, remain);
		assert_true(ret > 0);
		assert_true(remain >= (size_t)ret);
		remain -= ret;
		data += ret;
	}
}

static char *
vagent_poll_fetch(agent_test_verify_t verify_callback, const void *user_data,
		  va_list ud_va)
{
	int r, fds = g_agent_test.pipe[0];
	char *payload, c;
	size_t cnt;

	payload = NULL;
	for (cnt = 1;; cnt++) {
		r = read(fds, &c, 1);
		assert_int_equal(r, 1);

		payload = xrealloc(payload, cnt);
		payload[cnt - 1] = c;
		if (c == '\0') {
			va_list apc;
			int result;

			va_copy(apc, ud_va);
			result = verify_callback(payload, user_data, apc);
			va_end(apc);

			if (result) {
				break;
			}
			cnt = 0;
		}
	}
	return payload;
}

/**
 * Wait for data to arrive in test data pipe, and validate with callback
 * function.
 * @param[in] verify_callback user provided function to validate test data
 * @param[in] user_data provided to verify_callback along with test data
 */
void
agent_poll(agent_test_verify_t verify_callback, const void *user_data, ...)
{
	char *msg;
	va_list v_args;
	va_start(v_args, user_data);
	msg = vagent_poll_fetch(verify_callback, user_data, v_args);
	free(msg);
	va_end(v_args);
}

/**
 * Wait for data to arrive in test data pipe, and validate with callback
 * function.
 * @param[in] verify_callback user provided function to validate test data
 * @param[in] user_data provided to verify_callback along with test data
 *
 * @return A copy of the message that matched with `verify_callback`
 */
char *
agent_poll_fetch(agent_test_verify_t verify_callback, const void *user_data,
		 ...)
{
	char *msg;
	va_list v_args;
	va_start(v_args, user_data);
	msg = vagent_poll_fetch(verify_callback, user_data, v_args);
	va_end(v_args);
	return msg;
}

void
agent_register_payload(unsigned int id, enum evp_hub_type hub_type,
		       const char *payload)
{
	if (id > AGENT_TEST_MAX_PAYLOAD_ID) {
		fail_msg("Invalid test payload id: %d", id);
	}
	g_agent_test.payloads[hub_type][id] = payload;
}

const char *
agent_get_payload(unsigned int id)
{
	if (id > AGENT_TEST_MAX_PAYLOAD_ID) {
		fail_msg("Invalid test payload id: %d", id);
	}
	enum evp_hub_type hub_type = agent_test_get_hub_type();
	return g_agent_test.payloads[hub_type][id];
}

char *
agent_get_payload_formatted(unsigned int id, ...)
{
	const char *fmt = agent_get_payload(id);
	char *payload;
	va_list ap;
	int rv;

	va_start(ap, id);
	rv = vasprintf(&payload, fmt, ap);
	va_end(ap);
	if (rv == -1) {
		fail_msg("Failed to generate formatted payload");
	}
	return payload;
}

/**
 * Send a deployment manifest payload with the configured hub envelope
 */
void
agent_send_deployment(struct evp_agent_context *ctxt, const char *payload)
{
	message_info("Sending deployment");

	// EVP_HUB_TYPE_EVP[12]_TB
	// send deployment update
	char *msgdata;
	const char *topic = "v1/devices/me/attributes";
	xasprintf(&msgdata, "{\"deployment\": %s}", payload);
	evp_agent_send(ctxt, topic, msgdata);
	free(msgdata);
}

/**
 * Send a device config payload with the configured hub envelope
 */
void
agent_send_device_config(struct evp_agent_context *ctxt, const char *payload)
{
	// EVP_HUB_TYPE_EVP[12]_TB
	// test device config update
	char *msgdata;
	const char *topic = "v1/devices/me/attributes";
	xasprintf(&msgdata, "{\"desiredDeviceConfig\": %s}", payload);
	evp_agent_send(ctxt, topic, msgdata);
	free(msgdata);
}

void
agent_send_instance_config(struct evp_agent_context *ctxt, const char *payload)
{
	message_info("Sending instance config: %s", payload);

	// EVP_HUB_TYPE_EVP[12]_TB
	// test device config update
	const char *topic = "v1/devices/me/attributes";
	evp_agent_send(ctxt, topic, payload);
}

/**
 * Send a direct command request payload with the configured hub envelope
 */
void
agent_send_direct_command_req(struct evp_agent_context *ctxt,
			      const char *payload, EVP_RPC_ID mqtt_request_id)
{
	enum evp_hub_type hub_type = agent_test_get_hub_type();
	if (hub_type == EVP_HUB_TYPE_EVP1_TB) {
		// for EVP1, reqid in MQTT topic has to be the same
		// as EVP1 request id
		char *topic;
		xasprintf(&topic, "v1/devices/me/rpc/request/%lu",
			  mqtt_request_id);
		evp_agent_send(ctxt, topic, payload);
		free(topic);
	} else if (hub_type == EVP_HUB_TYPE_EVP2_TB) {
		// for EVP2, reqid in MQTT topic may be different from
		// EVP2 request id
		char *msgdata;
		char *topic;
		xasprintf(&topic, "v1/devices/me/rpc/request/%lu",
			  mqtt_request_id);
		xasprintf(&msgdata,
			  "{\"method\": \"evp-c2d\", \"params\": %s}",
			  payload);
		evp_agent_send(ctxt, topic, msgdata);
		free(msgdata);
		free(topic);
	}
}

/**
 * Send a storage token response payload with the configured hub envelope
 */
void
agent_send_storagetoken_response(struct evp_agent_context *ctxt,
				 const char *payload,
				 const char *evp1_topic_reqid)
{
	// send the STP response (with the token)
	char *topic;
	if (evp1_topic_reqid == NULL) {
		xlog_error("reqid can not be NULL");
		assert_non_null(evp1_topic_reqid);
	}
	xasprintf(&topic, "v1/devices/me/rpc/response/%s", evp1_topic_reqid);
	evp_agent_send(ctxt, topic, payload);
	free(topic);
}

void
agent_send_initial(struct evp_agent_context *ctxt, const char *deployment,
		   const char *device_config, const char *instance_config)
{
	message_info("Sending initial deployment");

	// EVP_HUB_TYPE_EVP[12]_TB
	// send shared attribute response
	char *msgdata;
	char *concat;
	const char *topic = "v1/devices/me/attributes/response/10000";
	if (deployment != NULL) {
		xasprintf(&msgdata, "{\"shared\":{\"deployment\":%s",
			  deployment);
	} else {
		xasprintf(&msgdata, "{\"shared\":{");
	}
	if (device_config != NULL) {
		if (deployment != NULL) {
			xasprintf(&concat, "%s\",desiredDeviceConfig\":%s",
				  msgdata, device_config);
		} else {
			xasprintf(&concat, "%s\"desiredDeviceConfig\":%s",
				  msgdata, device_config);
		}
		free(msgdata);
		msgdata = concat;
	}
	if (instance_config != NULL) {
		if (deployment != NULL || device_config != NULL) {
			xasprintf(&concat, "%s,%s", msgdata, instance_config);
		} else {
			xasprintf(&concat, "%s%s", msgdata, instance_config);
		}
		free(msgdata);
		msgdata = concat;
	}
	// append terminating braces
	xasprintf(&concat, "%s}}", msgdata);
	free(msgdata);
	msgdata = concat;
	// send payload
	evp_agent_send(ctxt, topic, msgdata);
	free(msgdata);
}

void
agent_poll_status(struct evp_agent_context *ctxt, enum evp_agent_status status,
		  int timeout)
{
	int iter = 0;
	while (1) {
		enum evp_agent_status new_status = evp_agent_get_status(ctxt);
		if (status == new_status) {
			break;
		}
		sleep(1);
		assert_int_not_equal(++iter, timeout);
	}
}

void
agent_ensure_deployment_status(const char *id, const char *status)
{

	enum evp_hub_type type = agent_test_get_hub_type();
	const char *fmt;

	switch (type) {
	case EVP_HUB_TYPE_EVP1_TB:
		fmt = "deploymentStatus=#{"
		      "deploymentId=%s,"
		      "reconcileStatus=%s"
		      "}";
		break;

	case EVP_HUB_TYPE_EVP2_TB:
		fmt = "deploymentStatus.deploymentId=%s,"
		      "deploymentStatus.reconcileStatus=%s";
		break;

	default:
		fail_msg("unexpected hub type %d\n", type);
	}

	message_info("Checking deployment");

	agent_poll(verify_json, fmt, id, status);
}

void
agent_ensure_instance_status(const char *id, const char *status)
{
	enum evp_hub_type type = agent_test_get_hub_type();
	char *fmt = NULL;

	switch (type) {
	case EVP_HUB_TYPE_EVP1_TB:
		{
			const char *s = "deploymentStatus=#{"
					"instances.%s.status=%%s"
					"}";

			assert_int_not_equal(asprintf(&fmt, s, id), -1);
		}
		break;

	case EVP_HUB_TYPE_EVP2_TB:
		{
			const char *s =
				"deploymentStatus.instances.%s.status=%%s";

			assert_int_not_equal(asprintf(&fmt, s, id), -1);
		}
		break;

	default:
		fail_msg("unexpected hub type %d\n", type);
		return;
	}

	agent_poll(verify_json, fmt, status);
	free(fmt);
}

void
agent_ensure_deployment(struct agent_deployment *d, const char *payload,
			const char *deploymentId)
{
	agent_ensure_deployment_config(d, payload, deploymentId, NULL);
}

void
agent_ensure_deployment_config(struct agent_deployment *d, const char *payload,
			       const char *deploymentId,
			       const char *instance_config)
{
	struct evp_agent_context *ctxt = d->ctxt;

	if (d->init) {
		agent_send_deployment(ctxt, payload);
	} else {
		agent_send_initial(ctxt, payload, NULL, instance_config);
		d->init = true;
	}

	if (!payload) {
		return;
	}

	agent_ensure_deployment_status(deploymentId, "ok");
}

struct profile
agent_profile_start(char *id)
{
	struct profile p = {.id = id};
	clock_gettime(CLOCK_MONOTONIC, &p.start);
	// message_info("profile %s: started", id);
	return p;
}

void
agent_profile_print(struct profile *p)
{
	struct timespec now, diff;
	clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, &p->start, &diff);
	int ms = (timespec2ns(&diff) + 999999) / 1000000;

	message_info("profile %s: %d ms", p->id, ms);
}
