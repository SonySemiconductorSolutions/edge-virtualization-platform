/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * REVISIT: handwritten converters like this is not maintainable
 * if we need to have many of them. at this point it's probably ok as
 * we only have one. but if it turns out that we need more, consider
 * implementing something more generic. like a code generator.
 * or, simply give up having "nice-looking C structures" and use
 * JSON_Value directly.
 */

#include <config.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/util.h>

#include "cdefs.h"
#include "global.h"
#include "manifest.h"
#include "module_instance.h"
#include "persist.h"
#include "xlog.h"

#if defined(RAW_CONTAINER_SPEC)
#include "container_spec.h"
#endif

const char *g_reserved_prefix = "$";

static void
free_topic_alias_list(struct TopicAliasList *list)
{
	if (list == NULL) {
		return;
	}
	unsigned int i;
	for (i = 0; i < list->n; i++) {
		free(list->aliases[i].alias);
		free(list->aliases[i].topic);
	}
	free(list);
}

static void
free_topic_list(struct TopicList *list)
{
	if (list == NULL) {
		return;
	}
	unsigned int i;
	for (i = 0; i < list->n; i++) {
		free(list->topics[i].name);
		free(list->topics[i].type);
		free(list->topics[i].topic);
	}
	free(list);
}

static void
free_stream_list(struct StreamList *list)
{
	if (list) {
		for (size_t i = 0; i < list->n; i++) {
			stream_free(&list->streams[i]);
		}
	}

	free(list);
}

static void
free_module_instance_spec(struct ModuleInstanceSpec *instance)
{
	free(instance->name);
	free(instance->moduleId);
	free(instance->entryPoint);
	free_topic_alias_list(instance->subscribe);
	free_topic_alias_list(instance->publish);
	free_stream_list(instance->streams);
	free(instance->failureMessage);
#if defined(RAW_CONTAINER_SPEC)
	if (instance->rawContainerSpec != NULL) {
		json_value_free(instance->rawContainerSpec);
	}
#endif /* RAW_CONTAINER_SPEC */
}

static void
free_instance_specs(struct InstanceSpecs *spec)
{
	if (spec == NULL) {
		return;
	}
	unsigned int i;
	for (i = 0; i < spec->n; i++) {
		free_module_instance_spec(&spec->instances[i]);
	}
	free(spec);
}

static void
free_module(struct Module *module)
{
	free(module->moduleId);
	free(module->moduleImpl);
	free(module->downloadUrl);
	free(module->hash);
	free(module->entryPoint);
}

static void
free_module_list(struct ModuleList *modules)
{
	if (modules == NULL) {
		return;
	}
	unsigned int i;
	for (i = 0; i < modules->n; i++) {
		free_module(&modules->modules[i]);
	}
	free(modules);
}

/**
 * @brief
 * This function performs further parsing and validation of
 * instance specifications. This can be used for implementations
 * such as the rawContainerSpec backdoor mechanism for docker
 * module instances.
 * \param [inout] spec the module instance being assembled.
 * \param [in] obj JSON value containing the instance spec JSON object
 * \return Zero on success. Otherwise, an errno value is returned.
 */
static int
instance_spec_extra_parse_evp1(struct ModuleInstanceSpec *spec,
			       const JSON_Object *obj)
{
	int ret = 0;
	char *failureMessage = NULL;

#if defined(RAW_CONTAINER_SPEC)
	ret = container_spec_extra_parse_evp1(spec, obj, &failureMessage);
#endif

	free(spec->failureMessage);

	if (ret != 0) {
		spec->failureMessage = failureMessage;
		xlog_error("Pre-validation error: %s", failureMessage);
	} else {
		free(failureMessage);
		spec->failureMessage = NULL;
	}
	return ret;
}

/**
 * @brief
 * This function performs further parsing and validation of
 * instance specifications. This can be used for implementations
 * such as the rawContainerSpec backdoor mechanism for docker
 * module instances.
 * \param [inout] spec the module instance being assembled.
 * \param [in] obj JSON value containing the instance spec JSON object
 * \return Zero on success. Otherwise, an errno value is returned.
 */
static int
instance_spec_extra_parse_evp2(struct ModuleInstanceSpec *spec,
			       const JSON_Object *obj)
{
	int ret = 0;
	char *failureMessage = NULL;

#if defined(RAW_CONTAINER_SPEC)
	ret = container_spec_extra_parse_evp2(spec, obj, &failureMessage);
#endif

	if (ret != 0) {
		xlog_error("Pre-validation error: %s", failureMessage);
	}

	spec->failureMessage = failureMessage;

	/* Conciously ignore the error status. Since spec->failureMessage is
	 * still set, this is enough for apply_deployment to avoid starting
	 * the affected module instance.
	 * Otherwise, returning != 0 would stop parsing the rest of the
	 * deployment, even if the deploymentManifest for other module
	 * instances is well-defined, with undesired consequences. */
	return 0;
}

void
free_deployment(struct Deployment *deploy)
{
	if (deploy == NULL) {
		return;
	}
	free_instance_specs(deploy->instanceSpecs);
	free_module_list(deploy->modules);
	free_topic_list(deploy->subscribe_topics);
	free_topic_list(deploy->publish_topics);
	free(deploy->deploymentId);
	free(deploy);
}

int
convert_topic(JSON_Object *obj, struct Topic *topic)
{
	const char *topic_type = json_object_get_string(obj, "type");
	const char *topic_topic = json_object_get_string(obj, "topic");
	if (topic_type == NULL || topic_topic == NULL) {
		return EINVAL;
	}
	topic->type = xstrdup(topic_type);
	topic->topic = xstrdup(topic_topic);
	return 0;
}

int
convert_topic_alias_list(const JSON_Object *obj, const char *name,
			 struct TopicAliasList **resultp)
{
	const JSON_Object *o = json_object_get_object(obj, name);
	if (o == NULL) {
		return EINVAL;
	}

	/* "o" here is something like:
	 *
	 *   {
	 *       "to-ppl": "local-topic-for-publish"
	 *   }
	 */

	struct TopicAliasList *list;
	size_t n = json_object_get_count(o);
	*resultp = list =
		xcalloc(1, sizeof(*list) + n * sizeof(*list->aliases));
	list->n = n;
	unsigned int i;
	for (i = 0; i < n; i++) {
		struct TopicAlias *alias = &list->aliases[i];

		const char *alias_alias = json_object_get_name(o, i);
		JSON_Value *alias_topic = json_object_get_value_at(o, i);
		alias->alias = xstrdup(alias_alias);
		alias->topic = xstrdup(json_value_get_string(alias_topic));
	}
	return 0;
}

int
convert_topic_list(JSON_Object *o, struct TopicList **resultp)
{
	int ret = 0;
	struct TopicList *list = NULL;
	if (o == NULL) {
		ret = EINVAL;
		goto failure;
	}

	/* "o" here is something like:
	 *
	 *   {
	 *     "local-topic-for-publish": {
	 *       "type": "local",
	 *       "topic": "spl-to-ppl"
	 *     }
	 *   }
	 */

	size_t n = json_object_get_count(o);
	list = xcalloc(1, sizeof(*list) + n * sizeof(*list->topics));
	list->n = n;
	for (size_t i = 0; i < n; i++) {
		struct Topic *topic = &list->topics[i];
		const char *topic_name = json_object_get_name(o, i);
		JSON_Value *v = json_object_get_value_at(o, i);
		JSON_Object *t = json_value_get_object(v);
		if (t == NULL) {
			ret = EINVAL;
			goto failure;
		}
		JSON_Value *topic_type = json_object_get_value(t, "type");
		JSON_Value *topic_topic = json_object_get_value(t, "topic");
		if (topic_type == NULL || topic_topic == NULL) {
			ret = EINVAL;
			goto failure;
		}
		const char *topic_topic_s = json_value_get_string(topic_topic);
		const char *topic_type_s = json_value_get_string(topic_type);
		if (topic_topic_s == NULL || topic_type_s == NULL) {
			ret = EINVAL;
			goto failure;
		}
		topic->name = xstrdup(topic_name);
		topic->type = xstrdup(topic_type_s);
		topic->topic = xstrdup(topic_topic_s);
	}
	*resultp = list;
	return 0;
failure:
	if (list) {
		for (size_t i = 0; i < list->n; i++) {
			struct Topic *topic = &list->topics[i];
			free(topic->name);
			free(topic->type);
			free(topic->topic);
		}
	}
	free(list);
	return ret;
}

static int
get_posix_stream_hostname(const JSON_Object *o, const struct Stream *stream,
			  struct StreamPosix *posix)
{
	const char *hostname = json_object_get_string(o, "hostname");
	if (hostname == NULL) {
		xlog_error("could not find stream hostname");
		return EINVAL;
	}

	posix->hostname = strdup(hostname);
	if (posix->hostname == NULL) {
		xlog_error("strdup(3) failed with errno %d", errno);
		return ENOMEM;
	}

	return 0;
}

static int
get_posix_stream_type(const JSON_Object *o, const struct Stream *stream,
		      struct StreamPosix *posix)
{
	const char *type = json_object_get_string(o, "type");
	if (type == NULL) {
		xlog_error("could not find stream type");
		return EINVAL;
	}

	if (!strcmp(type, "tcp")) {
		posix->type = STREAM_POSIX_TYPE_TCP;
	} else {
		xlog_error("unsupported type %s", type);
		return EINVAL;
	}

	return 0;
}

static int
get_posix_stream_domain(const JSON_Object *o, const struct Stream *stream,
			struct StreamPosix *posix)
{
	const char *domain = json_object_get_string(o, "domain");
	if (domain == NULL) {
		xlog_error("could not find stream domain");
		return EINVAL;
	}

	if (!strcmp(domain, "IPv4")) {
		posix->domain = STREAM_POSIX_DOMAIN_IPV4;
	} else if (!strcmp(domain, "IPv6")) {
		posix->domain = STREAM_POSIX_DOMAIN_IPV6;
	} else {
		xlog_error("unsupported domain %s", domain);
		return EINVAL;
	}

	return 0;
}

static int
get_posix_stream_port(const JSON_Object *o, const struct Stream *stream,
		      struct StreamPosix *posix)
{
	char *end;
	const char *port = json_object_get_string(o, "port");
	if (port == NULL) {
		xlog_error("could not find stream port");
		return EINVAL;
	}

	errno = 0;
	unsigned long value = strtoul(port, &end, 10);

	if (errno) {
		xlog_error("strotul(3) %s: errno %d", port, errno);
		return EINVAL;
	}

	if (*end || value > UINT16_MAX) {
		xlog_error("invalid port number %s", port);
		return EINVAL;
	}

	posix->port = value;
	return 0;
}

static int
convert_posix_stream(const JSON_Object *o, struct Stream *s)
{
	int ret = EINVAL;
	const JSON_Value *v = json_object_get_value(o, "parameters");
	struct StreamPosix posix = {0};

	if (v == NULL) {
		xlog_error("unexpected null parameters");
		ret = ENOMEM;
		goto end;
	}

	const JSON_Object *nobj = json_value_get_object(v);
	if (nobj == NULL) {
		xlog_error("unexpected null parameters object");
		goto end;
	}

	static int (*const params[])(const JSON_Object *,
				     const struct Stream *,
				     struct StreamPosix *) = {
		get_posix_stream_type, get_posix_stream_domain,
		get_posix_stream_hostname, get_posix_stream_port};

	for (size_t i = 0; i < __arraycount(params); i++) {
		ret = params[i](nobj, s, &posix);
		if (ret != 0) {
			goto end;
		}
	}

	s->type = STREAM_TYPE_POSIX;
	s->params.posix = posix;
	ret = 0;

end:
	if (ret != 0) {
		free(posix.hostname);
	}

	return ret;
}

static int
convert_stream(const JSON_Object *o, const char *name, struct Stream *stream)
{
	int ret = EINVAL;
	const char *direction = json_object_get_string(o, "direction");
	const char *type = json_object_get_string(o, "type");
	struct Stream s = {.name = strdup(name)};

	if (s.name == NULL) {
		xlog_error("strdup(3) errno %d", errno);
		ret = ENOMEM;
		goto end;
	}

	if (type == NULL) {
		xlog_error("could not find type in %s", name);
		goto end;
	}

	if (!strcmp(direction, "in")) {
		s.direction = STREAM_DIRECTION_IN;
	} else if (!strcmp(direction, "out")) {
		s.direction = STREAM_DIRECTION_OUT;
	} else {
		xlog_error("unexpected stream direction %s", direction);
		goto end;
	}

	if (!strcmp(type, "null")) {
		s.type = STREAM_TYPE_NULL;
	} else if (!strcmp(type, "posix")) {
		ret = convert_posix_stream(o, &s);
		if (ret != 0) {
			goto end;
		}
	} else {
		xlog_error("unexpected stream type %s", type);
		goto end;
	}

	*stream = s;
	ret = 0;

end:
	if (ret != 0) {
		stream_free(&s);
	}

	return ret;
}

static int
convert_streams(const JSON_Object *o, struct StreamList **const streams)
{
	int ret = EINVAL;
	size_t n = json_object_get_count(o);
	size_t totalsz = sizeof(**streams) + n * sizeof(struct Stream);
	struct StreamList *list = malloc(totalsz);

	if (list == NULL) {
		xlog_error("malloc(3) errno %d", errno);
		ret = ENOMEM;
		goto end;
	}

	list->n = n;

	for (size_t i = 0; i < n; i++)
		list->streams[i] = (struct Stream){0};

	for (size_t i = 0; i < n; i++) {
		const char *name = json_object_get_name(o, i);
		const JSON_Value *v = json_object_get_value_at(o, i);

		if (name == NULL) {
			xlog_error("unexpected null name at index %zu", i);
			goto end;
		}

		if (v == NULL) {
			xlog_error("unexpected null JSON_Value at index %zu",
				   i);
			goto end;
		}

		const JSON_Object *so = json_value_get_object(v);

		if (so == NULL) {
			xlog_error("unexpected null JSON_Object at index %zu",
				   i);
			goto end;
		}

		ret = convert_stream(so, name, &list->streams[i]);

		if (ret) {
			xlog_error("convert_stream failed");
			goto end;
		}
	}

	*streams = list;
	ret = 0;
end:
	if (ret != 0) {
		free_stream_list(list);
	}
	return ret;
}

struct Deployment *
create_empty_deployment(void)
{
	struct Deployment *deployment = xcalloc(1, sizeof(struct Deployment));
	deployment->instanceSpecs = xcalloc(1, sizeof(struct InstanceSpecs));
	deployment->modules = xcalloc(1, sizeof(struct ModuleList));
	deployment->subscribe_topics = xcalloc(1, sizeof(struct TopicList));
	deployment->publish_topics = xcalloc(1, sizeof(struct TopicList));
	deployment->deploymentId = NULL;
	return deployment;
}

int
create_deployment(const JSON_Object *obj, struct Deployment **resultp,
		  const JSON_Object **specs, const JSON_Object **modules)
{
	int ret;
	struct Deployment *deploy;
	JSON_Object *subscribe_topics;
	JSON_Object *publish_topics;
	const char *id = json_object_get_string(obj, "deploymentId");
	*specs = json_object_get_object(obj, "instanceSpecs");
	*modules = json_object_get_object(obj, "modules");
	subscribe_topics = json_object_get_object(obj, "subscribeTopics");
	publish_topics = json_object_get_object(obj, "publishTopics");

	if (*specs == NULL || *modules == NULL) {
		xlog_error("deployment with no specs or modules");
		return EINVAL;
	}

	*resultp = deploy = xcalloc(1, sizeof(*deploy));
	if (id != NULL) {
		deploy->deploymentId = xstrdup(id);
	} else {
		deploy->deploymentId = NULL;
	}

	// subscribeTopics entry is optional by now
	// todo: enforce subscribeTopics once it used in all e2e tests
	if (subscribe_topics != NULL) {
		ret = convert_topic_list(subscribe_topics,
					 &deploy->subscribe_topics);
		if (ret != 0) {
			xlog_error("cannot convert subscribe topic list");
			return ret;
		}
	}
	// publishTopics entry is optional by now
	// todo: enforce publishTopics once it used in all e2e tests
	if (publish_topics != NULL) {
		ret = convert_topic_list(publish_topics,
					 &deploy->publish_topics);
		if (ret != 0) {
			xlog_error("cannot convert publish topic list");
			return ret;
		}
	}

	return 0;
}

static int
convert_module_init(const JSON_Object *obj, struct Module *m)
{
	const char *url = json_object_get_string(obj, "downloadUrl");
	const char *temphash;
	if (url == NULL || strlen(url) == 0 ||
	    strcmp("EVP-BACKDOOR", url) == 0) {
		// If downloadUrl is missing, empty or set to "EVP-BACKDOOR"
		// then the agent should not download the module.
		// Used in EVP2 backdoor feature.
		m->downloadUrl = NULL;
		m->hash = NULL;
		m->hashLen = 0;
		temphash = NULL;
	} else {
		m->downloadUrl = xstrdup(url);
		temphash = json_object_get_string(obj, "hash");
		if (temphash == NULL) {
			return EINVAL;
		}
	}

	int ret = 0;
	if (temphash != NULL) {
		size_t hash_str_len = strlen(temphash);
		size_t hash_byte_len = hash_str_len / 2;
		m->hash = xmalloc(hash_byte_len);
		m->hashLen = hash_byte_len;
		ret = hexstr_to_char(temphash, m->hash, hash_byte_len);
		if (ret) {
			xlog_error("Failed to parse hash '%s' (len=%zu)",
				   temphash, hash_str_len);
		}
	}
	return ret;
}

static size_t
convert_module_list_init(const JSON_Object *obj, struct ModuleList **resultp)
{
	struct ModuleList *list;
	size_t n = json_object_get_count(obj);

	list = xcalloc(1, sizeof(*list) + n * sizeof(*list->modules));
	list->n = n;
	*resultp = list;
	return n;
}

static const char *
get_entrypoint(const struct ModuleList *modules, const char *moduleId)
{
	for (size_t i = 0; i < modules->n; i++) {
		const struct Module *m = &modules->modules[i];

		if (strcmp(m->moduleId, moduleId) == 0) {
			return m->entryPoint;
		}
	}

	return NULL;
}

static int
append_instance_spec(const struct ModuleInstanceSpec *instance,
		     struct InstanceSpecs **out)
{
	struct InstanceSpecs *specs = *out;
	size_t sz =
		sizeof(*specs) + sizeof(*specs->instances) * (specs->n + 1);
	struct InstanceSpecs *s = realloc(specs, sz);

	if (s == NULL) {
		int ret = errno;

		xlog_error("realloc(3) failed with %d", errno);
		return ret;
	}

	s->instances[s->n++] = *instance;
	*out = s;
	return 0;
}

static int
parse_instance_specs_evp1(const char *name, const JSON_Object *o,
			  const struct ModuleList *modules,
			  struct ModuleInstanceSpec *out)
{
	int ret = EINVAL;
	struct ModuleInstanceSpec instance = {0};
	const char *moduleId = json_object_get_string(o, "moduleId");
	const JSON_Value *v = json_object_get_value(o, "version");

	if (v == NULL) {
		xlog_error("missing version");
		goto failure;
	}

	instance.version = json_value_get_number(v);

	/* Check instance has valid values */
	if (o == NULL || moduleId == NULL ||
	    !strncmp(name, g_reserved_prefix, strlen(g_reserved_prefix))) {
		xlog_error("invalid or empty moduleId");
		goto failure;
	}

	const char *entryPoint = json_object_get_string(o, "entryPoint");

	if (entryPoint == NULL) {
		xlog_error("json_object_get_string entryPoint failed");
		goto failure;
	}

	instance.entryPoint = strdup(entryPoint);

	if (instance.entryPoint == NULL) {
		ret = errno;
		xlog_error("strdup(3) entryPoint failed with %d", errno);
		goto failure;
	}

	ret = convert_topic_alias_list(o, "publish", &instance.publish);

	if (ret != 0) {
		xlog_error("convert_topic_alias_list publish failed with %d",
			   ret);
		goto failure;
	}

	ret = convert_topic_alias_list(o, "subscribe", &instance.subscribe);

	if (ret != 0) {
		xlog_error("convert_topic_alias_list subscribe failed with %d",
			   ret);
		goto failure;
	}

	instance.name = strdup(name);

	if (instance.name == NULL) {
		ret = errno;
		xlog_error("strdup(3) name failed with %d", errno);
		goto failure;
	}

	instance.moduleId = strdup(moduleId);

	if (instance.moduleId == NULL) {
		ret = errno;
		xlog_error("strdup(3) moduleId failed with %d", errno);
		goto failure;
	}

	/* ignore "restartPolicy" */

	/* Perform parse-time validations on the instance spec.
	 * This enables setting the failureMessage field
	 * before an attempt to start the instance is made.*/
	ret = instance_spec_extra_parse_evp1(&instance, o);
	if (ret != 0) {
		goto failure;
	}

	*out = instance;
	return 0;

failure:
	free_module_instance_spec(&instance);
	return ret;
}

static int
convert_single_instance_specs_evp1(const char *name, const JSON_Object *o,
				   const struct ModuleList *modules,
				   struct InstanceSpecs **out)
{
	struct ModuleInstanceSpec instance = {0};
	int ret = parse_instance_specs_evp1(name, o, modules, &instance);

	if (ret != 0) {
		xlog_error("parse_instance_specs_evp1 failed "
			   "with %d",
			   ret);
		goto failure;
	}

	ret = append_instance_spec(&instance, out);

	if (ret != 0) {
		xlog_error("append_instance_spec failed with %d", ret);
		goto failure;
	}

	return 0;

failure:
	free_module_instance_spec(&instance);
	return ret;
}

/**
 * @brief
 * Parse json object `obj`and fill the instanceSpecs list `resultp`.
 *
 * @param obj           pointer to valid json object containing the
 * instanceSpecs
 * @param resultp       where to allocate the instanceSpec list
 * @modules             (Only for EVP2) pointer to valid modules list
 *
 * @return      0 if success, otherwise an error code
 */
int
convert_instance_specs_evp1(const JSON_Object *obj,
			    struct InstanceSpecs **resultp,
			    struct ModuleList *modules)
{
	int ret = 0;
	struct InstanceSpecs *specs = malloc(sizeof(*specs));

	if (specs == NULL) {
		ret = errno;
		xlog_error("malloc(3) failed with %d", errno);
		goto end;
	}

	*specs = (struct InstanceSpecs){0};

	for (size_t i = 0; i < json_object_get_count(obj); i++) {
		const JSON_Value *v = json_object_get_value_at(obj, i);

		if (v == NULL) {
			xlog_error("json_object_get_value_at %zu failed", i);
			ret = EINVAL;
			goto end;
		}

		const JSON_Object *o = json_value_get_object(v);

		if (o == NULL) {
			xlog_error("json_value_get_object failed");
			ret = EINVAL;
			goto end;
		}

		const char *name = json_object_get_name(obj, i);

		if (name == NULL) {
			xlog_error("json_object_get_name %zu failed", i);
			ret = EINVAL;
			goto end;
		}

		ret = convert_single_instance_specs_evp1(name, o, modules,
							 &specs);

		if (ret != 0) {
			xlog_error("convert_single_instance_specs_evp1 failed "
				   "with %d",
				   ret);
			goto end;
		}
	}

	*resultp = specs;

end:
	if (ret) {
		free_instance_specs(specs);
	}

	return ret;
}

static int
parse_instance_specs_evp2(const char *name, const JSON_Object *o,
			  const struct ModuleList *modules,
			  struct ModuleInstanceSpec *out)
{
	int ret = EINVAL;
	struct ModuleInstanceSpec instance = {0};
	const char *moduleId = json_object_get_string(o, "moduleId");

	/* Check instance has valid values */
	if (o == NULL || moduleId == NULL ||
	    !strncmp(name, g_reserved_prefix, strlen(g_reserved_prefix))) {
		xlog_error("invalid or empty moduleId");
		goto failure;
	}

	const char *entryPoint = get_entrypoint(modules, moduleId);

	if (entryPoint == NULL) {
		xlog_error("get_entrypoint failed");
		goto failure;
	}

	if (strlen(entryPoint) == 0) {
		xlog_error("get_entrypoint failed. Entypoint %s too short. At "
			   "least has to be 1 char length.",
			   entryPoint);
		goto failure;
	}

	instance.entryPoint = strdup(entryPoint);

	if (instance.entryPoint == NULL) {
		ret = errno;
		xlog_error("strdup(3) entryPoint failed with %d", errno);
		goto failure;
	}

	ret = convert_topic_alias_list(o, "publish", &instance.publish);

	if (ret != 0) {
		xlog_error("convert_topic_alias_list publish failed with %d",
			   ret);
		goto failure;
	}

	ret = convert_topic_alias_list(o, "subscribe", &instance.subscribe);

	if (ret != 0) {
		xlog_error("convert_topic_alias_list subscribe failed with %d",
			   ret);
		goto failure;
	}

	instance.name = strdup(name);

	if (instance.name == NULL) {
		ret = errno;
		xlog_error("strdup(3) name failed with %d", errno);
		goto failure;
	}

	instance.moduleId = strdup(moduleId);

	if (instance.moduleId == NULL) {
		ret = errno;
		xlog_error("strdup(3) moduleId failed with %d", errno);
		goto failure;
	}

	/* ignore "restartPolicy" */

	/* Perform parse-time validations on the instance spec.
	 * This enables setting the failureMessage field
	 * before an attempt to start the instance is made.*/
	ret = instance_spec_extra_parse_evp2(&instance, o);
	if (ret != 0) {
		goto failure;
	}

	const JSON_Object *streams = json_object_get_object(o, "streams");
	if (streams != NULL) {
		ret = convert_streams(streams, &instance.streams);
		if (ret != 0) {
			xlog_error("cannot convert streams");
			goto failure;
		}
	}

	/* For EVP2 this field is ignored. todo: Remove from struct? */
	instance.version = 1;
	*out = instance;
	return 0;

failure:
	free_module_instance_spec(&instance);
	return ret;
}

static int
convert_single_instance_specs_evp2(const char *name, const JSON_Object *o,
				   const struct ModuleList *modules,
				   struct InstanceSpecs **out)
{
	struct ModuleInstanceSpec instance = {0};
	int ret = parse_instance_specs_evp2(name, o, modules, &instance);

	if (ret != 0) {
		xlog_error("parse_instance_specs_evp2 failed "
			   "with %d",
			   ret);
		goto failure;
	}

	ret = append_instance_spec(&instance, out);

	if (ret != 0) {
		xlog_error("append_instance_spec failed with %d", ret);
		goto failure;
	}

	return 0;

failure:
	free_module_instance_spec(&instance);
	return ret;
}

/**
 * @brief
 * Parse json object `obj`and fill the instanceSpecs list `resultp`.
 * For EVP2 the entryPoint is read from modules list `modules`.
 *
 * @param obj           pointer to valid json object containing the
 * instanceSpecs
 * @param resultp       where to allocate the instanceSpec list
 * @modules             (Only for EVP2) pointer to valid modules list
 *
 * @return      0 if success, otherwise an error code
 */
int
convert_instance_specs_evp2(const JSON_Object *obj,
			    struct InstanceSpecs **resultp,
			    const struct ModuleList *modules)
{
	int ret = 0;
	struct InstanceSpecs *specs = malloc(sizeof(*specs));

	if (specs == NULL) {
		ret = errno;
		xlog_error("malloc(3) failed with %d", errno);
		goto end;
	}

	*specs = (struct InstanceSpecs){0};

	for (size_t i = 0; i < json_object_get_count(obj); i++) {
		const JSON_Value *v = json_object_get_value_at(obj, i);

		if (v == NULL) {
			xlog_error("json_object_get_value_at %zu failed", i);
			ret = EINVAL;
			goto end;
		}

		const JSON_Object *o = json_value_get_object(v);

		if (o == NULL) {
			xlog_error("json_value_get_object failed");
			ret = EINVAL;
			goto end;
		}

		const char *name = json_object_get_name(obj, i);

		if (name == NULL) {
			xlog_error("json_object_get_name %zu failed", i);
			ret = EINVAL;
			goto end;
		}

		ret = convert_single_instance_specs_evp2(name, o, modules,
							 &specs);

		if (ret != 0) {
			xlog_error("convert_single_instance_specs_evp2 failed "
				   "with %d",
				   ret);
			goto end;
		}
	}

	*resultp = specs;

end:
	if (ret) {
		free_instance_specs(specs);
	}

	return ret;
}

bool
module_impl_valid(const char *moduleImpl)
{
	const char *validImpl[] = {"docker", "wasm",   "dlfcn",
				   "spawn",  "python", NULL};

	const char **cur = validImpl;
	while (*cur != NULL) {
		if (strcmp(moduleImpl, *cur) == 0)
			return true;
		cur++;
	}

	return false;
}

int
convert_module_evp1(const JSON_Object *obj, struct Module *m)
{
	int ret = convert_module_init(obj, m);
	if (ret) {
		return ret;
	}

	const char *moduleImpl = json_object_get_string(obj, "moduleImpl");
	if (moduleImpl != NULL) {
		m->moduleImpl = xstrdup(moduleImpl);
	}

	return 0;
}

int
convert_module_evp2(const JSON_Object *obj, struct Module *m)
{
	int ret = convert_module_init(obj, m);
	if (ret) {
		return ret;
	}

	const char *moduleImpl = json_object_get_string(obj, "moduleImpl");
	/* For EVP2 moduleImpl is mandatory */
	if (moduleImpl == NULL || !module_impl_valid(moduleImpl)) {
		return EINVAL;
	}
	m->moduleImpl = xstrdup(moduleImpl);

	const char *entryPoint = json_object_get_string(obj, "entryPoint");
	if (entryPoint == NULL) {
		return EINVAL;
	}
	m->entryPoint = xstrdup(entryPoint);

	return 0;
}

static const JSON_Object *
convert_module_id(const JSON_Object *obj, struct Module *m, unsigned int i)
{
	const char *name = json_object_get_name(obj, i);
	const JSON_Value *v = json_object_get_value_at(obj, i);
	obj = json_value_get_object(v);
	if (obj == NULL) {
		return NULL;
	}

	m->moduleId = xstrdup(name);
	return obj;
}

int
convert_module_list_evp1(const JSON_Object *obj, struct ModuleList **resultp)
{
	size_t n = convert_module_list_init(obj, resultp);
	struct ModuleList *list = *resultp;
	unsigned int i;
	for (i = 0; i < n; i++) {
		struct Module *m = &list->modules[i];
		const JSON_Object *o = convert_module_id(obj, m, i);
		if (o == NULL) {
			return EINVAL;
		}
		int ret = convert_module_evp1(o, m);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int
convert_module_list_evp2(const JSON_Object *obj, struct ModuleList **resultp)
{
	size_t n = convert_module_list_init(obj, resultp);
	struct ModuleList *list = *resultp;
	unsigned int i;
	for (i = 0; i < n; i++) {
		struct Module *m = &list->modules[i];
		const JSON_Object *o = convert_module_id(obj, m, i);
		if (o == NULL) {
			return EINVAL;
		}
		int ret = convert_module_evp2(o, m);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

int
convert_deployment_evp1(const JSON_Object *obj, struct Deployment **resultp)
{
	const JSON_Object *specs, *modules;
	struct Deployment *deploy = NULL;
	int ret;

	ret = create_deployment(obj, &deploy, &specs, &modules);
	if (ret) {
		goto end;
	}

	/* First parse modules, because instanceSpecs parser needs information
	 * from modules. */
	ret = convert_module_list_evp1(modules, &deploy->modules);
	if (ret != 0) {
		xlog_error("cannot convert module list");
		goto end;
	}

	ret = convert_instance_specs_evp1(specs, &deploy->instanceSpecs,
					  deploy->modules);
	if (ret != 0) {
		xlog_error("cannot convert instance specs");
		goto end;
	}

	*resultp = deploy;

end:
	if (ret != 0) {
		free_deployment(deploy);
	}

	return ret;
}

int
convert_deployment_evp2(const JSON_Object *obj, struct Deployment **resultp)
{
	const JSON_Object *specs, *modules;
	struct Deployment *deploy = NULL;
	int ret;

	ret = create_deployment(obj, &deploy, &specs, &modules);
	if (ret) {
		goto end;
	}

	/* First parse modules, because instanceSpecs parser needs information
	 * from modules. */
	ret = convert_module_list_evp2(modules, &deploy->modules);
	if (ret != 0) {
		xlog_error("cannot convert module list");
		goto end;
	}

	ret = convert_instance_specs_evp2(specs, &deploy->instanceSpecs,
					  deploy->modules);
	if (ret != 0) {
		xlog_error("cannot convert instance specs");
		goto end;
	}

	*resultp = deploy;

end:
	if (ret != 0) {
		free_deployment(deploy);
	}

	return ret;
}

static void
set_desired_value(const char *key, JSON_Value *value)
{
	JSON_Object *obj = json_value_get_object(g_evp_global.desired);
	if (value == NULL || json_value_get_type(value) == JSONNull) {
		json_object_remove(obj, key);
	} else {
		value = json_value_deep_copy(value);
		json_object_set_value(obj, key, value);
	}
}

int
parse_deployment_evp1(JSON_Value *value, struct Deployment **resultp)
{
	const JSON_Object *obj;
	int ret;
	const char *json_str = json_value_get_string(value);
	value = json_parse_string(json_str);
	if (value == NULL) {
		xlog_warning("got invalid payload: %s", json_str);
		ret = EINVAL;
	}
	obj = json_value_get_object(value);
	if (obj == NULL) {
		ret = EINVAL;
	} else {
		ret = convert_deployment_evp1(obj, resultp);
	}
	json_value_free(value);
	return ret;
}

int
parse_deployment_evp2(JSON_Value *value, struct Deployment **resultp)
{
	const JSON_Object *obj;
	int ret;
	obj = json_value_get_object(value);
	if (obj == NULL) {
		ret = EINVAL;
	} else {
		ret = convert_deployment_evp2(obj, resultp);
	}
	return ret;
}

void
dump_global(void)
{
	if (g_evp_global.desired) {
		char *p =
			json_serialize_to_string_pretty(g_evp_global.desired);
		xlog_info("DESIRED: %s", p);
		json_free_serialized_string(p);
	}
	if (g_evp_global.current) {
		char *p =
			json_serialize_to_string_pretty(g_evp_global.current);
		xlog_info("CURRENT: %s", p);
		json_free_serialized_string(p);
	}
}

int
try_load_deployment(JSON_Value *json, JSON_Value **vp)
{
	JSON_Object *o;
	JSON_Value *v;

	o = json_value_get_object(json);
	v = json_object_get_value(o, "deployment");
	if (!v)
		return -1;
	*vp = v;
	return 0;
}

void
save_deployment(struct evp_agent_context *agent, JSON_Value *deployment)
{
	set_desired_value("deployment", deployment);
	save_desired(agent);
	dump_global();
}

enum sdk_msg_topic_type
topic_type_string_to_enum(const char *type)
{
	if (strcmp(type, "local") == 0) {
		return SDK_MSG_TOPIC_TYPE_LOCAL;
	}
	return SDK_MSG_TOPIC_TYPE_ERROR;
}
