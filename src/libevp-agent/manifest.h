/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This file contains the definitions for the agent-internal C-friendly
 * representation of DeploymentManifest
 *
 * The agent converts the on-wire JSON representation of DeploymentManifest
 * to this representation so that the further processing doesn't need to
 * deal with parson.
 * (An obvious alternative is simply to use parson structures directly,
 * as we do for other things like DeploymentStatus.)
 */

#if !defined(__MANIFEST_H__)
#define __MANIFEST_H__
#include <config.h>

#include <stddef.h>
#include <stdint.h>

#include <parson.h>

#include "stream/stream.h"

#if defined(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_RAW_CONTAINER_SPEC)
#define RAW_CONTAINER_SPEC
#endif

/*
 * InstanceSpec looks like the following.
 *
 * Note that JSON objects are used in two different ways in this schema:
 *  - An unordered list of named objects
 *  - A structure with named fields
 *
 * {
 *   "SPL": {
 *     "moduleId": "SPL-111",
 *     "entryPoint": ...
 *     "restartPolicy": "Always",
 *     "subscribe": [],
 *     "publish": {
 *       "to-ppl": "local-topic-for-publish"
 *     }
 *   },
 *   "PPL": {
 *     "moduleId": "PPL-222",
 *     "entryPoint": ...
 *     "restartPolicy": "Always",
 *     "subscribe": {
 *       "from-spl": "local-topic-for-subscribe"
 *     }
 *   }
 * }
 *
 * a Deployment looks like the following.
 *
 * {
 *   "instanceSpecs": {
 *        :
 *        :
 *   },
 *   "modules": {
 *     "SPL-111": {
 *       "downloadUrl": ...
 *       "vars": ...
 *     },
 *     "PPL-222": {
 *       "downloadUrl": ...
 *       "vars": ...
 *     }
 *   }
 * }
 * "publish_topics": {
 *   "local-topic-for-publish": {
 *       "type": "local",
 *       "topic": "spl-to-ppl"
 *     }
 *   },
 * "subscribe_topics": {
 *   "local-topic-for-subscribe": {
 *       "type": "local",
 *       "topic": "spl-to-ppl"
 *   }
 * }
 */

struct evp_agent_context;

/*
 * a scalar internal value for
 * .{subscribe|publish}_topics.<name>.type of JSON manifest
 */
enum sdk_msg_topic_type {
	SDK_MSG_TOPIC_TYPE_ERROR = -1,
	SDK_MSG_TOPIC_TYPE_LOCAL = 1,
};

struct TopicAlias {
	char *alias;
	char *topic;
};

struct TopicAliasList {
	size_t n;
	struct TopicAlias aliases[];
};

struct StreamList {
	size_t n;
	struct Stream streams[];
};

struct ModuleInstanceSpec {
	char *name;
	char *moduleId;
	char *entryPoint;
	/* Only valid for EVP1. For EVP2 it is hardcoded to 1 */
	uint32_t version;
	struct TopicAliasList *subscribe;
	struct TopicAliasList *publish;
	struct StreamList *streams;
#if defined(RAW_CONTAINER_SPEC)
	JSON_Value *rawContainerSpec;
#endif
	char *failureMessage;
};

struct InstanceSpecs {
	size_t n;
	struct ModuleInstanceSpec instances[];
};

struct Module {
	char *moduleId;
	char *moduleImpl;
	char *downloadUrl;
	unsigned char *hash;
	size_t hashLen;
	char *entryPoint;
};

struct ModuleList {
	size_t n;
	struct Module modules[];
};

struct Topic {
	char *name;
	char *type;
	char *topic;
};

struct TopicList {
	size_t n;
	struct Topic topics[];
};

struct Deployment {
	char *deploymentId;
	struct InstanceSpecs *instanceSpecs;
	struct ModuleList *modules;
	struct TopicList *subscribe_topics;
	struct TopicList *publish_topics;
};

struct Deployment *create_empty_deployment(void);
int create_deployment(const JSON_Object *obj, struct Deployment **resultp,
		      const JSON_Object **specs, const JSON_Object **modules);
int try_load_deployment(JSON_Value *json, JSON_Value **vp);
void save_deployment(struct evp_agent_context *agent, JSON_Value *deployment);
int parse_deployment_evp1(JSON_Value *, struct Deployment **);
int parse_deployment_evp2(JSON_Value *, struct Deployment **);
void free_deployment(struct Deployment *);
enum sdk_msg_topic_type topic_type_string_to_enum(const char *type);
#endif /* !defined(__MANIFEST_H__) */
