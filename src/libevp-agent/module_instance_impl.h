/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <pthread.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include "module_instance_impl_ops.h"

#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
#include "docker.h"
#endif

#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
#include <wasm_export.h>
#endif

#if defined(CONFIG_EVP_SDK_SOCKET)
#include "sdk_worker.h"
#endif

#include <internal/queue.h>

#include "manifest.h"
#include "sdk_agent.h"
#include "xpthread.h"

struct sdk_msg_topic_alias;
typedef TAILQ_HEAD(, sdk_msg_topic_alias) sdk_msg_topic_alias_queue;

// A persistent instance should not be stopped or pruned
#define MODULE_INSTANCE_PERSISTENT 0x01U

enum module_instance_status {
	MODULE_INSTANCE_STATUS_LOADING,
	MODULE_INSTANCE_STATUS_STARTING,
	MODULE_INSTANCE_STATUS_RUNNING,
	MODULE_INSTANCE_STATUS_STOPPED
};

struct module_instance_comparable {
	/* Fields used as map keys */
	const char *name;
	const char *moduleId;
	uint32_t version;
};

struct module_instance {
	/* Fields used as map keys */
	const char *name; /* module instance name */
	const char *moduleId;
	uint32_t version;
	/* Fields used as map values */
	const struct module_impl_ops *ops;
	uint32_t flags;
	char *failureMessage;
	struct EVP_client *sdk_handle;
	sdk_msg_topic_alias_queue
		publish_topic_aliases; /* attributes under
					    ".instanceSpecs.<instance>.publish"
					  of   manifest */
	sdk_msg_topic_alias_queue
		subscribe_topic_aliases; /* attributes under
					    ".instanceSpecs.<instance>.subscribe"
					    of manifest */
	const char *entryPoint;
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                                  \
	defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||                              \
	defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
#if defined(__NuttX__) || defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||            \
	defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	pid_t pid;
	struct timespec stop_request_time;
#else
#error not implemented
#endif /* defined(__NuttX__) || defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||      \
	  defined(CONFIG_EVP_MODULE_IMPL_PYTHON)*/
#endif /* defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                            \
	  defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||                            \
	  defined(CONFIG_EVP_MODULE_IMPL_PYTHON) */
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	struct docker_op *docker_op;
	struct docker_container *cont;
	enum DOCKER_CONTAINER_STATE_STATUS state_status;
	enum DOCKER_CONTAINER_STATE_HEALTH_STATUS state_health_status;
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	pthread_t wasm_runner;
	wasm_module_inst_t wasm_module_inst;
	char *wasm_runner_exception;
	pthread_cond_t exit_condition;
	struct evp_lock lock;
	enum module_instance_status status;
	wasm_module_t wasm_module;
	const void *wasm_binary;
	struct mod_fs_mmap_handle *wasm_module_mmap_handle;
	void *module_buffer;
	int module_buffer_offset;
#endif
#if defined(CONFIG_EVP_SDK_SOCKET)
	struct sdk_socket_context sdk_socket_worker_ctx;
	pthread_t sdk_socket_worker;
	bool thread_created;
#endif
	struct StreamList *streams;
	void *stack;
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER) ||                                 \
	defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                              \
	defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||                              \
	defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	bool stopped;
#endif
};
