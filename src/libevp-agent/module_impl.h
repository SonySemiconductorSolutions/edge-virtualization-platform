/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <stdbool.h>
#include <stddef.h>

#include "xpthread.h"

#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
#include <wasm_export.h>
#endif

struct module {
	const struct module_impl_ops *ops;
	const char *moduleId;
#if defined(CONFIG_EVP_MODULE_IMPL_OBJ)
	struct blob_work *blob_work;
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DLFCN) ||                                  \
	defined(CONFIG_EVP_MODULE_IMPL_SPAWN) ||                              \
	defined(CONFIG_EVP_MODULE_IMPL_PYTHON)
	void *handle; /* what dlopen returned */
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	const char *image;
	struct docker_op *docker_op;
#endif
#if defined(CONFIG_EVP_MODULE_IMPL_WASM)
	bool is_downloaded;
#endif
	struct evp_lock *failureMessageMutex;
	char *failureMessage;
};
