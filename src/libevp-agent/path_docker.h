/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * path inside docker containers
 */

#include "path_common.h"

#define EVP_SHARED_DIR "/evp" /* the directory shared with the agent */
#define DOCKER_DEFAULT_WORKSPACE_PATH                                         \
	(EVP_SHARED_DIR "/" DEFAULT_WORKSPACE_DIR)
#define DOCKER_SDK_SOCKET_PATH (EVP_SHARED_DIR "/" SDK_SOCKET_NAME)
