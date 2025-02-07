/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__PATH_H__)
#define __PATH_H__

/*
 * Path definitions
 *
 * Paths within the "host" namespace, for platforms where
 * multiple namespaces are used.
 */

#include "path_common.h"

/*
 * DATA_DIR is the top level directory for EVP agent to store
 * persistent data.
 *
 * The following sub directories are hardcoded in the EVP agent:
 *
 *    instances    See MODULE_INSTANCE_DIR
 *    modules      See MODULE_DIR in module_impl_obj.c
 *
 * The following sub directories are used by test code, including run2.sh.
 * The EVP agent doesn't have hardcoded knowledge about these directories:
 *
 *    cert2        Used to store certs and keys for
 *                 EVP_MQTT_TLS_CLIENT_CERT and others.
 *
 * Other possible future usage of DATA_DIR includes:
 *
 * - Certificate cache for EVP_BLOB_TYPE_EVP
 */

/*
 * MODULE_INSTANCE_DIR is used for per module instance data.
 *
 * It's used to implement module instance workspaces.
 * cf. EVP_getWorkspaceDirectory
 * For EVP_WORKSPACE_TYPE_DEFAULT, the following path is used.
 *
 *    $MODULE_INSTANCE_DIR/$MODULE_INSTANCE_NAME/$DEFAULT_WORKSPACE_DIR
 *
 * If EVP_SDK_SOCKET is enabled, it's also used for the unix domain socket
 * for the SDK communication.
 *
 *    $MODULE_INSTANCE_DIR/$MODULE_INSTANCE_NAME/$SDK_SOCKET_NAME
 */

enum path_id {
	TWINS_PATH_ID,
	DESIRED_TWINS_PATH_ID,
	CURRENT_TWINS_PATH_ID,
	MODULE_PATH_ID,
	MODULE_INSTANCE_PATH_ID,
	CACHE_PATH_ID,
	PATH_ID_COUNT
};

void path_init(const char *data_dir);
const char *path_get(enum path_id pid);
void path_free(void);
char *path_get_module(const char *module_id);

#endif /* !defined(__PATH_H__) */
