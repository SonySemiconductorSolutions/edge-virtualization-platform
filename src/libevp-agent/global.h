/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

#include "path.h"
#include "xpthread.h"

struct map;

struct global {
	/*
	 * persisted keys in desired:
	 *
	 *   "deployment" (JSONString)
	 *        DeploymentManifest
	 *
	 *   "configuration/<module instance>/<topic>" (JSONString)
	 *        EVP Configuration
	 *
	 * persisted keys in current:
	 *
	 *   "state/<module instance>/<topic>" (JSONString)
	 *        EVP Configuration
	 */

	JSON_Value *desired;         // shared attributes
	JSON_Value *current;         // client attributes (our current state)
	JSON_Value *instance_states; // Module instance states
	size_t instance_states_len;
	struct evp_lock instance_states_lock;
	/*
	 * Reconcile status
	 */

	const char *deploymentId;
	const char *reconcileStatus;

	/*
	 * Device configuration
	 */
	struct device_config *devcfg;

	/*
	 * Module instance configs
	 */
	struct map *instancecfg;

	/*
	 * Filesystem paths
	 */
	char *paths[PATH_ID_COUNT];
};

extern struct global g_evp_global;
