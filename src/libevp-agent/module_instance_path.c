/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "module_instance.h"
#include "path.h"
#include "path_docker.h"

int
convert_module_instance_path(const char *module_instance_name,
			     const char *path_in_module_instance,
			     char *path_for_agent, size_t n)
{
	const char *module_instance_dir = path_get(MODULE_INSTANCE_PATH_ID);
	const char *prefix = DOCKER_DEFAULT_WORKSPACE_PATH;
	size_t prefix_len = strlen(prefix);

	if (n == 0) {
		return EINVAL;
	}

	if (strncmp(path_in_module_instance, prefix, prefix_len)) {
		return EPERM;
	}
	if (strstr(path_in_module_instance, "..")) { /* XXX a bit loose */
		return EPERM;
	}
	int ret =
		snprintf(path_for_agent, n, "%s/%s/%s/%s", module_instance_dir,
			 module_instance_name, DEFAULT_WORKSPACE_DIR,
			 &path_in_module_instance[prefix_len]);
	if (ret < 0) {
		return EIO;
	}

	if ((unsigned)ret > n - 1) {
		return E2BIG;
	}

	return 0;
}
