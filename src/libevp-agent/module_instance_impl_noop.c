/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This is a parital implementaion of module_impl_ops.
 *
 * Intended to be used by module impls which don't require
 * path conversions between module instances and the agent.
 */

#include <errno.h>
#include <string.h>

#include "module_instance_impl_noop.h"

int
module_instance_impl_noop_convert_path(struct module_instance *m,
				       const char *path_in_module_instance,
				       char **resultp)
{
	char *path;

	path = strdup(path_in_module_instance);
	if (path == NULL) {
		return ENOMEM;
	}
	*resultp = path;
	return 0;
}
