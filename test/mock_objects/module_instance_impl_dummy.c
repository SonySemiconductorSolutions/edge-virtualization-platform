/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Mock module instance implementation for unit tests
 */

#include <errno.h>

#include "manifest.h"
#include "module_impl.h"
#include "module_instance_impl_ops.h"

static int
impl_start(struct module_instance *m, const struct ModuleInstanceSpec *spec,
	   const char *workspace, void *handle)
{
	return 0;
}

static int
impl_stop(struct module_instance *m)
{
	return 0;
}

static bool
impl_is_running(struct module_instance *m)
{
	return true;
}

static bool
impl_has_stopped(struct module_instance *m)
{
	return false;
}

static const char *
impl_stat(struct module_instance *m)
{
	return NULL;
}

static int
impl_init(void)
{
	return 0;
}

static int
impl_convert_path(struct module_instance *m,
		  const char *path_in_module_instance, char **resultp)
{
	return ENOTSUP;
}

static void
impl_post_create(struct module_instance *m)
{
}

const struct module_instance_impl_ops module_instance_impl_ops_dummy = {
	.name = "dummy",
	.convert_path = impl_convert_path,
	.is_running = impl_is_running,
	.has_stopped = impl_has_stopped,
	.init = impl_init,
	.post_create = impl_post_create,
	.stop = impl_stop,
	.start = impl_start,
	.stat = impl_stat,
};
