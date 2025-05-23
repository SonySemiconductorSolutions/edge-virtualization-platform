/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Mock module implementation for unit tests
 */
#include <errno.h>

#include "cdefs.h"
#include "manifest.h"
#include "module_impl.h"
#include "module_impl_ops.h"

static bool
impl_loaded(const struct module *m)
{
	return true;
}

static bool
impl_downloading(const struct module *m)
{
	return false;
}

static int
impl_download_cancel(struct module *m)
{
	return 0;
}

static int
impl_load(struct module *m, const struct Module *modspec)
{
	return 0;
}

static void
impl_unload(struct module *m)
{
}

static void
impl_init(void *p)
{
}

static void *
impl_handle(const struct module *m)
{
	return __UNCONST(m);
}

static void
impl_prune(void)
{
}

static void
impl_destroy(void)
{
}

extern const struct module_instance_impl_ops module_instance_impl_ops_docker;

const struct module_impl_ops __wrap_module_impl_ops_docker = {
	.name = "docker",
	.loaded = impl_loaded,
	.downloading = impl_downloading,
	.download_cancel = impl_download_cancel,
	.load = impl_load,
	.unload = impl_unload,
	.handle = impl_handle,
	.init = impl_init,
	.prune = impl_prune,
	.destroy = impl_destroy,
	.instance = &module_instance_impl_ops_docker};
