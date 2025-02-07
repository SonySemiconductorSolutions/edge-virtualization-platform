/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Mock module implementation for unit tests
 */

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

static int
impl_load_obj(struct module *m, const char *filename)
{
	return 0;
}

const struct module_impl_ops module_impl_ops_dummy = {
	.name = "dummy",
	.downloading = impl_downloading,
	.download_cancel = impl_download_cancel,
	.load = impl_load,
	.prune = impl_prune,
	.init = impl_init,
	.destroy = impl_destroy,
	.handle = impl_handle,
	.loaded = impl_loaded,
	.load_obj = impl_load_obj,
	.unload = impl_unload,
};
