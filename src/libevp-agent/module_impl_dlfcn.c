/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * dlopen-based implementation for NuttX
 */

#include <sys/stat.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

#include <internal/util.h>

#include "module.h"
#include "module_api_dlfcn.h"
#include "module_impl.h"
#include "module_impl_obj.h"
#include "module_impl_ops.h"

static bool
impl_loaded(const struct module *m)
{
	return m->handle != NULL;
}

static int
impl_load_obj(struct module *m, const char *filename)
{
	m->handle = dlopen(filename, RTLD_NOW);
	if (m->handle == NULL) {
		int ret;
		free(m->failureMessage);
		xasprintf(&m->failureMessage, "dlopen failed (error=%s)",
			  dlerror());
		/*
		 * Detect ENOENT to meet the caller's expectation.
		 * Note: dlopen doesn't necessarily set errno.
		 */
		struct stat st;
		ret = stat(filename, &st);
		if (ret == -1) {
			return errno;
		}
		return EINVAL;
	}
	return 0;
}

static void
impl_unload(struct module *m)
{
	dlclose(m->handle);
	m->handle = NULL;
}

static void *
impl_handle(const struct module *m)
{
	return m->handle;
}

static void
impl_init(void *param)
{
	module_api_init_dlfcn();
	module_impl_obj_init(param);
}

extern const struct module_instance_impl_ops module_instance_impl_ops_dlfcn;

const struct module_impl_ops module_impl_ops_dlfcn = {
	.name = "dlfcn",
	.downloading = module_impl_obj_downloading,
	.download_cancel = module_impl_obj_download_cancel,
	.destroy = module_impl_obj_destroy,
	.handle = impl_handle,
	.init = impl_init,
	.loaded = impl_loaded,
	.load = module_impl_obj_load,
	.load_obj = impl_load_obj,
	.prune = module_impl_obj_prune,
	.unload = impl_unload,
	.instance = &module_instance_impl_ops_dlfcn};
