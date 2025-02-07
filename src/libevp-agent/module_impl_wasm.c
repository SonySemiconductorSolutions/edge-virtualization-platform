/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Overview:
 *
 * This file contains the logic to load wasm-based EVP module.
 * (either wasm bytecode or AoT)
 *
 * A module is a single file.
 * The management of the file (downloading/caching/etc) is
 * implemented in module_impl_obj.c.
 *
 * Once loaded into a memory buffer, the module is loaded with
 * wasm-micro-runtime. (namely wasm_runtime_load)
 *
 * The wasm-micro-runtime library takes care of the module type
 * differences (wasm bytecode and AoT) automatically.
 */

#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>

#include <wasm_export.h>

#include <internal/util.h>

#include "fsutil.h"
#include "module.h"
#include "module_api_wasm.h"
#include "module_impl.h"
#include "module_impl_obj.h"
#include "module_impl_ops.h"
#include "platform.h"
#include "xlog.h"

static bool
impl_loaded(const struct module *m)
{
	/* This is checked on every agent loop iteration, via
	 * module_prune() and module_load(), hence it needs to
	 * be very light.
	 */
	return m->is_downloaded;
}

static int
impl_load_obj(struct module *m, const char *filename)
{
	m->is_downloaded = false;

	int error = 0;
	size_t wasm_binary_size = 0;
	const void *wasm_binary;
	struct mod_fs_mmap_handle *wasm_module_mmap_handle =
		plat_mod_fs_file_mmap(m, &wasm_binary, &wasm_binary_size,
				      false, &error);
	if (wasm_module_mmap_handle != NULL) {
		if (wasm_binary != NULL && wasm_binary_size > 0) {
			/* At this point, the image has been verified to load
			 * correctly.
			 */
			m->is_downloaded = true;
		}
		plat_mod_fs_file_munmap(wasm_module_mmap_handle);

	} else if (error != ENOENT) {
		/* ENOENT means the file was not found */
		xlog_error("Possible system error (%d), or module image is "
			   "of size 0, for %s",
			   error, m->moduleId);
	}

	return m->is_downloaded ? 0 : error;
}

static void
impl_unload(struct module *m)
{
	/* TODO : Revisit to confirm the sequence.
	 *        Also, maybe this should be moved into
	 *        module_impl_obj.c to match calls to
	 *        flash_file_write()
	 */
	plat_mod_fs_file_unlink(m);
	m->is_downloaded = false;
}

static void *
impl_handle(const struct module *m)
{
	return m->is_downloaded ? __UNCONST(m) : NULL;
}

static void
impl_init(void *param)
{
	module_api_init_wasm();
	module_impl_obj_init(param);
}

static void
impl_destroy(void)
{
	wasm_runtime_destroy();
}

extern const struct module_instance_impl_ops module_instance_impl_ops_wasm;

const struct module_impl_ops module_impl_ops_wasm = {
	.name = "wasm",
	.downloading = module_impl_obj_downloading,
	.download_cancel = module_impl_obj_download_cancel,
	.load = module_impl_obj_load,
	.prune = module_impl_obj_prune,
	.destroy = impl_destroy,
	.handle = impl_handle,
	.init = impl_init,
	.loaded = impl_loaded,
	.load_obj = impl_load_obj,
	.unload = impl_unload,
	.instance = &module_instance_impl_ops_wasm};
