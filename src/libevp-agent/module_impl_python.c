/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * posix_spawn-based module implementation for Linux
 */
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <internal/util.h>

#include "module.h"
#include "module_impl.h"
#include "module_impl_obj.h"
#include "module_impl_ops.h"
#include "path.h"
#include "xlog.h"

extern const struct module_instance_impl_ops module_instance_impl_ops_python;

bool module_impl_spawn_loaded(const struct module *m);
int module_impl_spawn_load_obj(struct module *m, const char *module_id);
void module_impl_spawn_unload(struct module *m);
void *module_impl_spawn_handle(const struct module *m);

const struct module_impl_ops module_impl_ops_python = {
	.name = "python",
	.downloading = module_impl_obj_downloading,
	.download_cancel = module_impl_obj_download_cancel,
	.load = module_impl_obj_load,
	.prune = module_impl_obj_prune,
	.init = module_impl_obj_init,
	.destroy = module_impl_obj_destroy,
	.handle = module_impl_spawn_handle,
	.loaded = module_impl_spawn_loaded,
	.load_obj = module_impl_spawn_load_obj,
	.unload = module_impl_spawn_unload,
	.instance = &module_instance_impl_ops_python,
};
