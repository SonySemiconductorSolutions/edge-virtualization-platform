/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "global.h"
#include "path.h"
#include "xlog.h"

#if !defined(DEFAULT_DATA_DIR)
#if defined(DATA_DIR)
/* TODO: eventually remove deprecated DATA_DIR macro */
#pragma message("DATA_DIR is deprecated, use DEFAULT_DATA_DIR instead")
#define DEFAULT_DATA_DIR DATA_DIR
#else
#define DEFAULT_DATA_DIR "/evp_data"
#endif
#endif

/*
 * TWINS_DIR is used to persist DeplymentManifest, Configuration, and State.
 */

#define TWINS_DIR           "/twins"
#define DESIRED_DIR         TWINS_DIR "/desired"
#define CURRENT_DIR         TWINS_DIR "/current"
#define MODULE_DIR          "/modules"
#define MODULE_INSTANCE_DIR "/instances"
#define CACHE_PATH          "/cache"

static const char *evp_path_subdir[] = {
	/* Default: /evp_data/twins/ */
	[TWINS_PATH_ID] = TWINS_DIR,
	/* Default: /evp_data/twins/desired/ */
	[DESIRED_TWINS_PATH_ID] = DESIRED_DIR,
	/* Default: /evp_data/twins/current/ */
	[CURRENT_TWINS_PATH_ID] = CURRENT_DIR,
	/* Default: /evp_data/modules */
	[MODULE_PATH_ID] = MODULE_DIR,
	/* Default: /evp_data/instances */
	[MODULE_INSTANCE_PATH_ID] = MODULE_INSTANCE_DIR,
	/* Default: /evp_data/cache */
	[CACHE_PATH_ID] = CACHE_PATH,
};

void
path_init(const char *data_dir)
{
	path_free();

	if (!data_dir)
		data_dir = DEFAULT_DATA_DIR;
	for (size_t i = 0; i < PATH_ID_COUNT; i++) {
		const char *sub_dir = evp_path_subdir[i];
		xasprintf(&g_evp_global.paths[i], "%s%s", data_dir, sub_dir);
	}
	xlog_debug("EVP data dir: %s", data_dir);
}

const char *
path_get(enum path_id pid)
{
	// TODO: Replace assert (runtime error)
	assert(pid < PATH_ID_COUNT);
	return g_evp_global.paths[pid];
}

void
path_free(void)
{
	for (size_t i = 0; i < PATH_ID_COUNT; i++) {
		free(g_evp_global.paths[i]);
		g_evp_global.paths[i] = NULL;
	}
}

char *
path_get_module(const char *module_id)
{
	const char *module_dir = path_get(MODULE_PATH_ID);
	char *buf;

	xasprintf(&buf, "%s/%s", module_dir, module_id);

	return buf;
}
