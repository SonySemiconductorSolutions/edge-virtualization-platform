/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

struct string_map *
string_map_alloc(size_t n, void (*free_fn)(void *))
{
	struct string_map *ret = malloc(sizeof(*ret));
	struct string_map_bucket **bucket;

	if (ret == NULL) {
		return NULL;
	}

	bucket = calloc(n, sizeof(*bucket));

	if (bucket == NULL) {
		free(ret);
		return NULL;
	}

	*ret = (struct string_map){.bucket = bucket, .n = n, .free = free_fn};

	return ret;
}
