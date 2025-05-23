/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

void *
string_map_lookup(struct string_map *map, const char *key)
{
	struct string_map_bucket *mp;
	unsigned long h = djb2(key) % map->n;

	for (mp = map->bucket[h]; mp; mp = mp->next) {
		if (strcmp(mp->key, key) == 0)
			return mp->value;
	}

	return NULL;
}
