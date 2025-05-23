/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

int
string_map_insert(struct string_map *map, const char *key, void *value,
		  bool overwrite)
{
	struct string_map_bucket *mp;
	unsigned long h = djb2(key) % map->n;

	for (mp = map->bucket[h]; mp; mp = mp->next) {
		if (strcmp(mp->key, key) != 0)
			continue;
		if (!overwrite) {
			errno = EEXIST;
			return -1;
		}
		if (map->free)
			map->free(mp->value);

		mp->value = value;
		return 0;
	}

	if ((mp = malloc(sizeof(*mp))) == NULL)
		return -1;

	if ((mp->key = strdup(key)) == NULL) {
		free(mp);
		return -1;
	}
	mp->next = map->bucket[h];
	mp->value = value;
	map->bucket[h] = mp;

	return 0;
}
