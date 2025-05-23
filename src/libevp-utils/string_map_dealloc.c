/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

void
string_map_dealloc(struct string_map *map)
{
	if (!map)
		return;

	struct string_map_bucket **mpp, *mp, *next;

	for (mpp = map->bucket; mpp < &map->bucket[map->n]; ++mpp) {
		for (mp = *mpp; mp; mp = next) {
			if (map->free)
				map->free(mp->value);

			next = mp->next;
			free(mp->key);
			free(mp);
		}
		*mpp = NULL;
	}

	free(map->bucket);
	free(map);
}
