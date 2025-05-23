/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

int
string_map_forall(struct string_map *map,
		  int (*fn)(const char *, void *, void *), void *user)
{
	int r;
	size_t i;
	struct string_map_bucket *next, *prev, *bp;

	for (i = 0; i < map->n; i++) {
		if (!map->bucket[i])
			continue;
		for (prev = bp = map->bucket[i]; bp; bp = next) {
			next = bp->next;
			r = fn(bp->key, bp->value, user);
			if (r == 0) {
				return -1;
			} else if (r > 0) {
				prev = bp;
			} else {
				if (prev == bp)
					map->bucket[i] = prev = next;
				else
					prev->next = next;

				if (map->free)
					map->free(bp->value);

				free(bp->key);
				free(bp);
			}
		}
	}

	return 0;
}
