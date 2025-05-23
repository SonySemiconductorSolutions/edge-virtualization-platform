/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <internal/string_map.h>

#include "string_map_internal.h"

size_t
string_map_count(const struct string_map *map)
{
	size_t ret = 0;

	for (size_t i = 0; i < map->n; i++) {
		const struct string_map_bucket *bp;

		for (bp = map->bucket[i]; bp; bp = bp->next)
			ret++;
	}

	return ret;
}
