/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

struct map;

struct map *map_init(size_t, int (*)(const void *, const void *),
		     int (*)(void *));
void *map_del(struct map *, const void *);
void *map_put(struct map *, const void *, void *);
void *map_get(struct map *, const void *);
void *map_get_with(struct map *, int (*)(const void *, const void *),
		   const void *);
void map_foreach(struct map *, int (*)(const void *, const void *),
		 const void *);
int map_free(struct map *map);
