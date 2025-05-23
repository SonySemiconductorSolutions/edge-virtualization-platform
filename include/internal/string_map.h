/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STRING_MAP_H_
#define STRING_MAP_H_

#include <stdbool.h>
#include <stddef.h>

struct string_map;

struct string_map *string_map_alloc(size_t n, void (*free_fn)(void *));
void string_map_dealloc(struct string_map *map);

void *string_map_lookup(struct string_map *map, const char *key);
int string_map_insert(struct string_map *map, const char *key, void *value,
		      bool overwrite);
int string_map_forall(struct string_map *map,
		      int (*fn)(const char *, void *, void *), void *user);
size_t string_map_count(const struct string_map *map);

#endif
