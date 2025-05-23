/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * poor-man's map.
 */

#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "map.h"

struct map {
	size_t size;
	int (*compare)(const void *, const void *);
	int (*free_element)(void *);
	void **array;
};

static void **
_find_empty_ptr(struct map *map)
{
	unsigned int i;
	for (i = 0; i < map->size; i++) {
		if (map->array[i] == NULL) {
			return &map->array[i];
		}
	}
	size_t newsize = map->size + 1;
	map->array = xrealloc(map->array, newsize * sizeof(*map->array));
	for (i = map->size; i < newsize; i++) {
		map->array[i] = NULL;
	}
	map->size = newsize;
	return _find_empty_ptr(map);
}

static void **
_find_ptr_with(struct map *map, int (*fn)(const void *, const void *),
	       const void *key)
{
	unsigned int i;
	for (i = 0; i < map->size; i++) {
		if (map->array[i] == NULL) {
			continue;
		}
		if (!fn(key, map->array[i])) {
			return &map->array[i];
		}
	}
	return NULL;
}

void
map_foreach(struct map *map, int (*fn)(const void *, const void *),
	    const void *vp)
{
	_find_ptr_with(map, fn, vp);
}

struct map *
map_init(size_t size_hint, int (*cmpfn)(const void *, const void *),
	 int (*freefn)(void *))
{
	struct map *map;

	map = xcalloc(1, sizeof(*map));
	map->size = 0;
	map->compare = cmpfn;
	map->free_element = freefn;
	map->array = NULL;
	return map;
}

void *
map_put(struct map *map, const void *key, void *value)
{
	void **vpp = _find_ptr_with(map, map->compare, key);
	if (vpp == NULL) {
		vpp = _find_empty_ptr(map);
		if (vpp == NULL) {
			/* Abort assessment:
			 * This seems impossible by construction of this
			 * implementation. `_find_ptr_with` calls xrealloc and
			 * will abort in case of OoM exception.
			 * Therefore this could even be removed.
			 */
			// TODO: Review exit (xerrx)
			//       Remove
			xerrx(1, "map full");
		}
	}
	void *old_value = *vpp;
	*vpp = value;
	return old_value;
}

void *
map_get(struct map *map, const void *key)
{
	return map_get_with(map, map->compare, key);
}

void *
map_del(struct map *map, const void *key)
{
	size_t pos, n;
	void **vpp;
	void *old;

	vpp = _find_ptr_with(map, map->compare, key);
	if (vpp == NULL)
		return NULL;
	old = *vpp;

	if (map->size == 1) {
		map->size = 0;
		free(map->array);
		map->array = NULL;
		return old;
	}

	pos = vpp - map->array;
	if (pos != map->size - 1) {
		n = map->size - pos - 1;
		memmove(vpp, vpp + 1, n * sizeof(*vpp));
	}
	map->size--;
	map->array = xrealloc(map->array, map->size * sizeof(*vpp));

	return old;
}

void *
map_get_with(struct map *map, int (*fn)(const void *, const void *),
	     const void *key)
{
	void **vpp = _find_ptr_with(map, fn, key);
	if (vpp == NULL) {
		return NULL;
	}
	return *vpp;
}

int
map_free(struct map *map)
{
	if (map == NULL) {
		return 0;
	}
	if (map->free_element == NULL) {
		free(map->array);
		free(map);
		return 1;
	} else {
		unsigned int i;
		for (i = 0; i < map->size; i++) {
			map->free_element(map->array[i]);
		}
		free(map->array);
		free(map);
		return 0;
	}
}
