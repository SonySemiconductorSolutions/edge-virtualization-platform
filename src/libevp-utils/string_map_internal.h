/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STRING_MAP_INTERNAL_H
#define STRING_MAP_INTERNAL_H

#include <stddef.h>

struct string_map_bucket {
	char *key;
	void *value;
	struct string_map_bucket *next;
};

struct string_map {
	size_t n;
	void (*free)(void *);
	struct string_map_bucket **bucket;
};

unsigned long djb2(const char *s);

#endif
