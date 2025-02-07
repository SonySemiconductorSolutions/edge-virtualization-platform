/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "string_map_internal.h"

/*
 * this algorithm (k=33) was first reported by dan bernstein many years
 * ago in comp.lang.c. another version of this algorithm (now favored by
 * bernstein) uses xor: hash(i) = hash(i - 1) * 33 ^ str[i]; the magic of
 * number 33 (why it works better than many other constants, prime or not)
 * has never been adequately explained.
 *
 * Reference: http://www.cse.yorku.ca/~oz/hash.html
 */

unsigned long
djb2(const char *s)
{
	const unsigned char *str = (unsigned char *)s;
	unsigned long hash = 5381;
	unsigned c;

	while ((c = *str++) != '\0')
		hash = hash * 33 + c;

	return hash;
}
