/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "sdkutil.h"

void *
xmalloc(size_t sz)
{
	void *vp = malloc(sz);
	if (vp == NULL) {
		abort();
	}
	return vp;
}
