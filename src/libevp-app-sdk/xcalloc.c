/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include "sdkutil.h"

void *
xcalloc(size_t num, size_t sz)
{
	void *vp = calloc(num, sz);
	if (vp == NULL) {
		abort();
	}
	return vp;
}
