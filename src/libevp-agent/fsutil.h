/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>

int rmtree(const char *);
int careful_open(const char *path, int oflags, int *fdp);
void *read_file(const char *path, size_t *sizep, bool add_nul);
int sync_parent_dir(const char *filename);
