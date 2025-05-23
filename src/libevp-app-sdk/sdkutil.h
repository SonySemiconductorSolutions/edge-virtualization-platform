/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct timespec;

void *xmalloc(size_t);
void *xcalloc(size_t, size_t);
void gettime(struct timespec *);
int absts2relms_realtime_roundup(const struct timespec *);
void relms2absts_realtime(int, struct timespec *);
