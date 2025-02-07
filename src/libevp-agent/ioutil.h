/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <unistd.h> /* ssize_t */

/*
 * I/O wrappers to retry on short results. Mainly for for sockets.
 * (Something similar to what's called readn/writen in Stevens.)
 */

ssize_t readall(int fd, void *buf, size_t sz);
int discardall(int fd, size_t sz);
