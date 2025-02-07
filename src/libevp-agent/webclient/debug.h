/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../xlog.h"

#define ninfo(format, ...) xlog_trace(format, ##__VA_ARGS__)
#define nwarn(format, ...) xlog_warning(format, ##__VA_ARGS__)
#define nerr(format, ...)  xlog_error(format, ##__VA_ARGS__)

#ifndef DEBUGASSERT
#define DEBUGASSERT(a) assert(a)
#endif
