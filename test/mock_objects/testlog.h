/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TESTLOG_H
#define TESTLOG_H

#include <stdio.h>

#define LOG_PREFIX "[   INFO   ] "
#define info(...)  printf(LOG_PREFIX __VA_ARGS__)

#endif // TESTLOG_H
