/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Definitions in Nuttx that are not present in POSIX
 * systems.
 */
#if !defined(__NuttX__)
#define CODE
#define FAR
#define OK    0
#define ERROR (-1)

typedef void *(*pthread_startroutine_t)(void *);
#endif

/*
 * Note: __dead macro provided by macOS system header is
 * not compatible with ours.
 */
#undef __dead

/*
 * Avoid conflicts with ESP32 toolchain math.h.
 * More specifically, their sys/features.h and sys/cdefs.h.
 */
#undef __GNUC_PREREQ__
#undef __CONCAT

#include <internal/cdefs.h>
