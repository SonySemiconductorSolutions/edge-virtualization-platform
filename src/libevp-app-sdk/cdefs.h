/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Avoid conflicts with ESP32 toolchain math.h.
 * More specifically, their sys/features.h and sys/cdefs.h.
 */
#undef __GNUC_PREREQ__
#undef __CONCAT

#include <internal/cdefs.h>
