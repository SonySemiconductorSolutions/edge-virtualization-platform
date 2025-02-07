/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

int base64_encode(const void *, size_t, char **, size_t *);
int base64_decode(const char *, size_t, void **, size_t *);

int base64_decode_append_nul(const char *, size_t, void **, size_t *);
