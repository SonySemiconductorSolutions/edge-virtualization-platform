/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct blob_work;
struct blob_worker;

unsigned int blob_type_http_get(struct blob_work *wk);
unsigned int blob_type_http_put(struct blob_work *wk);
