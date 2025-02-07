/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct blob_work;
struct blob_worker;

unsigned int blob_type_azure_blob_get(struct blob_work *wk);
unsigned int blob_type_azure_blob_put(struct blob_work *wk);
