/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct blob_worker;
struct blob_work;
struct mbedtls_ssl_config;

unsigned int blob_http_get(struct blob_work *wk, int fd,
			   const char *const *headers, unsigned int nheaders,
			   struct mbedtls_ssl_config *ssl_conf);

unsigned int blob_http_put(struct blob_work *wk, int fd,
			   const char *const *headers, unsigned int nheaders,
			   struct mbedtls_ssl_config *ssl_conf);
