/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <mbedtls/ssl.h>

struct mbedtls_ssl_config *https_ssl_config(void);
void https_ssl_config_init(mbedtls_ssl_config *ssl_conf);
