/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include "https_ssl_config.h"

static struct mbedtls_ssl_config *g_https_ssl_config;

struct mbedtls_ssl_config *
https_ssl_config(void)
{
	return g_https_ssl_config;
}

void
https_ssl_config_init(struct mbedtls_ssl_config *ssl_config)
{
	g_https_ssl_config = ssl_config;
}
