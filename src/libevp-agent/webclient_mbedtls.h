/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>

#include <mbedtls/x509_crt.h>

#include "webclient/webclient.h"

struct evp_agent_context;

struct webclient_mbedtls_param {
	bool insecure;
	bool nonblocking;

	struct mbedtls_ssl_config *ssl_config;

	/* Agent context. It is necessary for using event notifications */
	struct evp_agent_context *agent;
};

extern const struct webclient_tls_ops mbedtls_tls_ops;
