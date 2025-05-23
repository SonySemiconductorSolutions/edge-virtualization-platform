/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TLS_H
#define TLS_H

#include <stdbool.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>

#include "cdefs.h"

struct tls_mutual {
	mbedtls_ssl_config ssl_conf;
	mbedtls_x509_crt *ca_crt;
	mbedtls_x509_crt *client_crt;
	mbedtls_pk_context *client_key;
};

struct tls_server_only {
	mbedtls_ssl_config ssl_conf;
	mbedtls_x509_crt *ca_crt;
};

struct tls_context {
	mbedtls_entropy_context *entropy;
	mbedtls_ctr_drbg_context *ctr_drbg;
	struct tls_mutual mqtt;
	struct tls_server_only https;
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	struct tls_mutual docker;
#endif
};

struct tls_connection_context {
	mbedtls_net_context net_ctx;
	mbedtls_ssl_context ssl_ctx;
};

struct tls_context *tls_context_initialize(void);
void tls_context_free(struct tls_context *ctxt);
void tls_connection_context_init(struct tls_connection_context *tls_ctx);
void tls_connection_context_free(struct tls_connection_context *tls_ctx);
int tls_connect(struct tls_connection_context *tls_ctx,
		mbedtls_ssl_config *ssl_conf, const char *host,
		const char *port, unsigned int flags);
int tls_init_connection(struct tls_connection_context *tls_ctx,
			mbedtls_ssl_config *ssl_conf, const char *host,
			unsigned int flags);
int tls_prepare_poll(struct tls_connection_context *tls_ctx, bool want_write);
int mbedtls2errno(int rv);
void xlog_mbedtls_error(int rv, const char *fmt, ...) __printflike(2, 3);
char *tls_get_subject_common_name(mbedtls_x509_crt *cert);

#define TLS_BLOCKING 1
#define TLS_INSECURE 2

#define MBEDTLS_PREREQ(major, minor)                                          \
	((MBEDTLS_VERSION_MAJOR == (major) &&                                 \
	  MBEDTLS_VERSION_MINOR >= (minor)) ||                                \
	 (MBEDTLS_VERSION_MAJOR > (major)))

#endif
