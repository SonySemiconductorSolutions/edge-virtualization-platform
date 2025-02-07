/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "main_loop.h"
#include "platform.h"
#include "socketutil.h"
#include "timeutil.h"
#include "tls.h"
#include "xlog.h"
#include "xpthread.h"

#define MBED_TLS_TIMEOUT (180 * 1000)

#if !defined(MBEDTLS_NET_POLL_READ)
/* compat for older mbedtls */
#define MBEDTLS_NET_POLL_READ  1
#define MBEDTLS_NET_POLL_WRITE 1

int
mbedtls_net_poll(mbedtls_net_context *ctx, uint32_t rw, uint32_t timeout)
{
	/* XXX should use poll/select */
	usleep(300);
	return 1;
}
#endif

#if !MBEDTLS_PREREQ(2, 8)
int
mbedtls_ssl_check_pending(const mbedtls_ssl_context *ssl)
{
	return 0;
}
#endif

#if defined(MBEDTLS_DEBUG_C)
static void
my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	xlog_debug("%s:%d: |%d| %s", file, line, level, str);
}
#endif

#if defined(CONFIG_EVP_AGENT_TLS_KEYLOG)
static void
write_keylog(const char *keylogfile, const unsigned char client_random[32],
	     const unsigned char *secret, size_t secret_len)
{
	static struct evp_lock export_key_lock = EVP_LOCK_INITIALIZER;
	FILE *fp;
	unsigned int i;

	/*
	 * REVISIT: is it worth to report i/o errors?
	 */

	xpthread_mutex_lock(&export_key_lock);
	fp = fopen(keylogfile, "a");
	if (fp != NULL) {
		fprintf(fp, "CLIENT_RANDOM ");
		for (i = 0; i < 32; i++) {
			fprintf(fp, "%02x", client_random[i]);
		}
		fprintf(fp, " ");
		for (i = 0; i < secret_len; i++) {
			fprintf(fp, "%02x", secret[i]);
		}
		fprintf(fp, "\n");
		fclose(fp);
	}
	xpthread_mutex_unlock(&export_key_lock);
}

#if MBEDTLS_PREREQ(3, 0)
static void
my_export_key(void *context, mbedtls_ssl_key_export_type type,
	      const unsigned char *secret, size_t secret_len,
	      const unsigned char client_random[32],
	      const unsigned char server_random[32],
	      mbedtls_tls_prf_types tls_prf_type)
{
	if (type != MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET) {
		return;
	}
	write_keylog(context, client_random, secret, secret_len);
}

#else  /* MBEDTLS_PREREQ(3, 0) */

static int
my_export_key(void *context, const unsigned char *secret,
	      const unsigned char *kb, size_t maclen, size_t keylen,
	      size_t ivlen, const unsigned char client_random[32],
	      const unsigned char server_random[32],
	      mbedtls_tls_prf_types tls_prf_type)
{
	write_keylog(context, client_random, secret, 48);

	return 0;
}
#endif /* MBEDTLS_PREREQ(3, 0) */
#endif /* defined(CONFIG_EVP_AGENT_TLS_KEYLOG) */

void
xlog_mbedtls_error(int rv, const char *fmt, ...)
{
	char msg[100];
	va_list ap;
	int ret;

	// TODO: Replace assert (programming error)
	assert(rv != 0);
	va_start(ap, fmt);
	ret = vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (ret < 0 || (unsigned)ret >= sizeof(msg)) {
		// TODO: Review exit (xlog_abort)
		//       Trim error instead of abort
		xlog_abort("vsnprintf error %d", ret);
	} else if (rv < 0) {
		char buf[100];
		mbedtls_strerror(rv, buf, sizeof(buf));
		xlog_error("%s, mbedtls returned -0x%x (%s)", msg,
			   (unsigned int)-rv, buf);
	} else {
		xlog_error("%s, mbedtls returned 0x%x", msg, rv);
	}
}

int
failed(const char *fn, int rv)
{
	// TODO: Replace assert (programming error)
	assert(rv != 0);
	if (rv < 0) {
		char buf[100];
		mbedtls_strerror(rv, buf, sizeof(buf));
		xlog_error("%s failed with -0x%x (%s)", fn, -rv, buf);
	} else {
		xlog_error("%s failed, returning a positive value 0x%x", fn,
			   rv);
	}
	return rv;
}

int
cert_verify_failed(uint32_t rv)
{
	char buf[512];
	mbedtls_x509_crt_verify_info(buf, sizeof(buf), "\t", rv);
	xlog_error("Certificate verification failed (%0" PRIx32 ")\n%s", rv,
		   buf);
	/*
	 * MBEDTLS_ERR_X509_CERT_VERIFY_FAILED is what mbedtls_ssl_handshake()
	 * would return with the MBEDTLS_SSL_VERIFY_REQUIRED auth mode.
	 * (We use MBEDTLS_SSL_VERIFY_OPTIONAL.)
	 */
	return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
}

void
tls_connection_context_free(struct tls_connection_context *tls_ctx)
{
	mbedtls_net_context *net_ctx = &tls_ctx->net_ctx;
	mbedtls_ssl_context *ssl_ctx = &tls_ctx->ssl_ctx;

	mbedtls_ssl_free(ssl_ctx);
	mbedtls_net_free(net_ctx);
}

static int
load_cert(enum config_key key, mbedtls_x509_crt **pcrt)
{
	int rv = -1;
	void *buf;
	size_t buflen;
	struct config *cfg;
	mbedtls_x509_crt *crt;

	if ((cfg = get_config(key)) == NULL)
		return 0;

	if (load_config(cfg, &buf, &buflen) != 0)
		goto err1;

	if ((crt = malloc(sizeof(*crt))) == NULL)
		goto err2;

	mbedtls_x509_crt_init(crt);
	rv = mbedtls_x509_crt_parse(crt, buf, buflen);
	if (rv != 0)
		goto err3;

	unload_config(cfg, buf, buflen);
	*pcrt = crt;

	free_config(cfg);
	return 0;

err3:
	free(crt);
err2:
	unload_config(cfg, buf, buflen);
	failed("mbedtls_x509_crt_parse", rv);
err1:
	free_config(cfg);
	return -1;
}

static int
gen_entropy(mbedtls_entropy_context **pentropy,
	    mbedtls_ctr_drbg_context **pctr_drbg)
{
	int rv;
	char additional_input[100];
	mbedtls_entropy_context *entropy = NULL;
	mbedtls_ctr_drbg_context *ctr_drbg = NULL;
	const char *progname = xgetprogname();

	if (progname == NULL) {
		progname = "<no name>";
	}
	rv = snprintf(additional_input, sizeof(additional_input), "%s-%d-%d",
		      progname, (int)getpid(), (int)time(NULL));
	if (rv == -1 || (unsigned)rv >= sizeof(additional_input))
		goto err0;

	entropy = malloc(sizeof(*entropy));
	ctr_drbg = malloc(sizeof(*ctr_drbg));
	if (!entropy || !ctr_drbg)
		goto err1;

	mbedtls_entropy_init(entropy);
	mbedtls_ctr_drbg_init(ctr_drbg);
	rv = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
				   (const unsigned char *)additional_input,
				   rv);
	if (rv != 0)
		goto err2;

	*pentropy = entropy;
	*pctr_drbg = ctr_drbg;

	return 0;

err2:
	mbedtls_entropy_free(entropy);
	mbedtls_ctr_drbg_free(ctr_drbg);
	failed("mbedtls_ctr_drbg_seed", rv);
err1:
	free(entropy);
	free(ctr_drbg);
err0:
	xlog_error("failed to initialize entropy");
	return -1;
}

static int
load_key(enum config_key key, mbedtls_ctr_drbg_context *ctr_drbg,
	 mbedtls_pk_context **ppk)
{
	int rv = -1;
	void *buf;
	size_t buflen;
	struct config *cfg;
	mbedtls_pk_context *pk;

	if ((cfg = get_config(key)) == NULL)
		return 0;

	if (load_config(cfg, &buf, &buflen) != 0)
		goto err1;

	if ((pk = plat_secure_malloc(sizeof(*pk))) == NULL)
		goto err2;

	mbedtls_pk_init(pk);
#if MBEDTLS_PREREQ(3, 0)
	rv = mbedtls_pk_parse_key(pk, buf, buflen, NULL, 0,
				  mbedtls_ctr_drbg_random, ctr_drbg);
#else
	rv = mbedtls_pk_parse_key(pk, buf, buflen, NULL, 0);
#endif
	if (rv != 0)
		goto err3;

	unload_config(cfg, buf, buflen);
	*ppk = pk;

	free_config(cfg);
	return 0;

err3:
	plat_secure_free(pk);
err2:
	unload_config(cfg, buf, buflen);
	failed("mbedtls_pk_parse_key", rv);
err1:
	free_config(cfg);
	return -1;
}

void
tls_context_free(struct tls_context *ctxt)
{
	mbedtls_x509_crt_free(ctxt->https.ca_crt);
	free(ctxt->https.ca_crt);

	if (ctxt->https.ca_crt != ctxt->mqtt.ca_crt) {
		mbedtls_x509_crt_free(ctxt->mqtt.ca_crt);
		free(ctxt->mqtt.ca_crt);
	}

#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	mbedtls_x509_crt_free(ctxt->docker.ca_crt);
	free(ctxt->docker.ca_crt);

	mbedtls_x509_crt_free(ctxt->docker.client_crt);
	free(ctxt->docker.client_crt);

	mbedtls_pk_free(ctxt->docker.client_key);
	plat_secure_free(ctxt->docker.client_key);
#endif

	mbedtls_x509_crt_free(ctxt->mqtt.client_crt);
	free(ctxt->mqtt.client_crt);

	mbedtls_pk_free(ctxt->mqtt.client_key);
	plat_secure_free(ctxt->mqtt.client_key);

	mbedtls_entropy_free(ctxt->entropy);
	free(ctxt->entropy);

	mbedtls_ctr_drbg_free(ctxt->ctr_drbg);
	free(ctxt->ctr_drbg);
	free(ctxt);
}

static int
config_mutual(struct tls_mutual *m, mbedtls_ctr_drbg_context *ctr_drbg)
{
	int rv;

	mbedtls_ssl_config_init(&m->ssl_conf);
	rv = mbedtls_ssl_config_defaults(&m->ssl_conf, MBEDTLS_SSL_IS_CLIENT,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		return failed("mbedtls_ssl_config_defaults", rv);
	}
	if (m->client_crt && m->client_key) {
		rv = mbedtls_ssl_conf_own_cert(&m->ssl_conf, m->client_crt,
					       m->client_key);
		if (rv != 0) {
			return failed("mbedtls_ssl_conf_own_cert", rv);
		}
	}
	if (m->ca_crt) {
		mbedtls_ssl_conf_ca_chain(&m->ssl_conf, m->ca_crt, NULL);
	}
	mbedtls_ssl_conf_authmode(&m->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&m->ssl_conf, mbedtls_ctr_drbg_random, ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&m->ssl_conf, MBED_TLS_TIMEOUT);
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(&m->ssl_conf, my_debug, NULL);
	mbedtls_debug_set_threshold(CONFIG_EVP_AGENT_TLS_DEBUG_THRESHOLD);
#endif
#if defined(CONFIG_EVP_AGENT_TLS_KEYLOG)
#if !MBEDTLS_PREREQ(3, 0)
	const char *keylogfile = getenv("EVP_TLS_KEYLOGFILE");

	if (keylogfile != NULL) {
		mbedtls_ssl_conf_export_keys_ext_cb(
			&m->ssl_conf, my_export_key, __UNCONST(keylogfile));
	}
#endif /* !MBEDTLS_PREREQ(3, 0) */
#endif /* defined(CONFIG_EVP_AGENT_TLS_KEYLOG) */

	return 0;
}

static int
config_https(struct tls_server_only *so, mbedtls_ctr_drbg_context *ctr_drbg)
{
	mbedtls_ssl_config_init(&so->ssl_conf);
	int rv = mbedtls_ssl_config_defaults(
		&so->ssl_conf, MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rv != 0) {
		return failed("mbedtls_ssl_config_defaults", rv);
	}
	if (so->ca_crt) {
		mbedtls_ssl_conf_ca_chain(&so->ssl_conf, so->ca_crt, NULL);
	}
	mbedtls_ssl_conf_authmode(&so->ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&so->ssl_conf, mbedtls_ctr_drbg_random, ctr_drbg);
	mbedtls_ssl_conf_read_timeout(&so->ssl_conf, MBED_TLS_TIMEOUT);
#if defined(MBEDTLS_DEBUG_C)
	mbedtls_ssl_conf_dbg(&so->ssl_conf, my_debug, NULL);
	mbedtls_debug_set_threshold(CONFIG_EVP_AGENT_TLS_DEBUG_THRESHOLD);
#endif
#if defined(CONFIG_EVP_AGENT_TLS_KEYLOG)
#if !MBEDTLS_PREREQ(3, 0)
	const char *keylogfile = getenv("EVP_TLS_KEYLOGFILE");

	if (keylogfile != NULL) {
		mbedtls_ssl_conf_export_keys_ext_cb(
			&so->ssl_conf, my_export_key, __UNCONST(keylogfile));
	}
#endif /* !MBEDTLS_PREREQ(3, 0) */
#endif /* defined(CONFIG_EVP_AGENT_TLS_KEYLOG) */

	return 0;
}

static int
tls_context_initialize_config(struct tls_context *ctxt)
{
	int rv;

	rv = config_mutual(&ctxt->mqtt, ctxt->ctr_drbg);
	if (rv != 0) {
		return rv;
	}

#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	rv = config_mutual(&ctxt->docker, ctxt->ctr_drbg);
	if (rv != 0) {
		return rv;
	}
#endif

	rv = config_https(&ctxt->https, ctxt->ctr_drbg);
	if (rv != 0) {
		return rv;
	}

	return 0;
}

struct tls_context *
tls_context_initialize(void)
{
	int rv;
	struct tls_context *ctxt = calloc(1, sizeof(*ctxt));
	if (ctxt == NULL)
		return NULL;

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
	/* Initialize PSA Crypto */
	rv = psa_crypto_init();
	if (rv != PSA_SUCCESS) {
		failed("Failed to initialize PSA Crypto", rv);
		goto err;
	}
#endif

	if (gen_entropy(&ctxt->entropy, &ctxt->ctr_drbg) != 0)
		goto err;

	mbedtls_x509_crt *ca = NULL;
	if (load_cert(EVP_CONFIG_TLS_CA_CERT, &ca) != 0)
		goto err;

	if (ca) {
		ctxt->https.ca_crt = ca;
		ctxt->mqtt.ca_crt = ca;
	} else {
		if (load_cert(EVP_CONFIG_MQTT_TLS_CA_CERT,
			      &ctxt->mqtt.ca_crt) != 0)
			goto err;
		if (load_cert(EVP_CONFIG_HTTPS_CA_CERT, &ctxt->https.ca_crt) !=
		    0)
			goto err;
	}

	rv = load_cert(EVP_CONFIG_MQTT_TLS_CLIENT_CERT,
		       &ctxt->mqtt.client_crt);
	if (rv != 0)
		goto err;
	rv = load_key(EVP_CONFIG_MQTT_TLS_CLIENT_KEY, ctxt->ctr_drbg,
		      &ctxt->mqtt.client_key);
	if (rv != 0)
		goto err;

#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	rv = load_cert(EVP_CONFIG_DOCKER_TLS_CA_CERT, &ctxt->docker.ca_crt);
	if (rv != 0)
		goto err;
	rv = load_cert(EVP_CONFIG_DOCKER_TLS_CLIENT_CERT,
		       &ctxt->docker.client_crt);
	if (rv != 0)
		goto err;
	rv = load_key(EVP_CONFIG_DOCKER_TLS_CLIENT_KEY, ctxt->ctr_drbg,
		      &ctxt->docker.client_key);
	if (rv != 0)
		goto err;
#endif

	rv = tls_context_initialize_config(ctxt);
	if (rv != 0)
		goto err;

	return ctxt;

err:
	tls_context_free(ctxt);

	return NULL;
}

void
tls_connection_context_init(struct tls_connection_context *tls_ctx)
{
	mbedtls_net_context *net_ctx = &tls_ctx->net_ctx;
	mbedtls_ssl_context *ssl_ctx = &tls_ctx->ssl_ctx;

	mbedtls_net_init(net_ctx);
	mbedtls_ssl_init(ssl_ctx);
}

int
tls_connect(struct tls_connection_context *tls_ctx,
	    mbedtls_ssl_config *ssl_conf, const char *hostname,
	    const char *port, unsigned int flags)
{
	mbedtls_net_context *net_ctx = &tls_ctx->net_ctx;
	int rv;

	rv = mbedtls_net_connect(net_ctx, hostname, port,
				 MBEDTLS_NET_PROTO_TCP);
	xlog_info("%s: mbedtls_net_connect(): %d", __func__, rv);
	if (rv != 0) {
		return failed("mbedtls_net_connect", rv);
	}
	rv = tls_init_connection(tls_ctx, ssl_conf, hostname, flags);
	xlog_info("%s: tls_init_connection(): %d", __func__, rv);
	if (rv != 0) {
		return failed("tls_init_connection", rv);
	}
	return rv;
}

int
tls_init_connection(struct tls_connection_context *tls_ctx,
		    mbedtls_ssl_config *ssl_conf, const char *hostname,
		    unsigned int flags)
{
	mbedtls_net_context *net_ctx = &tls_ctx->net_ctx;
	mbedtls_ssl_context *ssl_ctx = &tls_ctx->ssl_ctx;
	int rv;

	xlog_socket_address(net_ctx->fd);
	if ((flags & TLS_BLOCKING) == 0) {
		rv = mbedtls_net_set_nonblock(net_ctx);
		if (rv != 0) {
			return failed("mbedtls_net_set_nonblock", rv);
		}
	}

	rv = mbedtls_ssl_setup(ssl_ctx, ssl_conf);
	if (rv != 0) {
		return failed("mbedtls_ssl_setup", rv);
	}
	rv = mbedtls_ssl_set_hostname(ssl_ctx, hostname);
	if (rv != 0) {
		return failed("mbedtls_ssl_set_hostname", rv);
	}
	if ((flags & TLS_BLOCKING) != 0) {
		mbedtls_ssl_set_bio(ssl_ctx, net_ctx, mbedtls_net_send, NULL,
				    mbedtls_net_recv_timeout);
		mbedtls_ssl_conf_read_timeout(ssl_conf, MBED_TLS_TIMEOUT);
	} else {
		mbedtls_ssl_set_bio(ssl_ctx, net_ctx, mbedtls_net_send,
				    mbedtls_net_recv, NULL);
	}
#if defined(CONFIG_EVP_AGENT_TLS_KEYLOG)
#if MBEDTLS_PREREQ(3, 0)
	const char *keylogfile = getenv("EVP_TLS_KEYLOGFILE");

	if (keylogfile != NULL) {
		mbedtls_ssl_set_export_keys_cb(ssl_ctx, my_export_key,
					       __UNCONST(keylogfile));
	}
#endif /* MBEDTLS_PREREQ(3, 0) */
#endif /* defined(CONFIG_EVP_AGENT_TLS_KEYLOG) */

	const uint64_t timeout = gettime_ms() + MBED_TLS_TIMEOUT;
	for (;;) {
		rv = mbedtls_ssl_handshake(ssl_ctx);
		uint32_t want = 0;
		if (rv == MBEDTLS_ERR_SSL_WANT_READ) {
			want |= MBEDTLS_NET_POLL_READ;
		} else if (rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
			want |= MBEDTLS_NET_POLL_WRITE;
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && MBEDTLS_VERSION_MAJOR == 3
		} else if (rv == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			want |= MBEDTLS_NET_POLL_READ;
			xlog_info("Got new TLS session ticket");
#endif
		} else {
			break;
		}
		if ((flags & TLS_BLOCKING) != 0) {
			// TODO: Replace assert (programming
			// error)
			assert(want == 0);
		} else {
			uint64_t remain = timeout - gettime_ms();
			if (remain > timeout) {
				xlog_error("mbedtls_ssl_"
					   "handshake "
					   "timeout");
				return -1;
			}
			rv = mbedtls_net_poll(net_ctx, want, remain);
			if (rv < 0) {
				return failed("mbedtls_net_poll", rv);
			} else if (rv == 0) {
				xlog_error("mbedtls_net_poll "
					   "timeout");
				return -1;
			} else {
				xlog_info("mbedtls_net_poll "
					  "success");
			}
		}
	}
	if (rv != 0) {
		return failed("mbedtls_ssl_handshake", rv);
	}
	uint32_t result = mbedtls_ssl_get_verify_result(ssl_ctx);
	if (result != 0) {
		if (result == (uint32_t)-1) {
			return failed("mbedtls_ssl_get_verify_"
				      "result",
				      result);
		} else {
			rv = cert_verify_failed(result);
			if ((flags & TLS_INSECURE) == 0) {
				return rv;
			}
		}
	}
	return 0;
}

int
tls_prepare_poll(struct tls_connection_context *tls_ctx, bool want_write)
{
#if MBEDTLS_PREREQ(3, 0)
	if (tls_ctx->ssl_ctx.private_conf == NULL) {
#else
	if (tls_ctx->ssl_ctx.conf == NULL) {
#endif
		/*
		 * Note: mbedtls_ssl_check_pending just crashes
		 * on zero'ed context. (Many of mbedtls
		 * functions return MBEDTLS_ERR_SSL_BAD_INPUT_DATA
		 * in that case.)
		 */
		xlog_warning("%s: invalid ssl context. probably "
			     "during reconnect.",
			     __func__);
		return EINVAL;
	}
	/*
	 * mbedtls_ssl_check_pending() returns true if the TLS
	 * library has some data in its buffer which has been
	 * read from the underlying socket but has not been
	 * processed by TLS yet. In that case, it isn't safe to
	 * block on the underlying socket before processing the
	 * data already read.
	 */
	if (mbedtls_ssl_check_pending(&tls_ctx->ssl_ctx)) {
		/*
		 * Schedule an immediate timeout to avoid a
		 * deadlock.
		 */
		main_loop_add_timeout_ms("TLS", 0);
	}
	int fd = tls_ctx->net_ctx.fd;
	return main_loop_add_fd(fd, want_write);
}

int
mbedtls2errno(int rv)
{
	int error;

	// TODO: Replace assert (programming error)
	assert(rv != 0);

	error = EIO;

	/* Use unusual errno for some of "common" errors */
	switch (rv) {
	case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
		error = EPERM;
		break;
	case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
		error = ECONNRESET;
		break;
	case MBEDTLS_ERR_NET_CONNECT_FAILED:
		error = ECONNREFUSED;
		break;
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && MBEDTLS_VERSION_MAJOR == 3
	case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
#endif
		error = EAGAIN;
		break;
	}

	/* do not output logs in retry case */
	if (error == EAGAIN) {
		return error;
	}

	if (rv < 0) {
		char buf[100];
		mbedtls_strerror(rv, buf, sizeof(buf));
		xlog_info("mbedtls2errno: converting -0x%x "
			  "(%s) to %d "
			  "(%s)",
			  -rv, buf, error, strerror(error));
	} else {
		xlog_info("mbedtls2errno: converting 0x%x to "
			  "%d (%s)",
			  rv, error, strerror(error));
	}

	return error;
}

char *
tls_get_subject_common_name(mbedtls_x509_crt *cert)
{
	int rv;
	const mbedtls_x509_name *name;
	const char *short_name = NULL;
	const char *cn_str = "CN";
	char *s;

	if (cert == NULL) {
		return NULL;
	}

	/*get CN str*/
	name = &(cert->subject);

	s = (char *)xmalloc(sizeof(char) * MBEDTLS_X509_MAX_DN_NAME_SIZE);

	while (name != NULL) {
		rv = mbedtls_oid_get_attr_short_name(&name->oid, &short_name);
		if (rv == 0 && strcmp(cn_str, short_name) == 0) {
			escape_string((char *)name->val.p, name->val.len, s,
				      (sizeof(char) *
				       MBEDTLS_X509_MAX_DN_NAME_SIZE) -
					      1);
			return s;
		}

		short_name = NULL;
		name = name->next;
	}

	free(s);
	xlog_info("failed to get CommonName in Client Cert");
	return NULL;
}
