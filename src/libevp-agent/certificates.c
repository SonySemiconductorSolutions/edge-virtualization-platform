/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "certificates.h"
#include "tls.h"
#include "xlog.h"
#include "xpthread.h"

#define CACHE_SIZE 1

static struct evp_lock g_cert_cache_lock = EVP_LOCK_INITIALIZER;

struct cert {
	struct mbedtls_x509_crt mbedtls;
	unsigned int refcnt EVP_GUARDED_BY(g_cert_cache_lock);
};

struct cert_cache_entry {
	char *id;
	struct cert *cert;
};

static struct cert_cache_entry
	g_cert_cache[CACHE_SIZE] EVP_GUARDED_BY(g_cert_cache_lock);

static void
cert_release_unlocked(struct cert *cert) EVP_REQUIRES(g_cert_cache_lock)
{
	// TODO: Replace assert (programming error)
	assert(cert->refcnt > 0);
	cert->refcnt--;
	if (cert->refcnt == 0) {
		mbedtls_x509_crt_free(&cert->mbedtls);
		free(cert);
	}
}

static int
cert_get_unlocked(const char *id, struct cert **certp)
	EVP_REQUIRES(g_cert_cache_lock)
{
	struct cert *cert;
	unsigned int i;

	for (i = 0; i < __arraycount(g_cert_cache); i++) {
		struct cert_cache_entry *ent = &g_cert_cache[i];
		if (ent->id != NULL && !strcmp(ent->id, id)) {
			cert = ent->cert;
			// TODO: Replace assert (programming error)
			assert(cert->refcnt > 0); /* 1 for cache entry */
			cert->refcnt++;
			*certp = cert;
			return 0;
		}
	}
	return ENOENT;
}

static void
cert_cache_evict_unlocked(struct cert_cache_entry *victim)
	EVP_REQUIRES(g_cert_cache_lock)
{
	if (victim->id != NULL) {
		cert_release_unlocked(victim->cert);
		free(victim->id);
		victim->id = NULL;
	}
}

struct mbedtls_x509_crt *
cert_mbedtls(struct cert *cert)
{
	xpthread_mutex_lock(&g_cert_cache_lock);
	// TODO: Replace assert (programming error)
	assert(cert->refcnt > 0);
	xpthread_mutex_unlock(&g_cert_cache_lock);
	return &cert->mbedtls;
}

int
cert_get(const char *id, struct cert **certp)
{
	int ret;

	xpthread_mutex_lock(&g_cert_cache_lock);
	ret = cert_get_unlocked(id, certp);
	xpthread_mutex_unlock(&g_cert_cache_lock);
	return ret;
}

int
cert_set(const char *id, const void *buf, size_t buflen, struct cert **certp)
{
	struct cert *cert;

	xpthread_mutex_lock(&g_cert_cache_lock);
	if (cert_get_unlocked(id, certp) == 0) {
		xpthread_mutex_unlock(&g_cert_cache_lock);
		return 0;
	}

#if CACHE_SIZE > 1
#error implement a real cache eviction algorithm
#else
	struct cert_cache_entry *victim = &g_cert_cache[0];
	cert_cache_evict_unlocked(victim);
#endif

	cert = xmalloc(sizeof(*cert));
	victim->id = xstrdup(id);
	victim->cert = cert;
	cert->refcnt = 1; /* for the cache entry */
	mbedtls_x509_crt_init(&cert->mbedtls);
	int rv = mbedtls_x509_crt_parse(&cert->mbedtls, buf, buflen);
	if (rv) {
		xlog_mbedtls_error(
			rv, "failed to load certificate(s) with id '%s'", id);
		cert_cache_evict_unlocked(victim);
		xpthread_mutex_unlock(&g_cert_cache_lock);
		return EINVAL;
	}
	cert->refcnt++; /* +1 for the caller */
	xpthread_mutex_unlock(&g_cert_cache_lock);
	*certp = cert;
	return 0;
}

void
cert_release(struct cert *cert)
{
	xpthread_mutex_lock(&g_cert_cache_lock);
	cert_release_unlocked(cert);
	xpthread_mutex_unlock(&g_cert_cache_lock);
}
