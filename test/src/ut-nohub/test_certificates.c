/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "certificates.c"
#include "hub.h"

static void
cert_cache_evict_all(void)
{
	unsigned int i;

	xpthread_mutex_lock(&g_cert_cache_lock);
	for (i = 0; i < __arraycount(g_cert_cache); i++) {
		struct cert_cache_entry *ent = &g_cert_cache[i];
		cert_cache_evict_unlocked(ent);
	}
	xpthread_mutex_unlock(&g_cert_cache_lock);
}

static unsigned int
cert_refcnt(struct cert *cert)
{
	unsigned int refcnt;

	xpthread_mutex_lock(&g_cert_cache_lock);
	refcnt = cert->refcnt;
	xpthread_mutex_unlock(&g_cert_cache_lock);
	return refcnt;
}

#include "azure_certs.h"

void
test_certificates(void **state)
{
	const char *test_cert = certificates;
	size_t test_cert_size = certlist_crt_len;

	struct cert *cert1;
	struct cert *cert2;
	struct cert *cert3;
	struct cert *cert4;
	struct cert *cert5;
	int ret;

	ret = cert_get("hoge", &cert1);
	assert_true(ret == ENOENT);

	ret = cert_set("hoge", "broken", 7, &cert1);
	assert_true(ret == EINVAL);

	ret = cert_set("hoge", certificates, test_cert_size, &cert1);
	assert_true(ret == 0);
	assert_true(cert_refcnt(cert1) == 2);
	cert_release(cert1);
	assert_true(cert_refcnt(cert1) == 1);
	ret = cert_get("hoge", &cert1);
	assert_true(ret == 0);
	assert_true(cert_refcnt(cert1) == 2);

	ret = cert_get("hoge", &cert2);
	assert_true(ret == 0);

	ret = cert_set("hoge", test_cert, test_cert_size, &cert3);
	assert_true(ret == 0);

	assert_true(cert1 == cert2);
	assert_true(cert1 == cert3);
	assert_true(cert_refcnt(cert1) == 4);

	ret = cert_set("fuga", test_cert, test_cert_size, &cert4);
	assert_true(ret == 0);
	assert_true(cert_refcnt(cert1) == 3);
	assert_true(cert1 != cert4);
	assert_true(cert_mbedtls(cert1) != cert_mbedtls(cert4));

	ret = cert_get("hoge", &cert5);
	assert_true(ret == ENOENT);

	cert_release(cert1);
	cert_release(cert2);
	cert_release(cert3);
	cert_release(cert4);
	cert_cache_evict_all();
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_certificates),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
