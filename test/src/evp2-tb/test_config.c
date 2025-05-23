/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <mock_objects/agent_test.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include <internal/evp_config.h>

#include "hub.h"
#include "path.h"

#define TEST_CONFIG_MQTT_HOST    "test.mqtt.host.value"
#define TEST_CONFIG_MQTT_PORT    "12435"
#define TEST_CONFIG_MQTT_MFS_QOS "1"

#define TEST_CONFIG_MQTT_PEM                                                  \
	"-----BEGIN CERTIFICATE-----"                                         \
	"MIIDLzCCAhcCFA8i0jF/+u/Klstn+7uFGYh9pirGMA0GCSqGSIb3DQEBCwUAMFQx"    \
	"CzAJBgNVBAYTAkpQMREwDwYDVQQKDAhNaWRva3VyYTEdMBsGA1UECwwUVHJhdmlz"    \
	"IEVWUCBEZXZpY2UgQ0kxEzARBgNVBAMMCnRlc3RkZXZpY2UwHhcNMjIwNDEyMTUy"    \
	"MDMwWhcNMjIwNTEyMTUyMDMwWjBUMQswCQYDVQQGEwJKUDERMA8GA1UECgwITWlk"    \
	"b2t1cmExHTAbBgNVBAsMFFRyYXZpcyBFVlAgRGV2aWNlIENJMRMwEQYDVQQDDAp0"    \
	"ZXN0ZGV2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzrG8WO/c"    \
	"SdtQxpuDhV25KDq6ItmO8J5APVqiC2f8Pg1JhzJHzt81QiTCY/EitMKbQ7iIpLbj"    \
	"QqSABt4Bfjasrvm8ew7YMPQuvsJ+9Ou6UOyRDk/8dQRnFaj/JSaCgvYefTGPCYoR"    \
	"f5KTjYz5iGY2tbWkIYBFncu/rvkeobXh257KDrC/J0VsKeYWGJpGE/9sxMyEoexh"    \
	"qmd9WDKfSeofPvKnaHAJIiObSZwUvKsrjD60K5cviv1w8BheafkH7JCpIA+T9rdW"    \
	"S4mevBzIuCGE14R/Zvy19yboj2a22bW8zSQPf+7fjaBJ4CUwnKwWPDbkyrG4wcpA"    \
	"ypqFIXz4gADOjwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAfnWfD7MbvkO+kZ55A"    \
	"fzHpaOHeETiMZvKTfrcC6quVjcQFNh8o+x7K450vjJ+TFQFYNXuNKt43ssLxRvTi"    \
	"R35rXqwxIH/5GyTD/dW4l/VF2UngAfSxbbDgsmeUgIZJ5O65P0V9RSlIkN3qxeAr"    \
	"WRwuRoueVla8jzrWAGLJ00YuDqV2H0ewq/J8bat3wXl4pRtb9AL9CrdUjR//6Nrt"    \
	"qRaEuL6ze2mi2Wl6wsiHwe//PYmB1Y+7XMed35O7SlO0xFKyYVgOXRIQe9i+SN1u"    \
	"D8rtPQ6YCRffPLTrFKt07/haF1LzbIU7mN+sSPqWJxZbStBvMFvMgNkaq5cJrNmA"    \
	"IP4a"                                                                \
	"-----END CERTIFICATE-----"

char *
test_config_mqtt_cert(void)
{
	int r;
	static char buf[FILENAME_MAX];

	r = snprintf(buf, sizeof(buf), "%s/dummy.pem",
		     path_get(MODULE_INSTANCE_PATH_ID));
	if (r < 0 || (unsigned)r >= sizeof(buf))
		return NULL;
	return buf;
}

int
setup(void **state)
{
	path_init(getenv("EVP_DATA_DIR"));
	int res = systemf("mkdir -p %s", path_get(MODULE_INSTANCE_PATH_ID));
	assert_int_equal(res, 0);
	putenv("EVP_MQTT_HOST=" TEST_CONFIG_MQTT_HOST);
	putenv("EVP_MQTT_PORT=" TEST_CONFIG_MQTT_PORT);
	setenv("EVP_MQTT_TLS_CA_CERT", test_config_mqtt_cert(), 1);
	putenv("EVP_IOT_PLATFORM=tb");
	putenv("EVP_MQTT_MFS_QOS=" TEST_CONFIG_MQTT_MFS_QOS);
	return systemf("echo -n %s > %s", TEST_CONFIG_MQTT_PEM,
		       test_config_mqtt_cert());
}

void
test_load_simple_config(void **state)
{
	struct config *host = get_config(EVP_CONFIG_MQTT_HOST);
	assert_non_null(host);
	const char *hostname = load_simple_config(host);
	assert_non_null(hostname);
	assert_string_equal(hostname, TEST_CONFIG_MQTT_HOST);
	free_config(host);
}

void
test_config_get_string(void **state)
{
	char *hostname = config_get_string(EVP_CONFIG_MQTT_HOST);
	assert_non_null(hostname);
	assert_string_equal(hostname, TEST_CONFIG_MQTT_HOST);
	free(hostname);
}

void
test_config_get_int(void **state)
{
	int rv;
	intmax_t value;
	int ref = atoi(TEST_CONFIG_MQTT_PORT);
	rv = config_get_int(EVP_CONFIG_MQTT_PORT, &value);
	assert_int_equal(rv, 0);
	assert_int_equal(value, ref);
	rv = config_get_int(EVP_CONFIG_MQTT_HOST, &value);
	assert_int_equal(rv, EINVAL);
	rv = config_get_int(EVP_CONFIG_MQTT_MFS_QOS, &value);
	assert_int_equal(rv, 0);
	assert_int_equal(value, 1);
}

void
test_get_free_config(void **state)
{
	struct config *cfg;
	cfg = get_config(EVP_CONFIG_MQTT_HOST);
	assert_non_null(cfg);
	free_config(cfg);
}

void
test_pk_config(void **state)
{
	struct config *cfg;
	void *buf;
	size_t buflen;
	int ret;

	cfg = get_config(EVP_CONFIG_MQTT_TLS_CA_CERT);
	assert_non_null(cfg);

	ret = load_config(cfg, &buf, &buflen);
	assert_int_equal(ret, 0);
	assert_int_equal(buflen, strlen(TEST_CONFIG_MQTT_PEM) + 1);

	unload_config(cfg, buf, buflen);
	free_config(cfg);
}

int
teardown(void **state)
{
	path_free();
	return 0;
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_load_simple_config),
		cmocka_unit_test(test_config_get_string),
		cmocka_unit_test(test_config_get_int),
		cmocka_unit_test(test_get_free_config),
		cmocka_unit_test(test_pk_config),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
