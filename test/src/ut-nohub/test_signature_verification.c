/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "base64.h"
#include "cdefs.h"
#include "signature_verification.h"

/* Command sequence to generate an ECDSA key pair:
 *
 *  $ openssl ecparam -name prime192v1 -genkey -noout -out key.pem
 *  $ openssl ec -in key.pem -pubout -out public_key_.pem
 */
static const char *public_key_OpenSSL =
	"-----BEGIN PUBLIC KEY-----\n"
	"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEM0jdqRiOQtrcPuryo4II6qEB/Rp+\n"
	"px8bTVVeItbLV/wUb7bUHQ+oYOl8e/VTppv8\n"
	"-----END PUBLIC KEY-----";

/* Command sequence to get the public key in DER form (continued from previous
 * sequence):
 *
 *  $ openssl pkey -pubin -in public_key_.pem -outform DER -pubout -out
 * public_key_.der
 *
 * For getting the C buffer representation:
 *  $ xxd -i public_key_.der
 */
static const unsigned char public_key_OpenSSL_DER[] = {
	0x30, 0x49, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
	0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
	0x01, 0x03, 0x32, 0x00, 0x04, 0x33, 0x48, 0xdd, 0xa9, 0x18, 0x8e,
	0x42, 0xda, 0xdc, 0x3e, 0xea, 0xf2, 0xa3, 0x82, 0x08, 0xea, 0xa1,
	0x01, 0xfd, 0x1a, 0x7e, 0xa7, 0x1f, 0x1b, 0x4d, 0x55, 0x5e, 0x22,
	0xd6, 0xcb, 0x57, 0xfc, 0x14, 0x6f, 0xb6, 0xd4, 0x1d, 0x0f, 0xa8,
	0x60, 0xe9, 0x7c, 0x7b, 0xf5, 0x53, 0xa6, 0x9b, 0xfc};
size_t public_key_OpenSSL_DER_len = 75;

/* Command sequence to get the DER public key base64-encoded (continued from
 * previous sequence):
 *
 *  $ openssl pkey -pubin -in public_key_.pem -outform DER -pubout | openssl
 * enc -A -a
 */
static const char *public_key_OpenSSL_DERb64 =
	"MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEM0jdqRiOQtrcPuryo4II6qEB/"
	"Rp+px8bTVVeItbLV/wUb7bUHQ+oYOl8e/VTppv8";

/* Command sequence to get a signature (continued from previous sequence):
 *
 *  $ printf "%s" testval | openssl dgst -SHA256 -sign key.pem -out
 * signature.dat $ xxd -i signature.dat
 */
static const char *input_message = "testval";
static const unsigned char signature[] = {
	0x30, 0x35, 0x02, 0x18, 0x2e, 0xfb, 0xb2, 0xfc, 0xc1, 0x08, 0xb1,
	0xd4, 0xba, 0x88, 0xd2, 0x49, 0x22, 0x5f, 0xd6, 0x4e, 0x6e, 0x72,
	0x7f, 0x6a, 0x02, 0x66, 0x64, 0x37, 0x02, 0x19, 0x00, 0xa4, 0xfc,
	0x5a, 0xa4, 0x69, 0x7f, 0xef, 0xa0, 0xab, 0x0f, 0x78, 0x5b, 0xe4,
	0x62, 0xc4, 0x00, 0x57, 0x30, 0x13, 0xce, 0x73, 0xdb, 0x02, 0x77};
unsigned int signature_len = 55;

void
test_parse_pemfile_string_valid(void **status)
{
	int ret;
	mbedtls_pk_context public_key;

	ret = parse_public_key((const unsigned char *)public_key_OpenSSL,
			       strlen(public_key_OpenSSL) + 1, &public_key);
	mbedtls_pk_free(&public_key);
	assert_int_equal(ret, 0);
}

void
test_parse_pemfile_string_invalid(void **status)
{
	int ret;
	mbedtls_pk_context public_key;

	const char *public_key_OpenSSL = "Not valid";

	ret = parse_public_key((const unsigned char *)public_key_OpenSSL,
			       strlen(public_key_OpenSSL) + 1, &public_key);
	mbedtls_pk_free(&public_key);
	assert_true(ret != 0);
}

void
test_parse_derfile_bytes_valid(void **status)
{
	int ret;
	mbedtls_pk_context public_key;
	ret = parse_public_key(public_key_OpenSSL_DER,
			       public_key_OpenSSL_DER_len, &public_key);
	mbedtls_pk_free(&public_key);
	assert_int_equal(ret, 0);
}

void
test_parse_derfile_base64enc_string_valid(void **status)
{
	int ret;

	mbedtls_pk_context public_key;

	ret = parse_public_key_base64_enc(public_key_OpenSSL_DERb64,
					  strlen(public_key_OpenSSL_DERb64),
					  &public_key);
	mbedtls_pk_free(&public_key);

	assert_int_equal(ret, 0);
}

void
test_parse_derfile_base64enc_string_empty(void **status)
{
	int ret;

	mbedtls_pk_context public_key;
	char empty_string[] = "";
	ret = parse_public_key_base64_enc(empty_string, strlen(empty_string),
					  &public_key);
	mbedtls_pk_free(&public_key);

	assert_int_not_equal(ret, 0);
}

void
test_signature(void **status)
{
	int ret;

	mbedtls_pk_context public_key;
	ret = parse_public_key(public_key_OpenSSL_DER,
			       public_key_OpenSSL_DER_len, &public_key);
	assert_int_equal(ret, 0);

	ret = validate_signature(input_message, strlen(input_message),
				 signature, signature_len, &public_key);
	assert_int_equal(ret, 0);

	mbedtls_pk_free(&public_key);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_parse_pemfile_string_valid),
		cmocka_unit_test(test_parse_pemfile_string_invalid),
		cmocka_unit_test(test_parse_derfile_bytes_valid),
		cmocka_unit_test(test_parse_derfile_base64enc_string_valid),
		cmocka_unit_test(test_parse_derfile_base64enc_string_empty),
		cmocka_unit_test(test_signature),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
