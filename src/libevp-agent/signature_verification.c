/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

#include "base64.h"
#include "cdefs.h"
#include "signature_verification.h"

int
parse_public_key(const unsigned char *buff, size_t buflen,
		 mbedtls_pk_context *public_key)
{
	mbedtls_pk_init(public_key);
	return mbedtls_pk_parse_public_key(public_key, buff, buflen);
}

int
parse_public_key_base64_enc(const char *buff, size_t buflen,
			    mbedtls_pk_context *public_key)
{
	int ret;
	void *decoded_DER = NULL;
	size_t decoded_DER_len;

	ret = base64_decode(buff, buflen, &decoded_DER, &decoded_DER_len);
	if (ret != 0)
		goto out;

	ret = parse_public_key(decoded_DER, decoded_DER_len, public_key);

out:
	free(decoded_DER);
	return ret;
}

int
validate_signature(const char *buff, size_t buflen,
		   const unsigned char *signature, unsigned int signature_len,
		   mbedtls_pk_context *public_key)
{
	enum { SHA256_DIGEST_LEN = 32 };

	unsigned char digest[SHA256_DIGEST_LEN];
	mbedtls_sha256((const unsigned char *)buff, buflen, digest, 0);

	return mbedtls_pk_verify(public_key, MBEDTLS_MD_SHA256, digest,
				 SHA256_DIGEST_LEN, signature, signature_len);
}
