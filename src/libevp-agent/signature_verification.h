/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file signature_verification.h
 * @brief Provides facilities for performing ECDSA signature verification
 *
 * It is used for the rawContainerSpec feature.
 */
#if !defined(__SIGNATURE_VERIFICATION_H__)
#define __SIGNATURE_VERIFICATION_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>

/**
 * @brief Parse a public key
 *
 * @param buf    Contains the DER or PEM formatted public key string.
 * @param buflen Size of the 'buf'.
 * @param public_key  Uninitialized public key object.
 *
 * This will initialize `public_key` by parsing `buf`.
 *
 * @return retcode from mbedtls_pk_parse_public_key()
 */
int parse_public_key(const unsigned char *buff, size_t buflen,
		     mbedtls_pk_context *public_key);

/**
 * @brief Parse a public key that is base64-encoded
 *
 * @param buf    Contains the DER or PEM formatted public key string that is
 * base64-encoded.
 * @param buflen Size of the 'buf'.
 * @param public_key  Uninitialized public key object.
 *
 * This will initialize `public_key` by base64-decoding `buf`, then parsing the
 * result.
 *
 * @return retcode from mbedtls_pk_parse_public_key()
 */
int parse_public_key_base64_enc(const char *buff, size_t buflen,
				mbedtls_pk_context *public_key);

/**
 * @brief Perform signature verification (SHA256 digest)
 *
 * @param buf         Contains the message for which signature is being
 * verified.
 * @param buflen      Size of the 'buf'.
 * @param signature   Buffer that contains the signature data.
 * @param signat_len  Size of the 'signature'.
 * @param public_key  Initialized public key object.
 *
 * This will use the `public_key` to verify that the provided `signature`
 * matches for the given payload in `buf`.
 *
 * @return retcode from mbedtls_pk_verify() or mbedtls_sha256_ret()
 */
int validate_signature(const char *buff, size_t buflen,
		       const unsigned char *signature,
		       unsigned int signature_len,
		       mbedtls_pk_context *public_key);

#endif /* __SIGNATURE_VERIFICATION_H__ */
