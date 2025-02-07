/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file certificates.h
 * @brief Handles the global x509 certificate chain store
 *
 * It is mostly used for the Storage Token feature.
 */
#if !defined(__CERTIFICATES_H__)
#define __CERTIFICATES_H__

struct cert;

/**
 * @brief Look a certificate up by its given ID string
 *
 * @param id     Certificate ID string
 * @param certp  Filled with a pointer to struct cert on success.
 *               The struct is reference-counted. It's the caller's
 *               responsibility to release the reference using cert_release().
 *
 * @return 0 if successful, error on error.
 */
int cert_get(const char *id, struct cert **certp);

/**
 * @brief Add a certificate to the cache
 *
 * @param id     Certificate ID string
 * @param buf    The x509 certificate to associate with the 'id'.
 * @param buflen Size of the 'buf'.
 * @param certp  Filled with a pointer to struct cert on success.
 *               The struct is reference-counted. It's the caller's
 *               responsibility to release the reference using cert_release().
 *
 * If the certificate with 'id' was already in the cache,
 * this function works as an equivalent of cert_get().
 *
 * @return 0 if successful, errno on error.
 */
int cert_set(const char *id, const void *buf, size_t buflen,
	     struct cert **certp);

/**
 * @brief Release a reference to the certificate.
 */
void cert_release(struct cert *cert);

/**
 * @brief Return a pointer to the corresponding mbedtls cert object.
 */
struct mbedtls_x509_crt *cert_mbedtls(struct cert *cert);

#endif /* __CERTIFICATES_H__ */
