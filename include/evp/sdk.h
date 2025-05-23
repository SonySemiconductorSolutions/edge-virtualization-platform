/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_H__)
#define __SDK_H__

/** @file sdk.h
 *
 *  - None of SDK functions are thread-safe, unless explicitly specified.
 *
 *  - None of SDK functions are async-signal safe.
 *
 *  - None of SDK functions are re-entrant, unless explicitly specified
 *    otherwise.
 *
 *  - None of SDK functions can be used in SDK callback functions like
 *    @ref EVP_CONFIGURATION_CALLBACK, unless explicitly specified otherwise.
 *
 *  - SDK functions might or might not be a pthread cancellation point.
 *    SDK users should not rely on either behaviours.
 *
 * \verbatim embed:rst:leading-asterisk
 * .. note::
 *       SDK functions taking a pointer to :c:type:`EVP_client` are safe
 *       to be called by multiple threads concurrently, as long as they use
 *       different :c:type:`EVP_client`. Concurrent calls with the same
 *       :c:type:`EVP_client` are not safe.
 * \endverbatim
 *
 * \verbatim embed:rst:leading-asterisk
 * .. note::
 *       In general, giving `NULL` to this SDK causes an undefined behavior,
 *       unless explicitly stated otherwise.
 *
 *       Please do not make implicit assumptions about how `NULL` is handled
 *       by the SDK. Such assumptions include:
 *
 *       - `NULL` is ignored
 *       - `NULL` means no-op
 *       - `NULL` is rejected
 * \endverbatim
 *
 * @internal
 *
 * Note: This header file is intended to be shared among possible
 * EVP device platforms, including NuttX and Linux.
 *
 * References:
 *
 *  https://docs.google.com/document/d/1YUcN8JdFOPbmGA5sVZFuvsXAvjXFF1juAGYp7SjEigo/edit#heading=h.dhorjsjskknq
 */

#include "sdk_types.h"

/* sdk_types.h should be included before sdk_base.h */

#include "sdk_base.h"
#include "sdk_blob.h"

#endif /* !defined(__SDK_H__) */
