/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <stdarg.h>

#include "cdefs.h"

#define XLOG_LEVEL_TRACE   0 /* Very basic steps */
#define XLOG_LEVEL_DEBUG   1 /* Detailed point to analyze errors */
#define XLOG_LEVEL_INFO    2 /* Info about process */
#define XLOG_LEVEL_WARNING 3 /* Expected fail, not critical */
#define XLOG_LEVEL_ERROR   4 /* Unexpected fail (recoverable) */
#define XLOG_LEVEL_FATAL   5 /* Unexpected fail (NOT recoverable) */

#define XLOG_LEVEL_ENABLED CONFIG_EVP_AGENT_XLOG_LEVEL

void xxlog_print(int lvl, const char *file, int line, const char *fmt, ...)
	__printflike(4, 5);
void xxlog_print_abort(int lvl, const char *file, int line, const char *fmt,
		       ...) __dead __printflike(4, 5);
void xlog(int lvl, const char *file, int line, const char *fmt, va_list ap);

/* To force compiler validate against __printflike and allow optimize it */
#define _noop(a, b, c, d, ...)                                                \
	do {                                                                  \
		if (0)                                                        \
			xxlog_print(a, b, c, d, ##__VA_ARGS__);               \
	} while (0)

/* Macro to avoid "print" */
#define xlog_dummy(fmt, ...) _noop(-1, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#if XLOG_LEVEL_ENABLED <= XLOG_LEVEL_TRACE
#define xlog_trace(fmt, ...)                                                  \
	xxlog_print(XLOG_LEVEL_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define xlog_trace(fmt, ...) xlog_dummy(fmt, ##__VA_ARGS__)
#endif

#if XLOG_LEVEL_ENABLED <= XLOG_LEVEL_DEBUG
#define xlog_debug(fmt, ...)                                                  \
	xxlog_print(XLOG_LEVEL_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define xlog_debug(fmt, ...) xlog_dummy(fmt, ##__VA_ARGS__)
#endif

#if XLOG_LEVEL_ENABLED <= XLOG_LEVEL_INFO
#define xlog_info(fmt, ...)                                                   \
	xxlog_print(XLOG_LEVEL_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define xlog_info(fmt, ...) xlog_dummy(fmt, ##__VA_ARGS__)
#endif

#if XLOG_LEVEL_ENABLED <= XLOG_LEVEL_WARNING
#define xlog_warning(fmt, ...)                                                \
	xxlog_print(XLOG_LEVEL_WARNING, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define xlog_warning(fmt, ...) xlog_dummy(fmt, ##__VA_ARGS__)
#endif

#define xlog_error(fmt, ...)                                                  \
	xxlog_print(XLOG_LEVEL_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define xlog_fatal(fmt, ...)                                                  \
	xxlog_print(XLOG_LEVEL_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define xlog_abort(fmt, ...)                                                  \
	xxlog_print_abort(XLOG_LEVEL_FATAL, __FILE__, __LINE__, fmt,          \
			  ##__VA_ARGS__)

/* Abort the execution if the condition `c` is true */
#define xlog_abortif(c, fmt, ...)                                             \
	do {                                                                  \
		if ((c)) {                                                    \
			xxlog_print_abort(XLOG_LEVEL_FATAL, __FILE__,         \
					  __LINE__, fmt, ##__VA_ARGS__);      \
		}                                                             \
	} while (c)
