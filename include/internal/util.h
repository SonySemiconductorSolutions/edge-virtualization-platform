/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cdefs.h"

#undef xmalloc
#undef xcalloc
#undef xrealloc

#define xmalloc(n)      xmalloc_internal(__FILE__, __LINE__, n)
#define xcalloc(n1, n2) xcalloc_internal(__FILE__, __LINE__, n1, n2)
#define xrealloc(p, n)  xrealloc_internal(__FILE__, __LINE__, p, n)
#define xstrdup(s)      xstrdup_internal(__FILE__, __LINE__, s)
#define xstrndup(s, n)  xstrndup_internal(__FILE__, __LINE__, s, n)
#define xasprintf(p, ...)                                                     \
	xasprintf_internal(__FILE__, __LINE__, p, __VA_ARGS__)
#define xmemdup(p, n) xmemdup_internal(__FILE__, __LINE__, p, n)

/*
 * The progname stuff, used by xerrx().
 *
 * The x-prefix was added to avoid conflicts on
 * the system-provided versions.
 */

void xsetprogname(const char *);
const char *xgetprogname(void);

/*
 * Our home-grown implementation of BSD err(3).
 *
 * https://netbsd.gw.com/cgi-bin/man-cgi?err
 * https://man7.org/linux/man-pages/man3/err.3.html
 *
 * The x-prefix was added to avoid conflicts on
 * the system-provided versions.
 */

void xerr(int, const char *, ...) __dead __printflike(2, 3);
void xerrx(int, const char *, ...) __dead __printflike(2, 3);
void xwarn(const char *, ...) __printflike(1, 2);
void xwarnx(const char *, ...) __printflike(1, 2);

/*
 * Convenient wrappers of getenv().
 */

const char *xgetenv(const char *);

/**
 * Parse int value from environment var name
 *
 * @param name	  string to parse
 * @param resultp The address of the variable to store the result on success
 *
 * @return 0 on success, errno on error.
 */
int getenv_int(const char *name, int *resultp);

/*
 * "Abort on ENOMEM" wrappers of the standard functions.
 *
 * Note: memdup is not a standard.
 */

void *xmalloc_internal(const char *, int, size_t);
void *xcalloc_internal(const char *, int, size_t, size_t);
void *xrealloc_internal(const char *, int, void *, size_t);
char *xstrdup_internal(const char *, int, const char *);
char *xstrndup_internal(const char *, int, const char *, size_t);
int xasprintf_internal(const char *, int, char **, const char *, ...)
	__printflike(4, 5);
void *xmemdup_internal(const char *, int, const void *, size_t);

/*
 * Misc stuff.
 */

int hexstr_to_char(const char *hexstr, unsigned char *result, int len);

/**
 * Convert string to uint checking the format
 *
 * @param string	The string to parse
 * @param resultp	Pointer to result value (content is only valid if
 * 					return is 0)
 *
 * @return 0 in case of success, otherwise an errno.
 */
int string_to_uint(const char *string, uintmax_t *resultp);

/**
 * Convert string to int checking the format
 *
 * @param string	The string to parse
 * @param resultp	Pointer to result value (content is only valid if
 * 					return is 0)
 *
 * @return 0 in case of success, otherwise an errno.
 */
int string_to_int(const char *string, intmax_t *resultp);

/**
 * Convert bin array to string of hex ascii representation
 *
 * @param bin		pointer to array to convert
 * @param len		length of the array
 * @param out		buffer to keep end string (size has to be len*2
 * + 1)
 * @param out_size	size of out buffer
 *
 * @return	Pointer to string
 */
char *bin_array_to_hexchar(const unsigned char *bin, size_t len, char *out,
			   size_t out_size);

/**
 * Make a copy of a string were prefix has been changed.
 *
 * @param[in] str A string.
 * @param[in] from The original prefix
 * @param[in] to The target prefix
 *
 * @return A copy of the string were prefix has been changed or
 *         NULL if the original prefix does not match or in case
 *         of memory allocation errors.
 */
char *copy_with_prefix_change(const char *str, const char *from,
			      const char *to);

/**
 * Make a copy (up to a limit) of a string were prefix has been changed.
 *
 * @param[in] str A string
 * @param[in] n The number of chars to copy.
 * @param[in] from The original prefix
 * @param[in] to The target prefix
 *
 * @return A copy of the string were prefix has been changed or
 *         NULL if the original prefix does not match or in case
 *         of memory allocation errors.
 */
char *copy_n_with_prefix_change(const char *str, size_t n, const char *from,
				const char *to);

/**
 * Free a const declared pointer.
 *
 * @param[in] ptr a pointer to an allocated memory in heap
 */
void free_const(const void *ptr);

/**
 * Escapes a string and show only readable ascii characters.
 *
 * @param[in] in the input string to escape
 * @param[in] len the input string length
 * @param[out] in a pointer to write the escaped string to
 * @param[out] in maximum length of the output
 */
void escape_string(const char *in, const size_t len, char *out,
		   const size_t maxlen);
