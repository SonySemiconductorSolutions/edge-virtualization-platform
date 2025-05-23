/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* for asprintf */
#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "platform.h"

static const char *progname;

void
xsetprogname(const char *name)
{
	progname = name;
}

const char *
xgetprogname(void)
{
	return progname;
}

void
xerrx(int eval, const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(eval);
}

void
xerr(int eval, const char *fmt, ...)
{
	const char *error_string = strerror(errno);

	va_list ap;

	fprintf(stderr, "%s: %s: ", progname, error_string);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");

	exit(eval);
}

void
xwarnx(const char *fmt, ...)
{
	va_list ap;

	fprintf(stderr, "%s: ", progname);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void
xwarn(const char *fmt, ...)
{
	const char *error_string = strerror(errno);

	va_list ap;

	fprintf(stderr, "%s: %s: ", progname, error_string);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

const char *
xgetenv(const char *name)
{
	const char *v = getenv(name);
	if (v == NULL) {
		/* Abort assessment:
		 * This is used during agent startup to load mandatory env
		 * vars. This can abort.
		 */
		//  TODO: Review exit (xerr)
		//        config error. Prefer xlog_abort[if]
		xerrx(1, "%s is not set", name);
	}
	return v;
}

int
string_to_uint(const char *string, uintmax_t *resultp)
{
	uintmax_t val;
	char *end;

#if defined(__clang_analyzer__)
	*resultp = 99999;
#endif
	errno = 0;
	val = strtoumax(string, &end, 10);
	if ((string == end) || (*end != '\0')) {
		return EINVAL; /* not a number */
	}

	if (errno != 0) {
		return errno;
	}

	*resultp = val;
	return 0;
}

int
string_to_int(const char *string, intmax_t *resultp)
{
	intmax_t val;
	char *end;

#if defined(__clang_analyzer__)
	*resultp = 99999;
#endif
	errno = 0;
	val = strtoimax(string, &end, 10);
	if ((string == end) || (*end != '\0')) {
		return EINVAL; /* not a number */
	}

	if (errno != 0) {
		return errno;
	}

	*resultp = val;
	return 0;
}

int
getenv_int(const char *name, int *resultp)
{
	const char *env_val = getenv(name);

	if (env_val == NULL) {
		return ENOENT;
	}
	intmax_t val;
	int ret = string_to_int(env_val, &val);
	if (ret != 0) {
		return ret;
	}
	if (val > INT_MAX || val < INT_MIN) {
		return ERANGE;
	}
	*resultp = (int)val;
	return 0;
}

void *
xmalloc_internal(const char *file, int line, size_t sz)
{
	void *vp = malloc(sz);
	if (vp == NULL) {
		plat_out_of_memory(file, line, "xmalloc", sz);
	}
	return vp;
}

void *
xcalloc_internal(const char *file, int line, size_t num, size_t sz)
{
	void *vp = calloc(num, sz);
	if (vp == NULL) {
		plat_out_of_memory(file, line, "xcalloc", sz * num);
	}
	return vp;
}

void *
xrealloc_internal(const char *file, int line, void *op, size_t sz)
{
	void *vp = NULL;

	/*
	 * several realloc implementations, like linux and nuttx,
	 * call free when sz is 0 and return NULL. To avoid a
	 * double free and to make the code more similar in any
	 * platform we add that check here and avoid the call to
	 * realloc()
	 */
	if (sz != 0) {
		vp = realloc(op, sz);
	}
	if (sz == 0 || vp == NULL) {
		/* cppcheck-suppress doubleFree */
		free(op);
		plat_out_of_memory(file, line, "xrealloc", sz);
	}
	return vp;
}

char *
xstrdup_internal(const char *file, int line, const char *p)
{
	char *cp = strdup(p);
	if (cp == NULL) {
		plat_out_of_memory(file, line, "xrealloc", strlen(p));
	}
	return cp;
}

char *
xstrndup_internal(const char *file, int line, const char *p, size_t sz)
{
	char *cp = strndup(p, sz);
	if (cp == NULL) {
		plat_out_of_memory(file, line, "xstrndup", sz);
	}
	return cp;
}

void *
xmemdup_internal(const char *file, int line, const void *p0, size_t sz)
{
	size_t allocsz = sz;
#if defined(__NuttX__)
	/*
	 * Note: NuttX returns NULL for malloc(0). It's the traditional
	 * System-V behavior, which is allowed by the standards.
	 * On the other hand, the majority of modern implementations,
	 * including the following ones, returns a non-NULL pointer
	 * in that case.
	 *
	 *     Ubuntu (glibc)
	 *     Alpine (musl)
	 *     macOS (jemalloc?)
	 *     NetBSD (jemalloc or phkmalloc)
	 */
	if (allocsz == 0) {
		allocsz = 1;
	}
#endif
	void *p = malloc(allocsz);
	if (p == NULL) {
		plat_out_of_memory(file, line, "xmemdup", sz);
	}

	memcpy(p, p0, sz);
	return p;
}

int
xasprintf_internal(const char *file, int line, char **ret, const char *format,
		   ...)
{
	va_list ap;
	int rv;

	va_start(ap, format);
	rv = vasprintf(ret, format, ap);
	va_end(ap);
	if (rv == -1) {
		plat_out_of_memory(file, line, "vasprintf", 0);
	}
	return rv;
}

int
hexstr_to_char(const char *hexstr, unsigned char *result, int len)
{
	const char *p = hexstr;
	int i;

	for (i = 0; i < len; i++) {
		char hex[3];
		unsigned int v;
		char *ep;

		strncpy(hex, p, 2);
		hex[2] = 0;
		if (strlen(hex) != 2) {
			return EINVAL;
		}
		errno = 0;
		unsigned long ul = strtoul(hex, &ep, 16);
		if (hex == ep || *ep != 0 || errno != 0 || ul > 255) {
			return EINVAL;
		}
		v = ul;
		result[i] = v;
		p += 2;
	}
	if (*p != 0) {
		return EINVAL;
	}
	return 0;
}

char *
bin_array_to_hexchar(const unsigned char *bin, size_t len, char *out,
		     size_t out_size)
{
	char *txt = out;
	size_t i;

	const char *out_original = out;
	int written;
	size_t out_remaining_size;

	for (i = 0; i < len; i++) {
		out_remaining_size = out_size - (txt - out_original);
		written = snprintf(txt, out_remaining_size, "%02x", bin[i]);
		if (written < 0 || (unsigned)written >= out_remaining_size) {
			xwarnx("snprintf failed: written=%d remaining=%zu",
			       written, out_remaining_size);
			return NULL;
		}
		txt += written;
	}
	return out;
}

char *
copy_n_with_prefix_change(const char *str, size_t n, const char *from,
			  const char *to)
{
	char *copy = NULL;
	size_t from_len = strlen(from);
	if (from_len <= n && memcmp(str, from, from_len) == 0) {
		if (xasprintf(&copy, "%s%.*s", to, (int)(n - from_len),
			      str + from_len) < 0) {
			copy = NULL;
		}
	}
	return copy;
}

char *
copy_with_prefix_change(const char *str, const char *from, const char *to)
{
	return copy_n_with_prefix_change(str, strlen(str), from, to);
}

void
free_const(const void *ptr)
{
	free(__UNCONST(ptr));
}

void
escape_string(const char *in, const size_t len, char *out, const size_t maxlen)
{
	size_t i, j;
	char c;

	for (i = 0, j = 0; i < len; i++, j++) {
		if (j >= maxlen) {
			/* Abort assessment:
			 * A buffer too small to fit escaped string should not
			 * cause the agent to exit.
			 */
			//  TODO: Review exit (xerr)
			//        Remove and return error
			xerrx(1, "buffer too small");
		}
		c = in[i];
		if (c && strchr(",=+<>#;\"\\", c)) {
			if (j + 1 >= maxlen) {
				/* Abort assessment:
				 * A buffer too small to fit escaped string
				 * should not cause the agent to exit.
				 */
				//  TODO: Review exit (xerr)
				//        Remove and return error
				xerrx(1, "buffer too small");
			}
			out[j++] = '\\';
		}
		if (c < 32 || c >= 127) {
			out[j] = '?';
		} else {
			out[j] = c;
		}
	}
	out[j] = '\0';
}
