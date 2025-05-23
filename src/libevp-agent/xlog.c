/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>

#include "cdefs.h"
#include "platform.h"
#include "xlog.h"

#define FIELD_SEP    "|"
#define SUBFIELD_SEP ":"

#ifdef CONFIG_EVP_AGENT_XLOG_COLORED_OUTPUT
#include "xlog_color.h"
#endif

static const char *
xlog_level_to_tag(int lvl)
{
	static const char *const table[] = {
		[XLOG_LEVEL_TRACE] = "T", [XLOG_LEVEL_DEBUG] = "D",
		[XLOG_LEVEL_INFO] = "I",  [XLOG_LEVEL_WARNING] = "W",
		[XLOG_LEVEL_ERROR] = "E", [XLOG_LEVEL_FATAL] = "F",
	};

	if (lvl < 0 || (unsigned)lvl >= __arraycount(table)) {
		return "?";
	}

	return table[lvl];
}

#ifndef CONFIG_EVP_AGENT_XLOG_TO_SYSLOG

static void
vxlog(FILE *out, const char *fmt, va_list ap)
{
	vfprintf(out, fmt, ap);
	fprintf(out, "\n");
}

static void
xxlog_header(FILE *out, int lvl, const char *file, int line)
{
	struct timespec now;
	int ret;
	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (0 != ret) {
		now.tv_sec = 0;
		now.tv_nsec = 0;
	}

	fprintf(out,
		"[%10lu.%09lu" FIELD_SEP "%04X" FIELD_SEP "%s" SUBFIELD_SEP
		"%04d" FIELD_SEP "%s] ",
		(unsigned long)now.tv_sec, (unsigned long)now.tv_nsec,
		(unsigned short)(uintptr_t)pthread_self(), file, line,
		xlog_level_to_tag(lvl));
}
#else

static int
xlog_level_to_syslog_priority(int lvl)
{
	static const int table[] = {
		[XLOG_LEVEL_TRACE] = LOG_DEBUG,
		[XLOG_LEVEL_DEBUG] = LOG_DEBUG,
		[XLOG_LEVEL_INFO] = LOG_INFO,
		[XLOG_LEVEL_WARNING] = LOG_WARNING,
		[XLOG_LEVEL_ERROR] = LOG_ERR,
		[XLOG_LEVEL_FATAL] = LOG_EMERG,
	};
	// TODO: Replace assert (programming error)
	assert(lvl >= 0);
	// TODO: Replace assert (programming error)
	assert(lvl < __arraycount(table));
	return table[lvl];
}

#define LOG_FORMAT_SIZE 256

static void
xxlog(int lvl, const char *file, int line, const char *fmt, va_list ap)
{
	struct timespec now;
	int ret;
	ret = clock_gettime(CLOCK_REALTIME, &now);
	if (ret != 0) {
		now.tv_sec = 0;
		now.tv_nsec = 0;
	}

	char logfmt[LOG_FORMAT_SIZE] = {0};
	int hdrsz = 0;
	int bdsz = 0;

	/* formatted log header with parameters filled in */
	hdrsz = snprintf(&logfmt[0], LOG_FORMAT_SIZE,
			 "[%10lu.%09lu" FIELD_SEP "%04X" FIELD_SEP
			 "%s" SUBFIELD_SEP "%04d" FIELD_SEP "%s] ",
			 (unsigned long)now.tv_sec, (unsigned long)now.tv_nsec,
			 (unsigned short)(uintptr_t)pthread_self(), file, line,
			 xlog_level_to_tag(lvl));

	if (hdrsz < 0) {
		syslog(LOG_ERR,
		       "Cannot format log header with parameters filled in "
		       "file %s, line %d.\n",
		       file, line);
		return;
	}

	/* log body format without parameters */
	bdsz = snprintf(&logfmt[hdrsz], LOG_FORMAT_SIZE - hdrsz, "%s\n", fmt);

	if (bdsz < 0) {
		syslog(LOG_ERR,
		       "Cannot print log body format without parameters in "
		       "file %s, line %d.\n",
		       file, line);
		return;
	}

	if ((hdrsz + bdsz) >= LOG_FORMAT_SIZE) {
		syslog(LOG_ERR,
		       "The length of log format over %d! file %s, line %d, "
		       "length %d.\n",
		       LOG_FORMAT_SIZE, file, line, hdrsz + bdsz);
		return;
	}

	vsyslog(xlog_level_to_syslog_priority(lvl), logfmt, ap);
}
#endif

#if !defined(__NuttX__)
static void
unlock(void *vp)
{
	funlockfile(vp);
}
#endif

#ifdef CONFIG_EVP_AGENT_XLOG_COLORED_OUTPUT
static void
print_color(int lvl, FILE *out)
{
	static const char *const colors[] = {
		[XLOG_LEVEL_TRACE] = XLOG_COLOR_T,
		[XLOG_LEVEL_DEBUG] = XLOG_COLOR_D,
		[XLOG_LEVEL_INFO] = XLOG_COLOR_I,
		[XLOG_LEVEL_WARNING] = XLOG_COLOR_W,
		[XLOG_LEVEL_ERROR] = XLOG_COLOR_E,
		[XLOG_LEVEL_FATAL] = XLOG_COLOR_F};

	fputs(colors[lvl], out);
}
#endif

void
xlog(int lvl, const char *file, int line, const char *fmt, va_list ap)
{
	int _errno = errno;
#ifndef CONFIG_EVP_AGENT_XLOG_TO_SYSLOG
#if !defined(__NuttX__) /* NuttX doesn't have flockfile */
	/*
	 * Note: xlog can be used in cancellable threads.
	 * (eg. SDK socket worker)
	 * Ensure unlock using pthread_cleanup_push.
	 * Otherwise, if this thread is cancelled during the stream I/O
	 * (fwrite etc) below, the stream is left locked and will cause
	 * deadlock.
	 */
	flockfile(stderr);
	pthread_cleanup_push(unlock, stderr);
#endif

#ifdef CONFIG_EVP_AGENT_XLOG_COLORED_OUTPUT
	print_color(lvl, stderr);
#endif

	xxlog_header(stderr, lvl, file, line);
	vxlog(stderr, fmt, ap);

#ifdef CONFIG_EVP_AGENT_XLOG_COLORED_OUTPUT
	fputs(XLOG_RESET_COLOR, stderr);
#endif

#if !defined(__NuttX__)
	pthread_cleanup_pop(1);
#endif
	fflush(stderr);
#else
	xxlog(lvl, file, line, fmt, ap);
#endif
	errno = _errno;
}

void
xxlog_print(int lvl, const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	plat_xlog(lvl, file, line, fmt, ap);
	va_end(ap);
}

void
xxlog_print_abort(int lvl, const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	plat_xlog(lvl, file, line, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}
