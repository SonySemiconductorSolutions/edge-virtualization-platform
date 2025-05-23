/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include <internal/util.h>

#include "hub.h"
#include "module_log_queue.h"
#include "xlog.h"

#define MODULE_LOG_CAPACITY                                                   \
	(CONFIG_EVP_AGENT_MODULE_LOG_REPORT_LEN -                             \
	 sizeof("{\"device/log\":[]}"))

#define LOG_APP      "test"
#define LOG_1_STREAM "stdout"
#define LOG_1_MSG    "A log message with \"double quotes\""
#define LOG_2_STREAM "stderr"
#define LOG_2_MSG    "ERROR:Something bad happened"
#define LOG_TIME     "2023-01-01T00:00:00.000000Z"

#define LOG_1                                                                 \
	",\n"                                                                 \
	"{"                                                                   \
	"\"log\":\"A log message with \\\"double quotes\\\"\","               \
	"\"stream\":\"" LOG_1_STREAM "\","                                    \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"time\":\"2023-01-01T00:00:00.000000Z\""                            \
	"}"

#define LOG_2                                                                 \
	",\n"                                                                 \
	"{"                                                                   \
	"\"log\":\"" LOG_2_MSG "\","                                          \
	"\"stream\":\"" LOG_2_STREAM "\","                                    \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"time\":\"2023-01-01T00:00:10.000000Z\""                            \
	"}"

void
test_log_queue_raw_bytes(void **state)
{
	size_t log1_len = strlen(LOG_1);
	size_t log2_len = strlen(LOG_2);

	assert_int_equal(module_log_queue_write(LOG_1, log1_len), log1_len);
	assert_int_equal(module_log_queue_get_len(), log1_len);

	assert_int_equal(module_log_queue_write(LOG_2, log2_len), log2_len);
	assert_int_equal(module_log_queue_get_len(), log1_len + log2_len);

	char buffer[1024];
	size_t read_len = module_log_queue_read(buffer, sizeof(buffer));
	assert_int_equal(read_len, log1_len + log2_len);
}

void
test_log_queue_put(void **state)
{
	size_t log1_len = strlen(LOG_1);
	size_t log2_len = strlen(LOG_2);

	assert_int_equal(
		module_log_queue_put(LOG_APP, LOG_1_STREAM, LOG_1_MSG),
		log1_len);
	assert_int_equal(module_log_queue_get_len(), log1_len);

	assert_int_equal(
		module_log_queue_put(LOG_APP, LOG_2_STREAM, LOG_2_MSG),
		log2_len);
	assert_int_equal(module_log_queue_get_len(), log1_len + log2_len);

	char buffer[1024];
	size_t read_len = module_log_queue_read(buffer, sizeof(buffer));
	assert_int_equal(read_len, log1_len + log2_len);
}

void
test_log_queue_rollover(void **state)
{
	assert_int_equal(module_log_queue_get_len(), 0);
	assert_int_equal(module_log_queue_is_full(), false);

	// Fill up buffer and expect queue to roll over.
	// Oldest bytes are overwritten by newest.
	size_t log_len = strlen(LOG_1);
	size_t queue_len, total = 0;
	while (total < MODULE_LOG_CAPACITY) {
		total += log_len;
		queue_len = total;
		if (total > MODULE_LOG_CAPACITY) {
			queue_len = MODULE_LOG_CAPACITY;
		}
		assert_int_equal(module_log_queue_write(LOG_1, log_len),
				 log_len);
		assert_int_equal(module_log_queue_get_len(), queue_len);
	}
	// Now queue must be full
	assert_int_equal(module_log_queue_get_len(), MODULE_LOG_CAPACITY);
	assert_int_equal(module_log_queue_is_full(), true);

	// Check that oldest log is truncated
	char buffer[1024] = {0};
	const char *log = LOG_1;
	size_t overwitten = total % MODULE_LOG_CAPACITY;
	size_t read_len = module_log_queue_read(buffer, log_len - overwitten);
	assert_int_equal(read_len, log_len - overwitten);
	assert_memory_equal(buffer, &log[overwitten], read_len);
}

int
main(void)
{
	module_log_queue_init();

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_log_queue_raw_bytes),
		cmocka_unit_test(test_log_queue_put),
		cmocka_unit_test(test_log_queue_rollover),
	};
	// run tests
	return cmocka_run_group_tests(tests, NULL, NULL);
}
