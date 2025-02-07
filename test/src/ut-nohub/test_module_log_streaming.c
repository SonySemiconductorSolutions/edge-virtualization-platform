/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <hub.h>
#include <req.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "module_log_queue.h"
#include "module_log_streaming.h"
#include "telemetry.h"
#include "timeutil.h"
#include "xlog.h"

#define MODULE_LOG_CAPACITY                                                   \
	(CONFIG_EVP_AGENT_MODULE_LOG_REPORT_LEN -                             \
	 sizeof("{\"device/log\":[]}"))

#define LOG_APP      "test"
#define LOG_1_STREAM "stdout"
#define LOG_1_MSG    "A log message"
#define LOG_2_STREAM "stdout"
#define LOG_2_MSG    "ERROR:Something bad happened"
#define LOG_TIME     "2023-01-01T00:00:00.000000Z"

#define LOG_1                                                                 \
	"{"                                                                   \
	"\"log\":\"" LOG_1_MSG "\","                                          \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"stream\":\"" LOG_1_STREAM "\","                                    \
	"\"time\":\"" LOG_TIME "\""                                           \
	"}"

#define LOG_2                                                                 \
	"{"                                                                   \
	"\"log\":\"" LOG_2_MSG "\","                                          \
	"\"app\":\"" LOG_APP "\","                                            \
	"\"stream\":\"" LOG_2_STREAM "\","                                    \
	"\"time\":\"" LOG_TIME "\""                                           \
	"}"

void
__wrap_getrealtime(struct timespec *tp)
{
	/* return UNIX time for 2023-01-01T00:00:00.000000Z */
	tp->tv_nsec = 0;
	tp->tv_sec = 1672531200;
}

void
__wrap_module_log_send_telemetry(struct evp_agent_context *ctxt,
				 struct telemetry_entries *telemetries)
{
	check_expected(telemetries->n);
	check_expected(telemetries->entries[0].module_instance);
	check_expected(telemetries->entries[0].topic);
	check_expected(telemetries->entries[0].value);
}

void
test_log_streaming_flush(void **state)
{
	module_log_queue_put(LOG_APP, LOG_1_STREAM, LOG_1_MSG);
	module_log_queue_put(LOG_APP, LOG_2_STREAM, LOG_2_MSG);

	const char *payload = "[" LOG_1 "," LOG_2 "]";
	expect_value(__wrap_module_log_send_telemetry, telemetries->n, 1);
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].module_instance, "device");
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].topic, "log");
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].value, payload);
	module_log_streaming_flush(NULL);
}

void
test_log_streaming_flush_truncated(void **state)
{
	char *log_1 = ",\n" LOG_1;
	char *log_2 = ",\n" LOG_2;
	char *truncated = &log_1[7];
	module_log_queue_write(truncated, strlen(truncated));
	module_log_queue_write(log_1, strlen(log_1));
	module_log_queue_write(log_2, strlen(log_2));

	const char *payload = "[" LOG_1 "," LOG_2 "]";
	expect_value(__wrap_module_log_send_telemetry, telemetries->n, 1);
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].module_instance, "device");
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].topic, "log");
	expect_string(__wrap_module_log_send_telemetry,
		      telemetries->entries[0].value, payload);
	module_log_streaming_flush(NULL);
}

int
main(void)
{
	module_log_queue_init();

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_log_streaming_flush),
		cmocka_unit_test(test_log_streaming_flush_truncated),
	};
	// run tests
	return cmocka_run_group_tests(tests, NULL, NULL);
}
