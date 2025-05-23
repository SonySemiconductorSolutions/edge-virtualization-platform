/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "main_loop.h"
#include "module_log_queue.h"
#include "module_log_streaming.h"
#include "telemetry.h"
#include "timeutil.h"
#include "xlog.h"

#define LOG_STREAMING_PERIOD CONFIG_EVP_AGENT_MODULE_LOG_REPORT_PERIOD

static uint64_t g_last_poll = 0;

static void
fastforward_to_next_log(void)
{
	size_t rv;
	do {
		char ch;
		rv = module_log_queue_read(&ch, 1);
		if (rv == 1 && ch == '\n') {
			// Found next segment
			return;
		}
	} while (rv);
}

static void
schedule_next(bool reported)
{
	// expect_poll[k-1]       expect_poll[k] now      expect_poll[k+1]
	//                               |<------>|<------------->|
	//                               | drift     correction   |
	//      |<------- PERIOD ------->|<------- PERIOD ------->|
	uint64_t now = gettime_ms();
	uint64_t drift = (now - g_last_poll) % LOG_STREAMING_PERIOD;
	uint64_t correction = LOG_STREAMING_PERIOD - drift;
	if (reported) {
		g_last_poll = now;
	}
	main_loop_add_abs_timeout_ms("PERIODIC-LOG-POLL", now + correction);
}

int
module_log_streaming_flush(struct evp_agent_context *ctxt)
{
	// Find beginning of next log entry
	fastforward_to_next_log();

	size_t queued_len = module_log_queue_get_len();
	if (queued_len == 0) {
		return 0;
	}

	int ret;
	char *buffer = xmalloc(queued_len + 3);
	buffer[0] = '[';
	module_log_queue_read(&buffer[1], queued_len);
	buffer[queued_len + 1] = ']';
	buffer[queued_len + 2] = '\0';
	JSON_Value *value = json_parse_string(buffer);
	if (value == NULL) {
		xlog_error("Invalid JSON string: %s", buffer);
		free(buffer);
		ret = -1;
	} else {
		free(buffer);
		buffer = json_serialize_to_string(value);
		json_value_free(value);
		struct telemetry_entries *telemetries = telemetry_create(1);
		telemetries->entries[0].module_instance = xstrdup("device");
		telemetries->entries[0].topic = xstrdup("log");
		telemetries->entries[0].value = buffer;
		module_log_send_telemetry(ctxt, telemetries);
		telemetry_destroy(telemetries);
		ret = 0;
	}
	return ret;
}

void
module_log_streaming_report(struct evp_agent_context *ctxt)
{
	bool report = (gettime_ms() - g_last_poll) >= LOG_STREAMING_PERIOD;
	if (report) {
		module_log_streaming_flush(ctxt);
	}
	schedule_next(report);
}
