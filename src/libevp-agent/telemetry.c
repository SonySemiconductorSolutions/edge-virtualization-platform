/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <evp/sdk.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "hub.h"
#include "req.h"
#include "sdk_agent.h"
#include "sys/sys.h"
#include "telemetry.h"
#include "xlog.h"

static int
add_telemetry(struct telemetry_entries *t, const char *module_instance,
	      const struct EVP_telemetry_entry *entry)
{
	xlog_abortif(!module_instance, "module_instance is NULL");
	xlog_abortif(!entry->key, "entry->key is NULL");
	xlog_abortif(!entry->value, "entry->value is NULL");

	char *instancedup = strdup(module_instance),
	     *topicdup = strdup(entry->key), *valuedup = strdup(entry->value);

	if (!instancedup || !topicdup || !valuedup) {
		xlog_error("failed to allocate telemetry data");
		goto failure;
	}

	size_t n = t->n + 1;
	struct telemetry_entry *entries;

	if (n > SIZE_MAX / sizeof(*entries)) {
		xlog_error("unsigned integer wraparound detected");
		goto failure;
	}

	entries = realloc(t->entries, n * sizeof(*entries));

	if (!entries) {
		xlog_error("failed to reallocate telemetry entries");
		goto failure;
	}

	entries[t->n++] = (struct telemetry_entry){
		.module_instance = instancedup,
		.topic = topicdup,
		.value = valuedup,
	};

	t->entries = entries;
	return 0;

failure:
	free(instancedup);
	free(topicdup);
	free(valuedup);
	return -1;
}

static int
add_sys_telemetry(const char *topic, const struct sys_telemetry *t,
		  struct telemetry_entries *entries)
{
	char *topicdup = strdup(topic), *valuedup = strdup(t->value),
	     *name = NULL;

	if (!topicdup || !valuedup) {
		xlog_error("failed to duplicate telemetry data");
		goto failure;
	}

	if ((name = strdup(sys_prefix)) == NULL) {
		xlog_error("failed to duplicate sys_prefix");
		goto failure;
	}

	size_t n = entries->n + 1;
	struct telemetry_entry *e = realloc(entries->entries, n * sizeof(*e));

	if (!e) {
		xlog_error("failed to reallocate entries");
		goto failure;
	}

	e[entries->n++] = (struct telemetry_entry){
		.module_instance = name,
		.topic = topicdup,
		.value = valuedup,
	};

	entries->entries = e;
	return 0;

failure:
	free(topicdup);
	free(valuedup);
	free(name);
	return -1;
}

struct telemetry_entries *
telemetry_create(size_t count)
{
	struct telemetry_entries *telemetries =
		xmalloc(sizeof(struct telemetry_entries));
	telemetries->n = count;
	if (count == 0) {
		telemetries->entries = NULL;
	} else {
		telemetries->entries =
			xcalloc(count, sizeof(struct telemetry_entry));
	}
	return telemetries;
}

void
telemetry_destroy(struct telemetry_entries *telemetries)
{
	for (unsigned int i = 0; i < telemetries->n; i++) {
		struct telemetry_entry *entry = &telemetries->entries[i];
		free(entry->module_instance);
		free(entry->topic);
		free(entry->value);
	}
	free(telemetries->entries);
	free(telemetries);
}

static int
add_evp_telemetries(const char *module_instance,
		    const struct EVP_telemetry_entry *entries, size_t nentries,
		    void *user)
{
	int ret = -1;
	struct telemetry_entries *t = telemetry_create(0);
	struct evp_agent_context *ctxt = user;

	for (size_t i = 0; i < nentries; i++) {
		if (add_telemetry(t, module_instance, &entries[i])) {
			xlog_error("failed to add telemetry %zu", i);
			goto end;
		}
	}

	if (t->n > 0 &&
	    (ret = ctxt->hub->send_telemetry(ctxt->transport_ctxt, t))) {
		xlog_error("Failed to enqueue telemetries");
		goto end;
	}

	ret = 0;

end:
	telemetry_destroy(t);
	return ret;
}

static int
enqueue_sys_telemetry(const char *topic, const struct sys_telemetry *syst,
		      void *user)
{
	int ret = -1;
	struct evp_agent_context *ctxt = user;
	struct telemetry_entries *t = telemetry_create(0);

	if (add_sys_telemetry(topic, syst, t)) {
		xlog_error("Failed to allocate system telemetries");
		goto end;
	}

	if (t->n > 0 && ctxt->hub->send_telemetry(ctxt->transport_ctxt, t)) {
		xlog_error("Failed to enqueue system telemetries");
		goto end;
	}

	ret = 0;

end:
	telemetry_destroy(t);
	return ret;
}

void
telemetry_process(struct evp_agent_context *ctxt)
{
	sdk_collect_telemetry(add_evp_telemetries, ctxt);
	sys_collect_telemetry(ctxt->sys, enqueue_sys_telemetry, ctxt);
}
