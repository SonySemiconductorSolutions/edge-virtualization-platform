/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <internal/util.h>

#include "webclient/webclient.h"

#include "test_blob_core_defs.h"

#define TEST_BLOB_PARAM(...) &((struct test_blob_core_param){__VA_ARGS__})

extern struct test_blob_core_context g_test_blob_core_context;

int add_instance_config(JSON_Object *o, int i, const char *name,
			const char *fmt, ...);
int add_instances_configs(JSON_Object *o, const char *prefix, int n);
int add_deployement(JSON_Object *o, enum test_impl impl, const char *module,
		    int n);

char *create_instance_config(const char *prefix, int n);

void send_stp_response(struct test_blob_core_context *ctxt,
		       const char *response_type, unsigned long expires_at_ms,
		       int i);

int setup_suite_blob_core(void **state);
int teardown_suite_blob_core(void **state);

int setup_test_blob_core(void **state);
int teardown_test_blob_core(void **state);

void test_upload_http_file(void **state);
void test_upload_evp_file(void **state);
