/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <parson.h>

struct blob_work;
struct blob_worker;
struct evp_agent_context;
struct request;
struct storagetoken_response;

unsigned int blob_type_evp_get(struct blob_work *wk);
unsigned int blob_type_evp_put(struct blob_work *wk);
void blob_type_evp_start_rpc(struct evp_agent_context *agent,
			     struct blob_work *wk);
int evp_send_storagetoken_request(struct evp_agent_context *agent,
				  struct request *req, JSON_Value *v);
int blob_type_evp_load(const struct evp_agent_context *agent,
		       const struct blob_work *wk,
		       struct storagetoken_response *resp);

int blob_type_evp_store(const struct blob_work *wk, const JSON_Value *v);
