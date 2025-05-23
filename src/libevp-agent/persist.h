/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct evp_agent_context;

void init_local_twins_db(void);
void deinit_local_twins_db(void);
void save_desired(const struct evp_agent_context *agent);
void load_desired(struct evp_agent_context *ctxt);
void save_current(const struct evp_agent_context *agent);
void load_current(struct evp_agent_context *agent);
void save_json(const char *filename, const JSON_Value *v);
