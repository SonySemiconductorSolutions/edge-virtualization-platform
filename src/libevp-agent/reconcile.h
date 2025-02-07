/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RECONCILE_H
#define RECONCILE_H

#include "parson.h"

struct evp_agent_context;

/**
 * Read, parse and apply current deployment
 */
void process_deployment(struct evp_agent_context *agent);

/**
 * Apply processing to a parsed deployment
 */
void apply_deployment(struct evp_agent_context *agent,
		      struct Deployment *deploy, const JSON_Value *deployment);

/**
 * Remove the persisted 'desired' deployment
 */
void clear_deployment(struct evp_agent_context *agent);

/**
 * Iterate through module instance state in 'current', renaming entries with a
 * matching module instance name.
 */
void rename_instance_states(const char *oldname, const char *newname);

#endif
