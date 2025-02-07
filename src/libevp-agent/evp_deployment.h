/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EVP_DEPLOYMENT_H
#define EVP_DEPLOYMENT_H

struct evp_agent_context;

int evp_deployment_acquire(struct evp_agent_context *ctxt);
void evp_deployment_release(struct evp_agent_context *ctxt);

#endif
