/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>

struct webclient_context;

/**
 * Set connection status
 */
void connections_set_status(bool is_connected);

/**
 * Invoke webclient_perform if connection status is true.
 * Returned Value:
 *               0: if the operation completed successfully;
 *  Negative errno: On a failure
 *       -ENETDOWN: If not connected
 */
int connections_webclient_perform(struct webclient_context *ctx);

/**
 * Get the number of webclient connections currently performing
 */
unsigned int connections_get_count(void);
