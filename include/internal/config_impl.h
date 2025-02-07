/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Header used by implementations of the evp_config.h interface
 */
#include <stdbool.h>

#include "evp_config.h"

struct config {
	enum config_key key;
	void *value;
	size_t size;
	void (*free)(void *);
};

bool is_config_optional(enum config_key);
int config_load_pk_file(const char *, void **, size_t *);
void config_unload_pk_file(void *, size_t);

/* Functions that call the backend-specific implementations */
int load_config_impl(struct config *, void **, size_t *);
void unload_config_impl(struct config *, void *, size_t);
struct config *get_config_impl(enum config_key);
bool config_is_pk_file(enum config_key key);
