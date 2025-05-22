/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <config.h>

#include <stdbool.h>
#include <stdint.h>

#include <evp/agent_config.h>

#define MIN_REPORT_INTERVAL_SEC       3
#define MAX_REPORT_INTERVAL_SEC       180
#define DEFAULT_MQTT_MFS_QOS          1
#define DEFAULT_TRANSPORT_QUEUE_LIMIT CONFIG_EVP_MQTT_SEND_BUFF_SIZE

struct config;

struct config *get_config(enum config_key);
void free_config(struct config *);
int load_config(struct config *, void **, size_t *);
char *load_simple_config(struct config *);
void unload_config(struct config *, void *, size_t);

/**
 * Get a string representation of the configuration setting.
 * The returned string is allocated on the heap and must be freed
 * after use.
 *
 * Settings are determined in the following order:
 * - Device level configuration from the Hub
 * - Configuration from environment or settings
 *
 * If the setting is not defined in either of these then NULL is returned.
 *
 * @param[in] key: configuration key
 *
 * @return the configuration value as a string, or NULL if not defined
 */
char *config_get_string(enum config_key key);

/**
 * Get an int representation of the configuration setting.
 *
 * Settings are determined in the following order:
 * - Device level configuration from the Hub
 * - Configuration from environment or settings
 * - Compile time default value
 *
 * If the setting is not defined in any of these then EINVAL is returned
 * and `value` is not set.
 *
 * @param[in] key: configuration key
 * @param[out] value: configuration integer value
 *
 * @return 0 in case of success, EINVAL if setting is not available or not a
 * valid number.
 */
int config_get_int(enum config_key key, intmax_t *value);

#endif /* CONFIG_H */
