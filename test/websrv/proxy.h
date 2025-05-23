/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

struct proxy_cfg {
	char *cert;
	char *frontend_ip;
	char *backend_ip;
	unsigned short frontend_port;
	unsigned short backend_port;
};

#define proxy_start_cfg(...) proxy_start(&(struct proxy_cfg){__VA_ARGS__})
int proxy_start(struct proxy_cfg *cfg);
int proxy_stop(void);
