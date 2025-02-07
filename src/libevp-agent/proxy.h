/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

int compose_proxy_auth_header(char **header, const char *user);
int tunnel_over_proxy(const char *proxy, const char *proxy_user,
		      const char *target_host, const char *target_port,
		      int *fdp);
