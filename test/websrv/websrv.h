/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <libweb/handler.h>
#include <libweb/http.h>

int websrv_setup(unsigned short port);
int websrv_get_port(unsigned short *port);
int websrv_add_route(const char *url, const enum http_op op,
		     const handler_fn fn, void *const user);
int websrv_start(void);
int websrv_stop(void);
int websrv_teardown(void);

// Default handlers
int on_get_user_string(const struct http_payload *p, struct http_response *r,
		       void *user);
int on_put_default(const struct http_payload *p, struct http_response *r,
		   void *user);
