/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <internal/string_map.h>

#include "sys.h"

struct collect_state {
	void (*fn)(const char *, const char *, const void *, size_t, void *);
	void *user;
};

static int
collect_state(const char *key, void *value, void *user)
{
	struct collect_state *c = user;

	c->fn(sys_prefix, key, value, strlen(value), c->user);
	return 1;
}

int
sys_collect_states(struct sys_group *gr,
		   void (*fn)(const char *, const char *, const void *, size_t,
			      void *),
		   void *user)
{
	struct collect_state c = {.fn = fn, .user = user};

	return string_map_forall(gr->state_map, collect_state, &c);
}
