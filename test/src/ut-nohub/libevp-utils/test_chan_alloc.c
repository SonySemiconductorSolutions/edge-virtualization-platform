/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <chan_def.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include <internal/chan.h>

static struct mock {
	bool enable;
	void *ret;
} mock;

void *
__wrap_malloc(size_t size)
{
	void *__real_malloc(size_t);

	if (mock.enable) {
		void *ret = mock.ret;

		mock = (struct mock){0};
		return ret;
	}

	return __real_malloc(size);
}

static void
test_chan_alloc_nomem(void **state)
{
	mock = (struct mock){.enable = true};
	struct chan *c = chan_alloc();
	assert_ptr_equal(c, NULL);
}

static void
test_chan_alloc(void **state)
{
	static struct chan chan;

	mock = (struct mock){.enable = true, .ret = &chan};
	struct chan *c = chan_alloc();
	assert_ptr_equal(c, &chan);
	assert_ptr_equal(c->head, c->tail);
	assert_ptr_equal(c->head, NULL);
}

int
main(void)
{
	static const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_chan_alloc),
		cmocka_unit_test(test_chan_alloc_nomem),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
