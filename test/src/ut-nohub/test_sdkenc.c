/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <flatcc/support/hexdump.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>

#include "hub.h"
#include "sdk_builder.h"
#include "sdk_reader.h"
#include "sdk_verifier.h"

#undef ns
#define ns(a) FLATBUFFERS_WRAP_NAMESPACE(EVP_SDK, a)

void
test_sdkenc(void **setup)
{
	int hoge;
	for (hoge = 0; hoge < 2; hoge++) {
		flatcc_builder_t builder;
		flatcc_builder_t *b = &builder;
		flatcc_builder_init(b);
		ns(Response_start_as_root(b));
		ns(Response_body_getEvent_start(b));
		if (hoge) {
			ns(Event_body_exit_start(b));
			ns(Event_body_exit_end(b));
		}
		ns(Response_body_getEvent_end(b));
		ns(Response_end_as_root(b));
		size_t buflen;
		void *buf = flatcc_builder_finalize_aligned_buffer(b, &buflen);
		flatcc_builder_clear(b);

		assert_int_not_equal(buf, NULL);
		assert_true(buflen > 0);
		hexdump("serialized buffer", buf, buflen, stdout);

		int ret = ns(Response_verify_as_root(buf, buflen));
		if (ret != 0) {
			printf("verify failed: %s\n",
			       flatcc_verify_error_string(ret));
		}
		assert_int_equal(ret, 0);
		ns(Response_table_t) resp = ns(Response_as_root(buf));
		assert_int_equal(ns(Response_body_type(resp)),
				 ns(ResponseUnion_getEvent));
		ns(Event_table_t) event = ns(Response_body(resp));
		if (hoge) {
			assert_int_equal(ns(Event_body_type(event)),
					 ns(EventBody_exit));
		} else {
			assert_int_equal(ns(Event_body_type(event)),
					 ns(EventBody_NONE));
		}
		flatcc_builder_aligned_free(buf);
	}
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sdkenc),
	};

	// test run
	return cmocka_run_group_tests(tests, NULL, NULL);
}
