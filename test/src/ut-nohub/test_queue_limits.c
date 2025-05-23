/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/utsname.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include <evp/agent.h>
#include <parson.h>

#include <internal/evp_config.h>

#include "cdefs.h"
#include "hub.h"
#include "req.h"
#include "system_info.h"
#include "version.h"

static void
test_queue_limits(void **state)
{
	struct request *reqs[] = {request_alloc(), request_alloc(),
				  request_alloc()};
	struct request *mfsreq = request_alloc();

	reqs[0]->topic_template = "test-topic";
	reqs[0]->payload = "0123456789";
	assert_int_equal(request_insert(reqs[0]), 0);

	reqs[1]->topic_template = "test-topic/%ju";
	reqs[1]->id = 12345;
	reqs[1]->payload = "12345678";
	assert_int_equal(request_insert(reqs[1]), 0);

	reqs[2]->topic_template = "test-topic";
	reqs[2]->payload = "this is too long!";
	assert_int_not_equal(request_insert(reqs[2]), 0);

	mfsreq->topic_template = "mfs-topic";
	mfsreq->payload = "this belongs to a different queue";
	mfsreq->priority = REQ_PRIORITY_MFS;
	assert_int_equal(request_insert(mfsreq), 0);

	request_unlink(reqs[0]);
	request_unlink(reqs[1]);
	assert_int_equal(request_insert(reqs[2]), 0);
	request_unlink(reqs[2]);

	for (size_t i = 0; i < sizeof reqs / sizeof *reqs; i++)
		request_free(reqs[i]);

	request_unlink(mfsreq);
	request_free(mfsreq);
}

static int
setup(void **state)
{
	return putenv("EVP_TRANSPORT_QUEUE_LIMIT=44");
}

int
main(void)
{

	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_queue_limits),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, NULL);
}
