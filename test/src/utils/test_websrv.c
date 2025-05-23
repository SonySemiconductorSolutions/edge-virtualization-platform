/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <netdb.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "websrv.h"
#include "xlog.h"

static int
on_get_root(const struct http_payload *p, struct http_response *r, void *user)
{
	static const char buf[] = "Hello world!";

	*r = (struct http_response){
		.status = HTTP_STATUS_OK,
		.buf.ro = buf,
		.n = sizeof buf - 1,
	};

	return 0;
}

void
test_websrv_get(void **state)
{
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo *res;
	char portstr[sizeof "65535"];
	unsigned short port;
	int ret = websrv_get_port(&port);

	if (ret) {
		fprintf(stderr, "%s: websrv_get_port failed\n", __func__);
	}

	assert_int_equal(ret, 0);

	ret = snprintf(portstr, sizeof(portstr), "%hu", port);

	assert_true(ret > 0 || ret < sizeof(portstr));

	int ecode = getaddrinfo("localhost", portstr, &hints, &res);

	if (ecode) {
		fprintf(stderr, "%s: getaddrinfo: %s", __func__,
			gai_strerror(ecode));
	}

	assert_int_equal(ecode, 0);
	int sockfd =
		socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	assert_int_not_equal(sockfd, -1);

	ret = connect(sockfd, res->ai_addr, res->ai_addrlen);

	if (ret) {
		fprintf(stderr, "%s: connect(2): %s\n", __func__,
			strerror(errno));
	}
	assert_int_equal(ret, 0);

	static const char request[] = "GET / HTTP/1.1\r\n"
				      "Host: localhost\r\n"
				      "Connection: close\r\n\r\n";

	const char *cbuf = request;
	size_t rem = sizeof(request);

	while (rem) {
		ssize_t n = send(sockfd, cbuf, rem, 0);
		assert_true(n >= 0);
		cbuf += n;
		rem -= n;
	}

	static const char exp_response[] = "HTTP/1.1 200 OK\r\n"
					   "Content-Length: 12\r\n"
					   "\r\n"
					   "Hello world!";

	char response[sizeof(exp_response)], *buf = response;
	rem = sizeof(response) - 1 /* exclude '\0' */;
	while (rem) {
		ssize_t n = recv(sockfd, buf, rem, 0);
		assert_true(n >= 0);
		buf += n;
		rem -= n;
	}

	response[sizeof(response) - 1] = '\0';
	assert_string_equal(response, exp_response);

	assert_int_equal(close(sockfd), 0);

	freeaddrinfo(res);
}

int
setup(void **state)
{
	if (websrv_setup(0)) {
		return -1;
	}

	websrv_add_route("/", HTTP_OP_GET, on_get_root, NULL);
	websrv_add_route("/", HTTP_OP_POST, on_get_root, NULL);

	return websrv_start();
}

int
teardown(void **state)
{
	websrv_stop();
	return websrv_teardown();
}

int
main(void)
{
	// define tests
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_websrv_get),
	};
	// setup, run tests and teardown
	return cmocka_run_group_tests(tests, setup, teardown);
}
