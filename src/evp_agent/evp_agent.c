/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <evp/agent.h>

#include "../libevp-agent/module_api_wasm.h"

static volatile sig_atomic_t g_signalled = 0;

static void
signal_handler(int signo)
{
	g_signalled = 1;
}

static void
usage(void)
{
	fputs("usage: evp_agent [-l file]*\n", stderr);
	exit(EXIT_FAILURE);
}

static void
add_wasm_native_library(const char *fname)
{
#if !defined(CONFIG_EVP_MODULE_IMPL_WASM)
	fputs("evp_agent: command line dynamic libraries is only enabled "
	      "with wasm "
	      "module implementation",
	      stderr);
	exit(EXIT_FAILURE);
#else
	wasm_add_native_lib(fname);
#endif
}

static int
on_start(const void *args, void *user_data)
{
	fprintf(stderr, "%s: start notification\n", __func__);
	return 0;
}

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "l:")) != -1) {
		switch (ch) {
		case 'l':
			add_wasm_native_library(optarg);
			break;
		default:
			usage();
		}
	}

	if (argv[optind])
		usage();

	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	struct evp_agent_context *ctxt = evp_agent_setup(argv[0]);

	if (evp_agent_notification_subscribe(ctxt, "start", on_start, NULL)) {
		fprintf(stderr, "%s: notification_register failed\n",
			__func__);
		evp_agent_free(ctxt);
		return -1;
	}

	int ret = evp_agent_start(ctxt);
	if (ret == 0) {
		ret = evp_agent_connect(ctxt);
	}

	while (ret == 0) {
		ret = evp_agent_loop(ctxt);
		if (g_signalled) {
			break;
		}
	}

	evp_agent_disconnect(ctxt);
	evp_agent_stop(ctxt);
	evp_agent_free(ctxt);
	return 0;
}
