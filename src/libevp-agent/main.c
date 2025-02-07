/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <config.h>

#include <signal.h>
#include <unistd.h>

#include <evp/agent.h>

#include "module_api_wasm.h"
#include "xlog.h"

#if !defined(__NuttX__)
static volatile sig_atomic_t g_signalled = 0;

static void
signal_handler(int signo)
{
	g_signalled = 1;
}
#endif

static void
usage(void)
{
	// Exit (xlog_abort): usage
	xlog_abort("evp_agent [-l file]*");
}

static void
add_wasm_native_library(const char *fname)
{
#if !defined(CONFIG_EVP_MODULE_IMPL_WASM_NATIVE_LIBS)
	// Exit (xlog_abort): runtime error
	xlog_abort("support for native dynamic libraries is disabled. "
		   "Please enable EVP_MODULE_IMPL_WASM_NATIVE_LIBS and build "
		   "again.");
#else
	wasm_add_native_lib(fname);
#endif
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

#if !defined(__NuttX__)
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGPIPE, SIG_IGN);
#endif

	struct evp_agent_context *ctxt = evp_agent_setup(argv[0]);
	int ret = evp_agent_start(ctxt);
	if (ret == 0) {
		ret = evp_agent_connect(ctxt);
	}

	while (ret == 0) {
		ret = evp_agent_loop(ctxt);
#if !defined(__NuttX__)
		if (g_signalled) {
			break;
		}
#endif
	}
	evp_agent_disconnect(ctxt);
	evp_agent_stop(ctxt);
	evp_agent_free(ctxt);

	return 0;
}
