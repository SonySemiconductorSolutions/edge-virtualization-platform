/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "proxy.h"
#include "xlog.h"

static struct proxy {
	struct proxy_cfg cfg;
	pid_t pid;
} g_proxy;

static void
spawn_proxy(struct proxy_cfg *cfg)
{
	xlog_debug("spawning: hitch -f[%s]:%u -b[%s]:%u %s\n",
		   cfg->frontend_ip, cfg->frontend_port, cfg->backend_ip,
		   cfg->backend_port, cfg->cert);

	char *argv[5] = {"hitch"};
	xasprintf(&argv[1], "-f[%s]:%u", cfg->frontend_ip, cfg->frontend_port);
	xasprintf(&argv[2], "-b[%s]:%u", cfg->backend_ip, cfg->backend_port);
	argv[3] = cfg->cert;

	execvp(argv[0], argv);
	_exit(1);
}

static int
getport(pid_t pid)
{
	FILE *fp;
	int port, r;
	char *cmd;

	r = asprintf(&cmd,
		     "for i in `pgrep -P %d hitch`\n"
		     "do\n"
		     "\tnetstat -ptnlA inet |\n"
		     "\tawk '/'$i'\\/hitch/ {\n"
		     "\t\tsplit($4, v, \":\")\n"
		     "\t\tprint v[2]\n"
		     "}'\n"
		     "done",
		     (int)pid);
	if (r < 0)
		goto err0;

	xlog_debug("getport: cmd:\n%s", cmd);
	r = -1;
	if ((fp = popen(cmd, "r")) == NULL)
		goto err1;
	if (fscanf(fp, "%d", &port) != 1)
		goto err2;
	r = port;

err2:
	pclose(fp);
err1:
	free(cmd);
err0:
	return r;
}

#define cfg_set_default(attr, default)                                        \
	.attr = ((cfg->attr) ? cfg->attr : default)

int
proxy_start(struct proxy_cfg *cfg)
{
	int i, port;
	struct proxy *ctxt = &g_proxy;

	ctxt->cfg = (struct proxy_cfg){
		cfg_set_default(cert, "certs/pair.pem"),
		cfg_set_default(backend_ip, "127.0.0.1"),
		cfg_set_default(frontend_ip, "127.0.0.1"),
		cfg_set_default(backend_port, 29999),
		cfg_set_default(frontend_port, 0),
	};

	pid_t pid = fork();

	if (pid < 0) {
		xlog_error("Process could not be forked. %s", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		spawn_proxy(&ctxt->cfg);
	} else {
		ctxt->pid = pid;
	}

	for (i = 0; i < 5 && (port = getport(pid)) < 0; i++)
		sleep(1);

	if (i == 5) {
		xlog_error("Proxy didn't open listening port");
		proxy_stop();
		return -1;
	}
	ctxt->cfg.frontend_port = port;
	*cfg = ctxt->cfg;

	xlog_debug("Proxy listening in %s:%d", cfg->frontend_ip,
		   cfg->frontend_port);

	return 0;
}

int
proxy_stop(void)
{
	struct proxy *ctxt = &g_proxy;

	if (ctxt->pid == 0) {
		xlog_warning("Proxy doesn't appear to be started.");
		return -1;
	}

	xlog_info("Stopping proxy...");
	if (kill(ctxt->pid, SIGTERM)) {
		xlog_error("Proxy could not be stopped.");
		return -1;
	}

	if (waitpid(ctxt->pid, NULL, 0) == -1) {
		xlog_error("waitpid failed: %s", strerror(errno));
		return -1;
	};

	xlog_info("Proxy stopped");
	ctxt->pid = 0;
	return 0;
}
