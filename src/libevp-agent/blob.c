/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "blob.h"
#include "blob_type_azure_blob.h"
#include "blob_type_evp.h"
#include "blob_type_http.h"
#include "certificates.h"
#include "evp/agent.h"
#include "xlog.h"

static struct blob_worker blob_worker_store;
static struct workq *blob_workq;

static void
process_blob_work(struct worker *gworker, struct work *gwk)
{
	struct blob_worker *worker = (void *)gworker;
	struct blob_work *wk = (void *)gwk;
	const char *filename = wk->filename;

	if (!filename)
		filename = "(memory)";

	void *ephemeral_buffer = NULL;
	if (worker->worker.max_jobs == 1) {
		wk->buffer = worker->buffer;
		wk->buffer_size = BLOB_WORKER_BUFFER_SIZE;
	} else {
		wk->buffer_size = BLOB_WORKER_BUFFER_SIZE;
		ephemeral_buffer = xmalloc(wk->buffer_size);
		wk->buffer = ephemeral_buffer;
	}

	const char *remote;
	if (wk->type == BLOB_TYPE_AZURE_BLOB || wk->type == BLOB_TYPE_HTTP ||
	    wk->type == BLOB_TYPE_HTTP_EXT) {
		remote = wk->url;
	} else {
		remote = wk->remote_name;
	}

	wk->agent = worker->agent;

	xlog_debug("BLOB action %s STARTING for type %d remote: %s, local: %s",
		   wk->op == BLOB_OP_GET ? "GET" : "PUT", (int)wk->type,
		   remote, filename);

	static unsigned int (*const getters[])(struct blob_work *) = {
		[BLOB_TYPE_AZURE_BLOB] = blob_type_azure_blob_get,
		[BLOB_TYPE_HTTP] = blob_type_http_get,
		[BLOB_TYPE_EVP_EXT] = blob_type_evp_get,
		[BLOB_TYPE_HTTP_EXT] = blob_type_http_get,

	};
	static unsigned int (*const putters[])(struct blob_work *) = {
		[BLOB_TYPE_AZURE_BLOB] = blob_type_azure_blob_put,
		[BLOB_TYPE_HTTP] = blob_type_http_put,
		[BLOB_TYPE_EVP_EXT] = blob_type_evp_put,
		[BLOB_TYPE_HTTP_EXT] = blob_type_http_put,
	};

	assert(wk->type == BLOB_TYPE_AZURE_BLOB ||
	       wk->type == BLOB_TYPE_HTTP || wk->type == BLOB_TYPE_EVP_EXT ||
	       wk->type == BLOB_TYPE_HTTP_EXT);
	switch (wk->op) {
	case BLOB_OP_GET:
		wk->result = getters[wk->type](wk);
		break;
	case BLOB_OP_PUT:
		wk->result = putters[wk->type](wk);
		break;
	default:
		wk->result = BLOB_RESULT_ERROR;
		wk->error = ENOTSUP;
		break;
	}

	xlog_debug("BLOB action %s ENDING for type %d remote: %s, local: %s "
		   "(RESULT is %d, error %d, http_status %u)",
		   wk->op == BLOB_OP_GET ? "GET" : "PUT", (int)wk->type,
		   remote, filename, (int)wk->result, wk->error,
		   wk->http_status);

	struct evp_agent_notification_blob_result notification = {
		.result = wk->result,
		.error = wk->error,
		.http_status = wk->http_status,
	};

	evp_agent_notification_publish(worker->agent, "blob/result",
				       &notification);

	free(ephemeral_buffer);
}

void
start_blob_worker_manager(struct evp_agent_context *agent)
{
	struct blob_worker *worker = &blob_worker_store;
	worker->agent = agent;
	worker->worker.name = "blob worker";
	worker->worker.process_item = process_blob_work;
	worker->worker.max_jobs = 6;

	if (1 == worker->worker.max_jobs) {
		/* Only 1 worker, reuse the same buffer */
		worker->buffer = xmalloc(BLOB_WORKER_BUFFER_SIZE);
	}

	worker_manager_start(&worker->worker);
	blob_workq = &worker->worker.q;
}

void
stop_blob_worker_manager(void)
{
	struct blob_worker *worker = &blob_worker_store;
	worker_manager_stop(&worker->worker);
	if (worker->worker.max_jobs == 1 && worker->buffer != NULL) {
		/* Only 1 worker, reuse the same buffer */
		free(worker->buffer);
		worker->buffer = NULL;
	}
}

void
blob_work_set_defaults(struct blob_work *wk)
{
	work_set_defaults(&wk->wk);
}

void
blob_work_enqueue(struct blob_work *wk)
{
	work_enqueue(blob_workq, &wk->wk);
}

int
blob_work_cancel(struct blob_work *wk)
{
	return work_trycancel(blob_workq, &wk->wk);
}

char *
blob_strerror(struct blob_work *wk)
{
	const char *op;
	char *ret;

	switch (wk->op) {
	case BLOB_OP_GET:
		op = "Download";
		break;
	case BLOB_OP_PUT:
		op = "Upload";
		break;
	default:
		op = "Invalid operation";
	}

	if (wk->wk.status != WORK_STATUS_DONE) {
		xasprintf(&ret, "%s is not done", op);
		goto end;
	}

	switch (wk->result) {
	case BLOB_RESULT_SUCCESS:
		xasprintf(&ret, "%s succeeded with http status %u", op,
			  wk->http_status);
		break;
	case BLOB_RESULT_ERROR:
		xasprintf(&ret, "%s failed with errno %d (%s)", op, wk->error,
			  strerror(wk->error));
		break;
	case BLOB_RESULT_ERROR_HTTP:
		xasprintf(&ret, "%s failed with http status %u", op,
			  wk->http_status);
		break;
	default:
		xasprintf(&ret, "Invalid result %d", (int)wk->result);
	}

end:
	return ret;
}

struct blob_work *
blob_work_alloc(void)
{
	struct blob_work *wk = malloc(sizeof(*wk));
	if (wk != NULL) {
		*wk = (struct blob_work){0};
		blob_work_set_defaults(wk);
	}
	return wk;
}

void
blob_work_free(struct blob_work *wk)
{
	if (wk->cert != NULL) {
		cert_release(wk->cert);
	}
	free(__UNCONST(wk->remote_name));
	free(__UNCONST(wk->module_instance_name));
	free(__UNCONST(wk->storage_name));
	free(__UNCONST(wk->url));
	free(__UNCONST(wk->filename));

	unsigned int i;
	for (i = 0; i < wk->nheaders; i++) {
		free(__UNCONST(wk->headers[i]));
	}
	free(__UNCONST(wk->cert_id));
	free(__UNCONST(wk->headers));
	free(__UNCONST(wk->proxy));
	free(__UNCONST(wk->proxy_user));
	free(wk);
}

void
blob_work_set_proxy(struct blob_work *wk)
{
	char *proxy_host = config_get_string(EVP_CONFIG_HTTP_PROXY_HOST);
	char *proxy_port = config_get_string(EVP_CONFIG_HTTP_PROXY_PORT);

	// TODO: Replace assert (programming error)
	assert(wk->proxy == NULL);
	if (proxy_host != NULL && proxy_port != NULL) {
		char *proxy;
		char *proxy_username;
		char *proxy_password;

		xasprintf(&proxy, "http://%s:%s", proxy_host, proxy_port);
		wk->proxy = proxy;

		proxy_username =
			config_get_string(EVP_CONFIG_HTTP_PROXY_USERNAME);
		proxy_password =
			config_get_string(EVP_CONFIG_HTTP_PROXY_PASSWORD);
		if (proxy_username != NULL && proxy_password != NULL) {
			char *proxy_user;

			xasprintf(&proxy_user, "%s:%s", proxy_username,
				  proxy_password);
			wk->proxy_user = proxy_user;
		}
		free(proxy_username);
		free(proxy_password);
	}
	free(proxy_host);
	free(proxy_port);
}
