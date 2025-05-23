/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Docker-based module implementation for Linux
 */

#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <internal/util.h>

#include "cdefs.h"
#include "docker_worker.h"
#include "manifest.h"
#include "module_impl.h"
#include "module_impl_ops.h"
#include "xpthread.h"

static struct docker_op *g_prune_op;

static int
cancel_or_complete_prune(void)
{
	if (g_prune_op != NULL) {
		int ret = docker_op_cancel_or_request_completion_notification(
			g_prune_op);
		if (ret != 0) {
			return ret;
		}
		g_prune_op = NULL;
	}
	return 0;
}

static bool
impl_loaded(const struct module *m)
{
	return m->image != NULL;
}

static bool
impl_downloading(const struct module *m)
{
	return m->docker_op != NULL;
}

static int
impl_download_cancel(struct module *m)
{
	// TODO: Replace assert (programming error)
	assert(m->docker_op == NULL || g_prune_op == NULL);
	if (m->docker_op != NULL) {
		int ret = docker_op_cancel(m->docker_op);
		if (ret != 0) {
			return ret;
		}
		free(__UNCONST(m->docker_op->image));
		free(m->docker_op);
		m->docker_op = NULL;
	}
	return 0;
}

static int
impl_load(struct module *m, const struct Module *modspec)
{
	int ret;

	/*
	 * Ensure that there is no overlapping image prune and image create
	 * to avoid races.
	 * Otherwise, if the image create is processed first, the image prune
	 * effectively undos the create.
	 */
	// TODO: Replace assert (programming error)
	assert(m->docker_op == NULL || g_prune_op == NULL);
	ret = cancel_or_complete_prune();
	if (ret != 0) {
		return ret;
	}
	if (m->docker_op != NULL) {
		struct docker_op *op = m->docker_op;
		ret = docker_op_cancel(op);
		if (ret != 0) {
			return ret;
		}
		if (op->wk.status == WORK_STATUS_DONE) {
			if (op->result != 0) {
				free(m->failureMessage);
				xasprintf(&m->failureMessage,
					  "image_create failed with %d\n",
					  op->result);
			} else {
				m->image = xstrdup(modspec->downloadUrl);
			}
		}
		free(__UNCONST(op->image));
		free(op);
		m->docker_op = NULL;
		if (m->failureMessage != NULL) {
			return EIO;
		}
	}
	if (m->image == NULL) {
		struct docker_op *op = xmalloc(sizeof(*op));
		m->docker_op = op;
		docker_op_set_defaults(op);
		op->op = DOCKER_OP_IMAGE_CREATE;
		op->image = xstrdup(modspec->downloadUrl); /* XXX abuse */
		docker_op_schedule(op);
		return EAGAIN;
	}
	return 0;
}

static void
impl_unload(struct module *m)
{
	/*
	 * Nothing to do for now.
	 *
	 * XXX do we want to remove the image eagerly to save space?
	 */

	free(__UNCONST(m->image));
	m->image = NULL;
}

static void
impl_init(void *param)
{
	docker_worker_start(param);
}

static void *
impl_handle(const struct module *m)
{
	return __UNCONST(m->image);
}

#if defined(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_NO_IMAGE_PRUNE)
#define NO_DOCKER_IMAGE_PRUNE
#endif

static void
impl_prune(void)
{
#if !defined(NO_DOCKER_IMAGE_PRUNE)
	/*
	 * XXX this would remove images for modules not used by
	 * any of module instances. is it ok?
	 * is there any use cases for modules without module instances
	 * for this docker version?
	 * (for nuttx, there were ideas of "library modules" floating around.)
	 */

	/*
	 * Note: this function is called when a deployment is commited.
	 * That is, we know there is no DOCKER_OP_IMAGE_CREATE in-progress.
	 */

	static struct docker_op op0;
	struct docker_op *op;

	int ret = cancel_or_complete_prune();
	if (ret != 0) {
		return;
	}

	// TODO: Replace assert (programming error)
	assert(g_prune_op == NULL);
	op = &op0;
	docker_op_set_defaults(op);
	op->op = DOCKER_OP_IMAGE_PRUNE;
	docker_op_schedule_without_completion_notification(op);
	g_prune_op = op;
#endif
}

static void
impl_destroy(void)
{
	// TODO: destroy the docker client
}

extern const struct module_instance_impl_ops module_instance_impl_ops_docker;

const struct module_impl_ops module_impl_ops_docker = {
	.name = "docker",
	.downloading = impl_downloading,
	.download_cancel = impl_download_cancel,
	.destroy = impl_destroy,
	.handle = impl_handle,
	.init = impl_init,
	.loaded = impl_loaded,
	.load = impl_load,
	.prune = impl_prune,
	.unload = impl_unload,
	.instance = &module_instance_impl_ops_docker,
};
