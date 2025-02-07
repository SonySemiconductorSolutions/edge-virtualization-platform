/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <evp/agent.h>
#include <parson.h>

#include <internal/util.h>

#include "agent_internal.h"
#include "cdefs.h"
#include "evp_deployment.h"
#include "evp_hub.h"
#include "global.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "reconcile.h"
#include "sdk_msg.h"
#include "xlog.h"

#if defined(RAW_CONTAINER_SPEC)
#include "container_spec.h"
#endif

static void
setup_messaging(struct Deployment *deployment)
{
	sdk_set_publish_topics(deployment->publish_topics);
	sdk_set_subscribe_topics(deployment->subscribe_topics);
}

static void
update_reconcile_status(struct evp_agent_context *agent,
			const char *deploymentId, const char *status)
{
	bool update = false;

	/* --- Check if deploymentId is updated --- */
	/* First time calling this method */
	if (!g_evp_global.deploymentId && deploymentId) {
		update = true;
	}

	/* Cleaning the value */
	if (g_evp_global.deploymentId && !deploymentId) {
		update = true;
	}

	/* Updating the value */
	if (g_evp_global.deploymentId && deploymentId &&
	    strcmp(g_evp_global.deploymentId, deploymentId) != 0) {
		update = true;
	}

	/* --- Check if status is updated --- */
	/* First time calling this method */
	if (!g_evp_global.reconcileStatus && status) {
		update = true;
	}

	/* Cleaning the value */
	if (g_evp_global.reconcileStatus && !status) {
		update = true;
	}

	/* Updating the value */
	if (g_evp_global.reconcileStatus && status &&
	    strcmp(g_evp_global.reconcileStatus, status) != 0) {
		update = true;
	}

	if (update) {
		xlog_info("DeploymentId: %s, status: %s",
			  deploymentId ? deploymentId : "none", status);

		free(__UNCONST(g_evp_global.deploymentId));
		if (deploymentId != NULL) {
			g_evp_global.deploymentId = xstrdup(deploymentId);
		} else {
			g_evp_global.deploymentId = NULL;
		}
		g_evp_global.reconcileStatus = status;

		struct reconcileStatusNotify notify_value = {
			.deploymentId = g_evp_global.deploymentId,
			.reconcileStatus = g_evp_global.reconcileStatus};

		if (evp_agent_notification_publish(
			    agent, "deployment/reconcileStatus",
			    &notify_value)) {
			xlog_error("evp_agent_notification_publish failed");
		}
	}
}

void
process_deployment(struct evp_agent_context *agent)
{
	// try to reconcile current to desired

	const char *name = "deployment";
	JSON_Object *desiredobj = json_value_get_object(g_evp_global.desired);
	JSON_Value *desired = json_object_get_value(desiredobj, name);

	if (desired == NULL) {
		/* XXX should report */
		return;
	}

	/*
	 * What to do:
	 *
	 * 1. stop tasks which are not in the given deploy.instanceSpecs.
	 *    Note: this step might need to be blocking, depending on the
	 *    protocol to stop tasks.
	 * 2. unload/delete modules which are not in the given deploy.modules.
	 * 3. download/load modules which are not in the current list of loaded
	 *    modules but in the given deploy.modules.
	 *    Note: downloading modules is blocking.
	 * 4. spawn tasks which are not in the current list of running tasks
	 * but in the given deployment.instanceSpecs.
	 *
	 * REVISIT:
	 * - does it make sense to cache unused modules?
	 * - does it make sense to populate the cache before stopping tasks?
	 * - NuttX dlopen is not mmap-based. We can freely delete dlopen'ed
	 *   modules. Maybe it's simpler to update modules and then update
	 * tasks.
	 */

	struct Deployment *deploy = NULL;
	int ret;
	ret = agent->hub->parse_deployment(desired, &deploy);
	if (ret != 0) {
		/*
		 * Note: Except ENOMEM, a failure here is likely a bug in
		 * the hub. It's the responsibility of the hub to give
		 * us a valid DeploymentManifest.
		 */
		xlog_error("Failed to parse DeploymentManifest with error %d",
			   ret);
	} else {
		apply_deployment(agent, deploy, desired);
	}

	free_deployment(deploy);
}

void
apply_deployment(struct evp_agent_context *agent, struct Deployment *deploy,
		 const JSON_Value *deployment)
{
	int ret;

	const char *reconcile_status = "applying";
	ret = module_instance_stop(deploy->instanceSpecs);
	if (ret != 0) {
		xlog_error("Failed to stop instance %d", ret);
		goto end;
	}

	ret = module_unload(deploy->modules);
	if (ret != 0) {
		xlog_error("Failed to unload instance %d", ret);
		goto end;
	}

	ret = evp_deployment_acquire(agent);
	if (ret == EAGAIN) {
		reconcile_status = "paused";
		goto end;
	}

	ret = module_load(deploy->modules);
	if (ret != 0 && ret != EAGAIN) {
		xlog_error("Failed to load instance %d", ret);
	}

	if (deployment == NULL) {
		/* Nothing to start. */
		ret = 0;
		goto end;
	}

	ret = module_instance_start(deployment, agent->hub,
				    deploy->instanceSpecs);

	if (ret != 0) {
		goto end;
	}

	/* Commit the new deployment */
	reconcile_status = "ok";
	setup_messaging(deploy);
	gc_module_instance_dir();
	module_prune();
	evp_deployment_release(agent);

end:
	if (ret != 0 && ret != EAGAIN) {
		reconcile_status = "error";
	}

	update_reconcile_status(agent, deploy->deploymentId, reconcile_status);
}

void
rename_instance_states(const char *oldname, const char *newname)
{
	char *prefix = NULL;
	int len = xasprintf(&prefix, "state/%s/", oldname);
	if (len == -1) {
		free(prefix); // prevent fortify complaint
		return;
	}
	JSON_Object *obj = json_value_get_object(g_evp_global.instance_states);
	size_t n = json_object_get_count(obj);
	for (unsigned int i = 0; i < n; i++) {
		const char *name = json_object_get_name(obj, i);
		if (strncmp(prefix, name, len) == 0) {
			JSON_Value *val = json_object_get_value_at(obj, i);
			char *str;
			xasprintf(&str, "state/%s/%s", newname, name + len);
			val = json_value_deep_copy(val);
			if (json_object_set_value(obj, str, val) ==
			    JSONSuccess) {
				json_object_remove(obj, name);
			} else {
				json_value_free(val);
			}
			free(str);
		}
	}
	free(prefix);
}

void
clear_deployment(struct evp_agent_context *agent)
{
	JSON_Object *desired = json_value_get_object(g_evp_global.desired);
	json_object_remove(desired, "deployment");
}
