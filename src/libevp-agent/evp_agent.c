/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__NuttX__)
#include <nuttx/compiler.h>
#else
#if !defined(FAR)
#define FAR
#endif
#endif

#include <config.h>

#if defined(__NuttX__)
#include <nuttx/mm/iob.h>
#endif

#include <inttypes.h>
#if defined(__NuttX__) || defined(__GLIBC__)
#include <malloc.h>
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <version.h>

#include <evp/agent.h>
#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "agent_event.h"
#include "agent_internal.h"
#include "backdoor.h"
#include "blob.h"
#include "blob_type_evp.h"
#include "cdefs.h"
#include "connections.h"
#include "deployment.h"
#include "direct_command.h"
#include "evp_deployment.h"
#include "evp_hub.h"
#include "global.h"
#include "https_ssl_config.h"
#include "hub.h"
#include "instance_config.h"
#include "main_loop.h"
#include "manifest.h"
#include "module.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "module_log_cap.h"
#include "module_log_streaming.h"
#include "notification.h"
#include "path.h"
#include "persist.h"
#include "platform.h"
#include "proxy.h"
#include "reconcile.h"
#include "report.h"
#include "req.h"
#include "sdk_agent.h"
#include "stream/stream.h"
#include "sys/sys.h"
#include "telemetry.h"
#include "timeutil.h"
#include "tls.h"
#include "xlog.h"
#include "xpthread.h"

struct global g_evp_global;

#define evp_agent_lock()   xpthread_mutex_lock(&ctxt->lock)
#define evp_agent_unlock() xpthread_mutex_unlock(&ctxt->lock)

static void
dump_memory_usage(void)
{

	uint64_t now = gettime_ms();
	static uint64_t last_dump_memory = 0;

	if (last_dump_memory + 1000 > now) {
		return;
	}
	last_dump_memory = now;
#if defined(__NuttX__)
	struct mallinfo info = mallinfo();
	xlog_info("arena %d ordblks %d mxordblk %d uordblks %d fordblks %d",
		  info.arena, info.ordblks, info.mxordblk, info.uordblks,
		  info.fordblks);
#elif defined(__GLIBC__)
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33)
	// mallinfo deprecated in glibc v2.33
	struct mallinfo2 info = mallinfo2();
	xlog_info("arena %zu ordblks %zu mxordblk 0 uordblks %zu fordblks %zu",
		  info.arena, info.ordblks, info.uordblks, info.fordblks);
#else
	struct mallinfo info = mallinfo();
	xlog_info("arena %u ordblks %u mxordblk 0 uordblks %u fordblks %u",
		  info.arena, info.ordblks, info.uordblks, info.fordblks);
#endif
#endif

	/*
	 * Note: iob_navail is not a system call or a library api.
	 * Even with the FLAT model, it is not exported to modules by default.
	 */
#if defined(__NuttX__) && defined(CONFIG_BUILD_FLAT) &&                       \
	CONFIG_EXTERNALS_EVP_AGENT == CONFIG_y
	xlog_info("IOB navail %d / %d", iob_navail(true), iob_navail(false));
#endif
}

/* TODO: move notification_singleton to struct evp_agent_context. */
static struct notification *notification_singleton;

struct evp_agent_context *
evp_agent_setup(const char *progname)
{
	xsetprogname(progname);
	dump_memory_usage();
	struct evp_agent_context *ctxt =
		xcalloc(1, sizeof(struct evp_agent_context));
	xpthread_mutex_init(&ctxt->lock);

	deployment_init(&ctxt->deployment);

	if (stream_atexit()) {
		xlog_warning("stream_atexit failed");
	}
	/* TODO: allocate into ctxt->context. */
	if (!notification_singleton) {
		notification_singleton = notification_alloc();
		if (!notification_singleton) {
			xlog_warning("notification_setup failed");
		}
	}

	return ctxt;
}

enum evp_agent_status
evp_agent_get_status(struct evp_agent_context *ctxt)
{
	enum evp_agent_status status;
	evp_agent_lock();
	status = ctxt->status;
	evp_agent_unlock();
	return status;
}

bool
evp_agent_ready(struct evp_agent_context *ctxt)
{
	return evp_agent_get_status(ctxt) != EVP_AGENT_STATUS_INIT;
}

static void *
json_malloc(size_t siz)
{
	return xmalloc(siz);
}

int
evp_agent_start(struct evp_agent_context *ctxt)
{
	/* TLS context */
	ctxt->tls_context = tls_context_initialize();
	if (!ctxt->tls_context) {
		xlog_abort("failed to initialize tls context");
	}

	ctxt->sys = sys_group_alloc();
	if (!ctxt->sys) {
		xlog_abort("failed to initialize the SystemApp group");
	}

	/* initialize the https singleton */
	https_ssl_config_init(&ctxt->tls_context->https.ssl_conf);

	/* initialize state len lock */
	xpthread_mutex_init(&g_evp_global.instance_states_lock);

	/* Configure data directory paths */
	path_init(getenv("EVP_DATA_DIR"));

	/* The following message is parsed by test automation scripts.
	 * Please do not change it. */
	xlog_info("EVP device agent is up");

	// Configure EVP Hub and transport contexts
	char *iot_platform = config_get_string(EVP_CONFIG_IOT_PLATFORM);
	evp_agent_lock();
	ctxt->hub = evp_hub_setup(iot_platform);
	free(iot_platform);

	xlog_info("EVP device agent %s (%s)", AGENT_VERSION,
		  AGENT_COMMIT_HASH);

	xlog_info("EVP client mode: %s", ctxt->hub->impl_name);

	ctxt->transport_ctxt =
		transport_setup(ctxt->hub->on_connected, ctxt->hub->on_message,
				ctxt, ctxt->tls_context);

	connections_set_status(true); // allow module and blob downloads
	start_blob_worker_manager(ctxt);
	json_set_allocation_functions(json_malloc, free);

	init_local_twins_db();
	main_loop_init();
	void *param = NULL;
#if defined(CONFIG_EVP_MODULE_IMPL_DOCKER)
	param = &ctxt->tls_context->docker.ssl_conf;
#endif
	module_init(param);
	module_log_cap_init();
	module_instance_init();
	sdk_init();

	load_desired(ctxt);
	load_current(ctxt);

	module_log_cap_start();
	ctxt->status = EVP_AGENT_STATUS_READY;

	evp_agent_unlock();
	evp_agent_notification_publish(ctxt, "start", NULL);
	return 0;
}

static void
process_report(struct evp_agent_context *ctxt)
{
	if (!ctxt->hub->is_ready()) {
		return;
	}

	if (get_report_interval(&ctxt->report_params)) {
		// TODO: Should we request the agent to exit?
		return;
	}

	periodic_report_status(ctxt, &ctxt->report_params, ctxt->hub,
			       &ctxt->report_status);
	periodic_report_instance_state(ctxt, &ctxt->report_params, ctxt->hub,
				       &ctxt->report_instance_state);
}

int
evp_agent_loop(struct evp_agent_context *ctxt)
{
	int ret = 0;
#if defined(HAVE_LSAN)
	/* cf.
	 * https://github.com/llvm-mirror/compiler-rt/blob/master/include/sanitizer/lsan_interface.h
	 */
	int __lsan_do_recoverable_leak_check(void);

	if (__lsan_do_recoverable_leak_check()) {
		// TODO: Review exit (xlog_abort)
		//       maybe should be an assert
		xlog_abort("Memory leak detected");
	}
#endif
	uint64_t now = gettime_ms();

	enum evp_agent_status status = evp_agent_get_status(ctxt);
	if (status == EVP_AGENT_STATUS_INIT) {
		xlog_error("agent not started");
		return -1;
	}
	if (status == EVP_AGENT_STATUS_STOPPED) {
		return 0;
	}
	if (status == EVP_AGENT_STATUS_CONNECTING ||
	    status == EVP_AGENT_STATUS_CONNECTED) {
		evp_agent_lock();
		ret = transport_sync(ctxt->transport_ctxt, now);
		if (ret) {
			evp_agent_unlock();
			return ret;
		}
		if (transport_is_connected(ctxt->transport_ctxt)) {

			if (ctxt->status != EVP_AGENT_STATUS_CONNECTED) {
				ctxt->status = EVP_AGENT_STATUS_CONNECTED;
				xlog_info("agent connected to hub");
				evp_agent_notification_publish(
					ctxt, "agent/status", "connected");
				evp_agent_notification_publish(
					ctxt, "agent/conn_status",
					"connected");
			}

		} else {
			if (ctxt->status == EVP_AGENT_STATUS_CONNECTED) {
				ctxt->status = EVP_AGENT_STATUS_CONNECTING;
				xlog_info("agent disconnected from hub");
				evp_agent_notification_publish(
					ctxt, "agent/status", "disconnected");
				evp_agent_notification_publish(
					ctxt, "agent/conn_status",
					"connecting");
			}
		}
		evp_agent_unlock();
	}

	ret = main_loop_block();
	if (ret) {
		return ret;
	}

	evp_agent_lock();
	sys_process_events(ctxt->sys);
	dump_memory_usage();
	process_deployment(ctxt);
	if (sdk_check_resend_request()) {
		process_config(ctxt);
	}
	process_report(ctxt);
	module_log_streaming_report(ctxt);
	telemetry_process(ctxt);
	process_blob_rpcs(ctxt);
	direct_command_process(ctxt);
	switch (ctxt->status) {
	case EVP_AGENT_STATUS_CONNECTED:
		resend_requests(ctxt->transport_ctxt);
		break;
	case EVP_AGENT_STATUS_DISCONNECTING:
		if (connections_get_count() == 0) {
			ctxt->status = EVP_AGENT_STATUS_DISCONNECTED;
			ret |= evp_agent_notification_publish(
				ctxt, "agent/status", "disconnected");
			ret |= evp_agent_notification_publish(
				ctxt, "agent/conn_status", "disconnected");
		}
		break;
	default:
		break;
	}
	clean_expired_requests(ctxt);
	sdk_process_outbox_messages();
	evp_agent_unlock();
	return ret;
}

int
evp_agent_stop(struct evp_agent_context *ctxt)
{
	xlog_info("Exiting gracefully...");
	evp_agent_lock();

	json_free_serialized_string(ctxt->report_status.last_report_payload);
	ctxt->report_status.last_report_payload = NULL;
	json_free_serialized_string(
		ctxt->report_instance_state.last_report_payload);
	ctxt->report_instance_state.last_report_payload = NULL;

	module_instance_deinit();

	xpthread_mutex_destroy(&g_evp_global.instance_states_lock);
	path_free();
	deinit_local_twins_db();
	module_log_cap_stop();
	module_log_cap_free();
	module_destroy();
	module_deinit();

	stop_blob_worker_manager();
	transport_free(ctxt->transport_ctxt);
	sys_group_dealloc(ctxt->sys);
	ctxt->transport_ctxt = NULL;
	ctxt->hub = NULL;
	ctxt->sys = NULL;
	ctxt->status = EVP_AGENT_STATUS_STOPPED;

	free(__UNCONST(g_evp_global.deploymentId));

	tls_context_free(ctxt->tls_context);

	evp_agent_unlock();

	return 0;
}

struct EVP_client *
evp_agent_add_instance(struct evp_agent_context *ctxt, const char *name)
{
	struct module_instance *m;
	struct ModuleInstanceSpec spec = {};
	spec.name = __UNCONST(name);
	evp_agent_lock();
	int ret = module_instance_start1(&spec, &m);
	evp_agent_unlock();
	if ((ret != 0 && ret != EEXIST) || m == NULL) {
		return NULL;
	}
	return m->sdk_handle;
}

struct EVP_client *
evp_agent_get_instance(struct evp_agent_context *ctxt, const char *name)
{
	evp_agent_lock();
	struct module_instance *instance = get_module_instance_by_name(name);
	evp_agent_unlock();
	if (instance == NULL) {
		return NULL;
	}
	return instance->sdk_handle;
}

int
evp_agent_stop_instance(struct evp_agent_context *ctxt, const char *name)
{
	evp_agent_lock();
	struct module_instance *instance = get_module_instance_by_name(name);
	int ret = module_instance_stop1(instance);
	evp_agent_unlock();
	return ret;
}

void
evp_agent_send(struct evp_agent_context *ctxt, const char *topic,
	       const char *payload)
{
	evp_agent_lock();
	xlog_info("TEST_MOCK_onMessage: topic=%s, payload=%s", topic, payload);
	ctxt->hub->on_message(ctxt, topic, request_id_alloc(), 0, payload);
	main_loop_wakeup(__func__);
	evp_agent_unlock();
}

void
evp_agent_free(struct evp_agent_context *ctxt)
{
	/* TODO: replace with ctxt->notification. */
	struct notification *notif = notification_singleton;

	notification_free(notif);
	xpthread_mutex_destroy(&ctxt->lock);
	free(ctxt);
}

void
evp_agent_wakeup(const char *name)
{
	main_loop_wakeup(name);
}

int
evp_agent_connect(struct evp_agent_context *ctxt)
{
	enum evp_agent_status status = evp_agent_get_status(ctxt);
	if (status == EVP_AGENT_STATUS_CONNECTING ||
	    status == EVP_AGENT_STATUS_CONNECTED) {
		return 0;
	}
	if (status != EVP_AGENT_STATUS_READY &&
	    status != EVP_AGENT_STATUS_DISCONNECTED &&
	    status != EVP_AGENT_STATUS_DISCONNECTING) {
		return -1;
	}
	evp_agent_lock();
	int rv = transport_connect(ctxt->transport_ctxt);
	ctxt->status = EVP_AGENT_STATUS_CONNECTING;
	connections_set_status(true);
	main_loop_wakeup(__func__);
	evp_agent_unlock();
	return rv;
}

int
evp_agent_disconnect(struct evp_agent_context *ctxt)
{
	enum evp_agent_status status = evp_agent_get_status(ctxt);
	if (status == EVP_AGENT_STATUS_DISCONNECTING ||
	    status == EVP_AGENT_STATUS_DISCONNECTED ||
	    status == EVP_AGENT_STATUS_READY) {
		return 0;
	}
	evp_agent_lock();
	// Cancel queued work that may generate network activity
	module_download_cancel();
	// Disconnect from hub
	int rv = transport_disconnect(ctxt->transport_ctxt);
	// Disconnect network connections
	connections_set_status(false);
	const char *conn_status;
	if (connections_get_count() == 0) {
		ctxt->status = EVP_AGENT_STATUS_DISCONNECTED;
		conn_status = "disconnected";
	} else {
		ctxt->status = EVP_AGENT_STATUS_DISCONNECTING;
		conn_status = "disconnecting";
	}
	main_loop_wakeup(__func__);
	evp_agent_unlock();
	rv |= evp_agent_notification_publish(ctxt, "agent/status",
					     "disconnected");
	rv |= evp_agent_notification_publish(ctxt, "agent/conn_status",
					     conn_status);
	return rv;
}

int
evp_send_storagetoken_request(struct evp_agent_context *agent,
			      struct request *req, JSON_Value *v)
{
	return agent->hub->send_storagetoken_request(agent, req, v);
}

int
evp_agent_undeploy_all(struct evp_agent_context *ctxt)
{
	struct Deployment *empty = create_empty_deployment();
	JSON_Value *v = json_value_init_object();
	evp_agent_lock();
	clear_deployment(ctxt);
	apply_deployment(ctxt, empty, v);
	save_desired(ctxt);
	evp_agent_unlock();
	free_deployment(empty);
	json_value_free(v);
	return 0;
}

int
evp_agent_empty_deployment_has_completed(struct evp_agent_context *ctxt)
{
	return (
		/* 1. reconciliation is complete */
		strcmp(g_evp_global.reconcileStatus, "ok") == 0 &&
		/* 2. deploymentIds match */
		g_evp_global.deploymentId == NULL);
}

int
evp_agent_notification_subscribe(struct evp_agent_context *ctxt,
				 const char *event,
				 int (*cb)(const void *, void *),
				 void *user_data)
{
	if (agent_event_check(event)) {
		xlog_error("agent event %s not recognized", event);
		return -1;
	}

	/* TODO: replace with ctxt->notification. */
	struct notification *notif = notification_singleton;

	return notification_subscribe(notif, event, cb, user_data, NULL);
}

int
evp_agent_notification_publish(struct evp_agent_context *ctxt,
			       const char *event, const void *args)
{
	if (agent_event_check(event)) {
		xlog_error("agent event %s not recognized", event);
	}

	/* TODO: replace with ctxt->notification. */
	struct notification *notif = notification_singleton;

	return notification_publish(notif, event, args);
}

int
evp_deployment_acquire(struct evp_agent_context *ctxt)
{
	return deployment_acquire(&ctxt->deployment);
}

void
evp_deployment_release(struct evp_agent_context *ctxt)
{
	deployment_release(&ctxt->deployment);
}

int
evp_agent_request_pause_deployment(struct evp_agent_context *ctxt)
{
	return deployment_request_pause(&ctxt->deployment);
}

int
evp_agent_resume_deployment(struct evp_agent_context *ctxt)
{
	return deployment_resume(&ctxt->deployment);
}

int
evp_agent_platform_register(struct evp_agent_context *ctxt,
			    const struct evp_agent_platform *p)
{
	if (ctxt->status == EVP_AGENT_STATUS_INIT) {
		return plat_register(p);
	}
	return EBUSY;
}

struct SYS_client *
evp_agent_register_sys_client(struct evp_agent_context *ctxt)
{
	return sys_register(ctxt->sys);
}

int
evp_agent_unregister_sys_client(struct evp_agent_context *ctxt,
				struct SYS_client *c)
{
	return sys_unregister(ctxt->sys, c);
}
