# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk

MORE_CPPFLAGS = \
	-IMQTT-C/include\

obj-y += \
	agent_event.o\
	backdoor.o\
	base64.o\
	blob.o\
	blob_get.o\
	blob_http.o\
	blob_put.o\
	blob_rpc.o\
	blob_type_azure_blob.o\
	blob_type_evp.o\
	blob_type_evp_rpc.o\
	blob_type_http.o\
	certificates.o\
	config.o\
	config_pk_file.o\
	connections.o\
	deployment.o\
	device_config.o\
	device_state.o\
	direct_command.o\
	evp_agent.o\
	evp_hub.o\
	fsutil.o\
	hash.o\
	hub/tb/tb.o\
	hub/hub_tb.o\
	mstp_schema.o\
	hub/dispatch.o\
	https_ssl_config.o\
	instance_config.o\
	ioutil.o\
	local_socket.o\
	main_loop.o\
	manifest.o\
	map.o\
	models/mstp.o\
	module.o\
	module_log_cap.o\
	module_log_queue.o\
	module_log_send_telemetry.o\
	module_log_streaming.o\
	module_instance.o\
	module_instance_impl_ops.o\
	module_impl_ops.o\
	mqtt_pal/mbedtls.o\
	mqtt_pal/tcp.o\
	mqtt_pal_custom.o\
	mqtt.o\
	notification.o\
	pal.o\
	path.o\
	platform.o\
	proxy.o\
	reconcile.o\
	report.o\
	report_refresh.o\
	report_send.o\
	req.o\
	retry.o\
	signature_verification.o\
	sdk.o\
	sdk_msg.o\
	socketutil.o\
	stream/null.o\
	stream/stream.o\
	stream/posix.o\
	system_info.o\
	tcp.o\
	telemetry.o\
	timeutil.o\
	transport.o\
	util.o\
	work.o\
	xlog.o\
	xmqtt.o\
	tls.o\
	xpthread.o\
	webclient/webclient.o\
	webclient_mbedtls.o\
	netlib/netlib_parseurl.o\
	sys/sys_collect_responses.o\
	sys/sys_common.o\
	sys/sys_client_alloc.o\
	sys/sys_client_dealloc.o\
	sys/sys_collect_states.o\
	sys/sys_collect_telemetry.o\
	sys/sys_ddc_dealloc.o\
	sys/SYS_get_blob.o\
	sys/sys_group_alloc.o\
	sys/sys_group_dealloc.o\
	sys/sys_is_sysapp.o\
	sys/sys_notify_config.o\
	sys/sys_notify_ddc.o\
	sys/SYS_process_event.o\
	sys/sys_process_events.o\
	sys/SYS_put_blob.o\
	sys/SYS_put_blob_mstp.o\
	sys/SYS_reason_tostr.o\
	sys/sys_register.o\
	sys/SYS_register_command_cb.o\
	sys/SYS_result_tostr.o\
	sys/SYS_send_telemetry.o\
	sys/SYS_set_response_cb.o\
	sys/SYS_set_configuration_cb.o\
	sys/SYS_set_state.o\
	sys/sys_state_dealloc.o\
	sys/sys_telemetry_dealloc.o\
	sys/sys_unregister.o\

obj-$(CONFIG_EVP_MODULE_IMPL_DLFCN) += \
	health_check.o\
	module_api_dlfcn.o\
	module_impl_dlfcn.o\
	module_instance_impl_dlfcn.o\

obj-$(CONFIG_EVP_MODULE_IMPL_DOCKER) += \
	docker.o\
	docker_worker.o\
	module_impl_docker.o\
	module_instance_impl_docker.o\
	module_instance_path.o\

obj-$(CONFIG_EVP_MODULE_IMPL_WASM) += \
	module_api_wasm.o\
	module_impl_wasm.o\
	module_instance_impl_wasm.o\
	sdk_callback_wasm.o\
	sdk_local_wasm.o\

obj-$(CONFIG_EVP_SDK_LOCAL) += \
	sdk_common.o\
	sdk_local.o\
	sdk_execute.o\
	sdk_local_native.o\
	sdk_callback_native.o\

obj-$(CONFIG_EVP_SDK_SOCKET) += \
	sdk_remote.o\
	sdk_worker.o\
	sdkrpc/server.o\

obj-$(CONFIG_EVP_MODULE_IMPL_NOOP) += module_instance_impl_noop.o
obj-$(CONFIG_EVP_MODULE_IMPL_OBJ) += module_impl_obj.o
obj-$(CONFIG_EVP_MODULE_IMPL_SPAWN) += module_impl_spawn.o module_instance_impl_spawn.o
obj-$(CONFIG_EVP_MODULE_IMPL_PYTHON) += module_impl_python.o module_instance_impl_python.o
obj-$(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_RAW_CONTAINER_SPEC) += container_spec.o

obj-$(CONFIG_EVP_TWINS_PERSISTENCE) += persist.o
obj-$(CONFIG_EVP_TWINS_NO_PERSISTANCE) += nopersist.o

all: libevp-agent.a

libevp-agent.a: $(obj-y)
	$(AR) $(PROJ_ARFLAGS) $@ $?
	$(RANLIB) $@
	cp $@ $(LIBDIR)

clean:
	rm -f $(LIBDIR)/libevp-agent.a
	find . -name '*.o' | xargs rm -f
	find . -name '*.d' | xargs rm -f

sdkrpc/server.o:
	$(CC) $(PROJ_CFLAGS) -c -Wno-cast-align -Wno-clobbered -o $@ sdkrpc/server.c

sdk_remote.o:
	$(CC) $(PROJ_CFLAGS) -c -Wno-cast-align sdk_remote.c
