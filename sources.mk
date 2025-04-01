# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

CSRCS += src/libparson/parson.c
CSRCS += agent_event.c
CSRCS += backdoor.c
CSRCS += base64.c
CSRCS += blob.c
CSRCS += blob_get.c
CSRCS += blob_http.c
CSRCS += blob_put.c
CSRCS += blob_rpc.c
CSRCS += blob_type_azure_blob.c
CSRCS += blob_type_evp.c
CSRCS += blob_type_evp_rpc.c
CSRCS += blob_type_http.c
CSRCS += certificates.c
CSRCS += config.c
CSRCS += config_pk_file.c
CSRCS += connections.c
CSRCS += deployment.c
CSRCS += device_config.c
CSRCS += device_state.c
CSRCS += direct_command.c
CSRCS += evp_agent.c
CSRCS += evp_hub.c
CSRCS += fsutil.c
CSRCS += hash.c
CSRCS += hub/tb/tb.c
CSRCS += hub/hub_tb.c
CSRCS += mstp_schema.c
CSRCS += hub/dispatch.c
CSRCS += https_ssl_config.c
CSRCS += instance_config.c
CSRCS += ioutil.c
CSRCS += local_socket.c
CSRCS += main_loop.c
CSRCS += manifest.c
CSRCS += map.c
CSRCS += models/mstp.c
CSRCS += module.c
CSRCS += module_log_cap.c
CSRCS += module_log_queue.c
CSRCS += module_log_send_telemetry.c
CSRCS += module_log_streaming.c
CSRCS += module_instance.c
CSRCS += module_instance_impl_ops.c
CSRCS += module_impl_ops.c
CSRCS += mqtt_pal/mbedtls.c
CSRCS += mqtt_pal/tcp.c
CSRCS += mqtt_pal_custom.c
CSRCS += MQTT-C/src/mqtt.c
$(EVP_AGENT_OSS)/src/libevp-agent/MQTT-C/src/mqtt.c_CFLAGS = -include mqtt_pal_socket_handle.h
CSRCS += netlib/netlib_parseurl.c
CSRCS += notification.c
CSRCS += pal.c
CSRCS += path.c
CSRCS += platform.c
CSRCS += proxy.c
CSRCS += reconcile.c
CSRCS += report.c
CSRCS += report_refresh.c
CSRCS += report_send.c
CSRCS += req.c
CSRCS += retry.c
CSRCS += signature_verification.c
CSRCS += sdk.c
CSRCS += sdk_msg.c
CSRCS += socketutil.c
CSRCS += stream/stream.c
CSRCS += stream/null.c
CSRCS += stream/posix.c
CSRCS += system_info.c
CSRCS += tcp.c
CSRCS += telemetry.c
CSRCS += timeutil.c
CSRCS += tls.c
CSRCS += transport.c
CSRCS += util.c
CSRCS += webclient/webclient.c
CSRCS += webclient_mbedtls.c
CSRCS += work.c
CSRCS += xlog.c
CSRCS += xmqtt.c
CSRCS += xpthread.c
CSRCS += sys/sys_client_alloc.c
CSRCS += sys/sys_client_dealloc.c
CSRCS += sys/sys_collect_responses.c
CSRCS += sys/sys_collect_states.c
CSRCS += sys/sys_collect_telemetry.c
CSRCS += sys/sys_common.c
CSRCS += sys/sys_ddc_dealloc.c
CSRCS += sys/SYS_get_blob.c
CSRCS += sys/sys_group_alloc.c
CSRCS += sys/sys_group_dealloc.c
CSRCS += sys/sys_is_sysapp.c
CSRCS += sys/sys_notify_config.c
CSRCS += sys/sys_notify_ddc.c
CSRCS += sys/SYS_put_blob.c
CSRCS += sys/SYS_put_blob_mstp.c
CSRCS += sys/SYS_process_event.c
CSRCS += sys/sys_process_events.c
CSRCS += sys/SYS_reason_tostr.c
CSRCS += sys/sys_register.c
CSRCS += sys/SYS_register_command_cb.c
CSRCS += sys/SYS_result_tostr.c
CSRCS += sys/SYS_send_telemetry.c
CSRCS += sys/SYS_set_response_cb.c
CSRCS += sys/SYS_set_configuration_cb.c
CSRCS += sys/SYS_set_state.c
CSRCS += sys/sys_state_dealloc.c
CSRCS += sys/sys_telemetry_dealloc.c
CSRCS += sys/sys_unregister.c

ifeq ($(CONFIG_EVP_MODULE_IMPL_DLFCN),y)
CSRCS += health_check.c
CSRCS += module_api_dlfcn.c
CSRCS += module_impl_dlfcn.c
CSRCS += module_instance_impl_dlfcn.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_DOCKER),y)
CSRCS += docker.c
CSRCS += docker_worker.c
CSRCS += module_impl_docker.c
CSRCS += module_instance_impl_docker.c
CSRCS += module_instance_path.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_NOOP),y)
CSRCS += module_instance_impl_noop.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_OBJ),y)
CSRCS += module_impl_obj.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_SPAWN),y)
CSRCS += module_impl_spawn.c
CSRCS += module_instance_impl_spawn.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_WASM),y)
CSRCS += module_api_wasm.c
CSRCS += module_impl_wasm.c
CSRCS += module_instance_impl_wasm.c
CSRCS += sdk_callback_wasm.c
CSRCS += sdk_local_wasm.c
endif

ifeq ($(CONFIG_EVP_MODULE_IMPL_PYTHON),y)
CSRCS += module_impl_python.c
CSRCS += module_instance_impl_python.c
endif

ifeq ($(CONFIG_EVP_SDK_LOCAL),y)
CSRCS += sdk_common.c
CSRCS += sdk_local.c
CSRCS += sdk_execute.c
CSRCS += sdk_local_native.c
CSRCS += sdk_callback_native.c
endif

ifeq ($(CONFIG_EVP_SDK_SOCKET),y)
CSRCS += sdk_remote.c
CSRCS += sdk_worker.c
CSRCS += sdkrpc/server.c
endif

ifeq ($(CONFIG_EVP_TWINS_PERSISTENCE),y)
CSRCS += persist.c
endif

ifeq ($(CONFIG_EVP_TWINS_NO_PERSISTANCE),y)
CSRCS += nopersist.c
endif

ifeq ($(CONFIG_EVP_AGENT_MODULE_IMPL_DOCKER_RAW_CONTAINER_SPEC),y)
CSRCS += container_spec.c
endif
