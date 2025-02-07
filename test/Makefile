# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ..

DIRS =\
	certs\

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk

MORE_CPPFLAGS=\
	-I../src/libevp-agent\
	-I../src/libevp-agent/sdkenc\
	-I../src/libevp-agent/MQTT-C/include\
	-I../src/libevp-app-sdk\
	-I../src/libevp-utils\
	-I./mock_objects\
	-I./libweb/include\
	-I./\
	-DDEFAULT_DATA_DIR=\"$$PWD/evp-data\"\

MORE_LDLIBS =\
	-lcmocka\
	-levp-agent\
	-levp-utils\
	-lparson\
	-lweb\
	-ldynstr\
	$(DEPLIBS)\
	-lm\

COMMON=\
	mock_objects/agent_test.o\
	mock_objects/mock_hash.o\
	mock_objects/mock_module_impl_docker.o\
	mock_objects/mock_module_instance_impl_docker.o\
	mock_objects/mock_mqtt.o\
	mock_objects/mock_util.o\
	mock_objects/mock_webclient.o\
	mock_objects/mock_xlog.o\
	mock_objects/module_impl_dummy.o\
	mock_objects/module_instance_impl_dummy.o\
	mock_objects/test_blob_core.o\
	mock_objects/test_blob_mstp_cache.o\
	mock_objects/wasm_utils.o\
	websrv/proxy.o\
	websrv/websrv.o\
	$(PROJECTDIR)/src/evp_agent/config_env.o

UTESTS_EVP1_TB=\
	src/evp1-tb/test_manifest_evp1.elf\
	src/evp1-tb/test_mdc_evp1.elf\
	src/evp1-tb/test_messaging.elf\
	src/evp1-tb/test_module_instance_evp1.elf\
	src/evp1-tb/test_mstp_evp1.elf\

UTESTS_EVP2_TB=\
	src/evp2-tb/test_blob_type_evp_rpc.elf\
	src/evp2-tb/test_config.elf\
	src/evp2-tb/test_configuration.elf\
	src/evp2-tb/test_container_spec.elf\
	src/evp2-tb/test_deployment.elf\
	src/evp2-tb/test_device_config.elf\
	src/evp2-tb/test_device_state.elf\
	src/evp2-tb/test_embed_backdoor.elf\
	src/evp2-tb/test_manifest.elf\
	src/evp2-tb/test_mdc.elf\
	src/evp2-tb/test_models_mstp.elf\
	src/evp2-tb/test_module_instance.elf\
	src/evp2-tb/test_mstp.elf\
	src/evp2-tb/test_mstp_cache.elf\
	src/evp2-tb/test_rename_instance_states.elf\
	src/evp2-tb/test_report_negative_max_interval.elf\
	src/evp2-tb/test_system_info.elf\

UTESTS_NH=\
	src/ut-nohub/libevp-utils/test_chan_alloc.elf\
	src/ut-nohub/libevp-utils/test_chan_dealloc.elf\
	src/ut-nohub/libevp-utils/test_chan_recv.elf\
	src/ut-nohub/libevp-utils/test_djb2.elf\
	src/ut-nohub/libevp-utils/test_string_map_alloc.elf\
	src/ut-nohub/libevp-utils/test_string_map_dealloc.elf\
	src/ut-nohub/libevp-utils/test_string_map_forall.elf\
	src/ut-nohub/libevp-utils/test_string_map_insert.elf\
	src/ut-nohub/libevp-utils/test_string_map_lookup.elf\
	src/ut-nohub/test_blob_strerror.elf\
	src/ut-nohub/test_certificates.elf\
	src/ut-nohub/test_dynlib_cmdline.elf\
	src/ut-nohub/test_evp_notification.elf\
	src/ut-nohub/test_evp_toobig.elf\
	src/ut-nohub/test_fsutil.elf\
	src/ut-nohub/test_get_native_lib.elf\
	src/ut-nohub/test_local_socket.elf\
	src/ut-nohub/test_logging.elf\
	src/ut-nohub/test_module_instance_wasm_except.elf\
	src/ut-nohub/test_module_log_cap.elf\
	src/ut-nohub/test_module_log_queue.elf\
	src/ut-nohub/test_module_log_streaming.elf\
	src/ut-nohub/test_notification.elf\
	src/ut-nohub/test_queue_limits.elf\
	src/ut-nohub/test_sanity.elf\
	src/ut-nohub/test_sdkenc.elf\
	src/ut-nohub/test_signature_verification.elf\
	src/ut-nohub/test_timeutil.elf\
	src/ut-nohub/test_transport.elf\
	src/ut-nohub/test_util.elf\
	src/ut-nohub/test_wasm_api_bad_handle.elf\


STESTS=\
	src/systest/test_backdoor_instance_config.elf\
	src/systest/test_capture_mode.elf\
	src/systest/test_connection_error.elf\
	src/systest/test_deployment.elf\
	src/systest/test_device_config.elf\
	src/systest/test_direct_command.elf\
	src/systest/test_direct_command_parallel.elf\
	src/systest/test_instance_config.elf\
	src/systest/test_instance_state.elf\
	src/systest/test_failed_wasm_load.elf\
	src/systest/test_messaging.elf\
	src/systest/test_mi_denied_requests.elf\
	src/systest/test_mod_download_evp_file.elf\
	src/systest/test_module_log.elf\
	src/systest/test_mstp.elf\
	src/systest/test_mstp_null.elf\
	src/systest/test_python_mod_config_echo.elf\
	src/systest/test_python_mod_telemetry_echo2.elf\
	src/systest/test_python_mod_mdc.elf\
	src/systest/test_python_mod_upload_http_file.elf\
	src/systest/test_python_mod_upload_http_memory.elf\
	src/systest/test_python_mod_zombie.elf\
	src/systest/test_spawn_mod_config_echo.elf\
	src/systest/test_spawn_mod_mstp_cache_load.elf\
	src/systest/test_spawn_mod_mstp_cache_store.elf\
	src/systest/test_spawn_mod_telemetry_echo2.elf\
	src/systest/test_spawn_mod_upload_http_file.elf\
	src/systest/test_sysapp_command.elf\
	src/systest/test_sysapp_telemetry.elf\
	src/systest/test_system_info.elf\
	src/systest/test_telemetry.elf\
	src/systest/test_wasm_blob_http.elf\
	src/systest/test_wasm_blobs.elf\
	src/systest/test_wasm_blobs_tls.elf\
	src/systest/test_wasm_mod_backdoor_state_report.elf\
	src/systest/test_wasm_mod_config_echo.elf\
	src/systest/test_wasm_mod_deployment.elf\
	src/systest/test_wasm_mod_download_http_ext.elf\
	src/systest/test_wasm_mod_failed_connect.elf\
	src/systest/test_wasm_mod_health_check.elf\
	src/systest/test_wasm_mod_http_config_echo.elf\
	src/systest/test_wasm_mod_instance_state.elf\
	src/systest/test_wasm_mod_invalid_free.elf\
	src/systest/test_wasm_mod_messaging.elf\
	src/systest/test_wasm_mod_mstp_cache_load.elf\
	src/systest/test_wasm_mod_mstp_cache_store.elf\
	src/systest/test_wasm_mod_pause_deployment.elf\
	src/systest/test_wasm_mod_performance_boot_mstp.elf\
	src/systest/test_wasm_mod_streams.elf\
	src/systest/test_wasm_mod_telemetry_echo2.elf\
	src/systest/test_wasm_mod_threading.elf\
	src/systest/test_wasm_mod_undeploy_all.elf\
	src/systest/test_wasm_mod_upload_evp_file.elf\
	src/systest/test_wasm_mod_upload_evp_memory.elf\
	src/systest/test_wasm_mod_upload_http_file.elf\
	src/systest/test_wasm_mod_workspace.elf\
	src/systest/test_wasm_repeated_deploy.elf\
	src/systest/test_wasm_rpc.elf\
	src/systest/test_wasm_telemetry.elf\

STESTS_NH=\
	src/st-nohub/test_blob_type_http.elf\
	src/st-nohub/test_blob_type_http_ext.elf\
	src/st-nohub/test_cancel_blob.elf\
	src/st-nohub/test_connection_mode.elf\
	src/st-nohub/test_connection_timeout.elf\
	src/st-nohub/test_connections_disconnecting.elf\
	src/st-nohub/test_instance_event_timeout.elf\
	src/st-nohub/test_start_stop.elf\
	src/st-nohub/test_sysapp_blob.elf\
	src/st-nohub/test_sysapp_blob_put.elf\
	src/st-nohub/test_sysapp_blob_put_mstp.elf\
	src/st-nohub/test_sysapp_config.elf\
	src/st-nohub/test_sysapp_state.elf\
	src/st-nohub/test_worker_manager.elf\

TESTS=$(UTESTS_EVP1_TB) $(UTESTS_EVP2_TB) $(UTESTS_NH) $(STESTS) $(STESTS_NH)

BINDEPS =\
	$(LIBDIR)/libevp-agent.a\
	$(LIBDIR)/libevp-utils.a\
	$(LIBDIR)/libparson.a\
	$(LIBDIR)/libweb.a\
	$(LIBDIR)/libdynstr.a\
	$(FILELIBS)\

all: test

build: $(TESTS)

$(COMMON) $(TESTS:.elf=.o): libweb libdynstr
$(TESTS): $(COMMON) certs $(BINDEPS)

# libweb and libdynstr does not accept parameters in CFLAGS or LDFLAGS
# and for that reason we have to modify the MAKEFLAGS environment
# variable to remove any possible value on them
libweb libdynstr: FORCE
	cd $@ && MAKEFLAGS='' $(MAKE) CC=$(CC)

libdynstr/.git: libweb/.git
libweb/.git:
	git submodule update --recursive --init libweb

libweb: libweb/.git
libdynstr: libdynstr/.git

libweb: libdynstr

$(LIBDIR)/libweb.a: libweb
	cp libweb/libweb.a $@

$(LIBDIR)/libdynstr.a: libdynstr
	cp libdynstr/libdynstr.a $@

# Overwrite the general rule to generate .elf. We could use other extension
# to avoid overriding, but I only thought about using .test, but having things
# like test_manifest_evp1.test seemed too much testing to me.
%.elf: %.o
	$(LD) -r -o $@-tmp.o $< $(COMMON)
	$(NM) $@-tmp.o | awk '$$3 ~ /^__wrap/ {\
		gsub(/__wrap_/, "");\
		printf ",--wrap=%s", $$3\
	}' > $@.wrap
	$(CC) $(PROJ_LDFLAGS) -o $@ $@-tmp.o -Wl`cat $@.wrap` $(PROJ_LDLIBS)
	rm $@-tmp.o $@.wrap

test: FORCE
	rm -rf logs
	+@$(MAKE) test-helper

test-helper: run-ut run-st
	@awk '\
		BEGIN  {print "----------- SUMMARY -----------"}\
		/PASS/ {pass++}\
		/FAIL/ {fail++; ln = ln $$0 "\n"}\
		       {run++}\
		END {\
			print "RUN", int(run);\
			print "PASSED", int(pass);\
			print "FAILED", int(fail);\
			print ln;\
			exit fail != 0\
		}' logs/*/run-*.res

.IGNORE: run-ut run-st
.IGNORE: run-ut-evp1-tb run-ut-evp2-tb run-ut-nh
.IGNORE: run-st-evp1-tb run-st-evp2-tb run-st-nh

run-ut: run-ut-evp1-tb run-ut-evp2-tb run-ut-nh
run-st: run-st-evp1-tb run-st-evp2-tb run-st-nh

run-ut-evp1-tb: $(UTESTS_EVP1_TB) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP1-TB -p EVP1 $(UTESTS_EVP1_TB)

run-ut-evp2-tb: $(UTESTS_EVP2_TB) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP2-TB -p TB $(UTESTS_EVP2_TB)

run-ut-nh: $(UTESTS_NH) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP2-TB -p TB $(UTESTS_NH)

run-st-evp1-tb: $(STESTS) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP1-TB -p EVP1 $(STESTS)

run-st-evp2-tb: $(STESTS) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP2-TB -p TB $(STESTS)

run-st-nh: $(STESTS_NH) FORCE
	@./run-tests.sh $(RUNFLAGS) -d logs/EVP2-TB -p TB $(STESTS_NH)

clean:
	test -f libweb/Makefile && cd libweb && $(MAKE) clean || true
	test -f libdynstr/Makefile && cd libdynstr && $(MAKE) clean || true
	rm -rf logs
	find . -name '*.o' | xargs rm -f
	find . -name '*.elf' | xargs rm -f
	find . -name '*.wrap' | xargs rm -f

distclean:
	find . -name '*.d' | xargs rm -f

src/ut-nohub/test_sdkenc.o:
	$(CC) $(PROJ_CFLAGS) -c -Wno-cast-align -o $@ src/ut-nohub/test_sdkenc.c
