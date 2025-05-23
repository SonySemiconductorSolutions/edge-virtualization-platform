# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ..

DIRS =\
	python

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk

KEY_FILE=../tools/module_key.bin

MODULES =\
	config_echo.$(EXT)\
	download_azure_file.$(EXT)\
	download_azure_memory.$(EXT)\
	download_http_ext_memory.$(EXT)\
	download_http_ext_range_file.$(EXT)\
	download_http_file.$(EXT)\
	exit_voluntarily.$(EXT)\
	file_reader.$(EXT)\
	file_writer.$(EXT)\
	hub_scalability_test.$(EXT)\
	hub_scalability_test_stderr.$(EXT)\
	invalid_free.$(EXT)\
	messaging.$(EXT)\
	performance_boot_mstp.$(EXT)\
	performance_boot_mstp_memory.$(EXT)\
	rpc.$(EXT)\
	stream_reader.$(EXT)\
	stream_reader_large.$(EXT)\
	stream_writer.$(EXT)\
	stream_writer_large.$(EXT)\
	telemetry_echo2.$(EXT)\
	threading.$(EXT)\
	upload_azure_file.$(EXT)\
	upload_evp_file.$(EXT)\
	upload_evp_legacy_file.$(EXT)\
	upload_evp_memory.$(EXT)\
	upload_evp_mstp_file.$(EXT)\
	upload_http_file.$(EXT)\
	zombie.$(EXT)\

HUB_OBJS =\
	hub_scalability_test.$O\
	hub_scalability_test_stdout.$O\
	parson.$O\
	timer.$O\

HUB_STDERR_OBJS =\
	hub_scalability_test.$O\
	hub_scalability_test_stderr.$O\
	parson.$O\
	timer.$O\

RPC_OBJS =\
	parson.$O\
	rpc.$O\

EXT = elf
TARGET=x86_64
WAMRC= $(WAMRC_PREFIX)wamrc
WAMRC_XTENSA = $(WAMRC_PREFIX)wamrc-xtensa

MORE_LDLIBS =\
	-levp-app-sdk\
	$(DEPLIBS)\
	-lm\

all: python elf wasm aot xip

elf: FORCE
	$(MAKE) EXT=elf modules

wasm: FORCE
	$(MAKE) EXT=wasm TOOL=wasi SYS=wasm modules

aot: wasm
	$(MAKE) TOOL=wasi WAMRC_FLAGS="--disable-simd --size-level=1" EXT=wasm.x86_64.aot modules
	$(MAKE) TOOL=wasi TARGET=aarch64 EXT=wasm.aarch64.aot modules
	$(MAKE) TOOL=wasi WAMRC=$(WAMRC_XTENSA) TARGET=xtensa EXT=wasm.xtensa.aot modules

xip: wasm
	$(MAKE) TOOL=wasi WAMRC_FLAGS="--disable-simd" EXT=wasm.x86_64.aot.xip modules
	$(MAKE) TOOL=wasi TARGET=aarch64 EXT=wasm.aarch64.aot.xip modules
	$(MAKE) TOOL=wasi WAMRC=$(WAMRC_XTENSA) TARGET=xtensa EXT=wasm.xtensa.aot.xip modules

signed: xip
	$(MAKE) TARGET=xtensa EXT=wasm.xtensa.aot.xip.signed modules

%.wasm.$(TARGET).aot.xip.signed: %.wasm.$(TARGET).aot.xip
	python3 ../tools/sign_module.py -m $< -k $(KEY_FILE)

hub_scalability_test.wasm: $(HUB_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(HUB_OBJS)

hub_scalability_test.elf: $(HUB_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(HUB_OBJS) $(PROJ_LDLIBS)

hub_scalability_test_stderr.wasm: $(HUB_STDERR_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(HUB_STDERR_OBJS)

hub_scalability_test_stderr.elf: $(HUB_STDERR_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(HUB_STDERR_OBJS) $(PROJ_LDLIBS)

rpc.wasm: $(RPC_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(RPC_OBJS)

rpc.elf: $(RPC_OBJS)
	$(CC) $(PROJ_LDFLAGS) -o $@ $(RPC_OBJS) $(PROJ_LDLIBS)

modules: $(MODULES)

%.wasm.$(TARGET).aot: %.wasm
	$(WAMRC) --target=$(TARGET) $(WAMRC_FLAGS) -o $@ $<

%.wasm.$(TARGET).aot.xip: %.wasm
	$(WAMRC) --target=$(TARGET) --xip --bounds-checks=0 --size-level=0 $(WAMRC_FLAGS) $(WAMRC_XIP_FLAGS) -o $@ $<

clean:
	rm -f *.elf *.wasm *.aot *.xip *.signed
