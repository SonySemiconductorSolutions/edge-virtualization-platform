# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

include $(SCRIPTDIR)/build/tool/clang.mk

O = wo
LDINCLUDES= -L$(LIBDIR)/wasm
CROSS_COMPILE = $(WASI_PREFIX)

# Max memory is computed as a number of pages of 64KB, the default is 256KB or 4 pages.
MAX_MEM = $$((4 << 16))

TOOL_CFLAGS =\
	-Os\
	$${WASI_SYSROOT:+--sysroot=$$WASI_SYSROOT} \
	-pthread\
	-target wasm32-wasi-threads\
	-fPIE\

TOOL_LDFLAGS =\
	$${WASI_SYSROOT:+--sysroot=$$WASI_SYSROOT} \
	-target wasm32-wasi-threads \
	-pthread\
	-lpthread\
	-Wl,--max-memory=$(MAX_MEM) \
	-Wl,-allow-undefined \
	-Wl,--export=malloc \
	-Wl,--export=free \
	-Wl,--export=__data_end \
	-Wl,--export=__heap_base \
