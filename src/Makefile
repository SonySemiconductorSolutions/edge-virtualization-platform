# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ..

EVP_LIBS = \
	libevp-agent\
	libevp-utils\
	libevp-app-sdk \

DIRS = \
	evp_agent\
	libparson\
	sdkenc\
	$(EVP_LIBS)

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk

# After build try to remove the cmake directory that
# some cmake projects create in the top directory
all: evp_agent libs
	rm -rf $(PROJECTDIR)/cmake

depend: $(LIBDIRS)

libs: $(EVP_LIBS)

libevp-agent libevp-app-sdk: $(LIBDIRS)

libevp-agent: libevp-utils

evp_agent: libevp-agent libevp-utils

sdkenc: flatcc

# cmake dependencies
wasm-micro-runtime: wasm-micro-runtime/build/Makefile
flatcc: flatcc/build/Makefile
mbedtls: mbedtls/build/Makefile
