# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ..

DIRS = \
	evp_agent\
	libparson\
	sdkenc\
	libevp-agent\
	libevp-utils\
	libevp-app-sdk\
	python-evp-app-sdk\

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk
-include $(PROJECTDIR)/.config

EVP_LIBS-y += \
	libevp-agent\
	libevp-utils\

EVP_LIBS-$(CONFIG_EVP_SDK_SOCKET) +=\
	libevp-app-sdk\

# After build try to remove the cmake directory that
# some cmake projects create in the top directory
all: evp_agent libs
	rm -rf $(PROJECTDIR)/cmake

depend: $(LIBDIRS)

libs: $(EVP_LIBS-y)

libevp-agent libevp-app-sdk: $(LIBDIRS)

python-evp-app-sdk: libevp-app-sdk

libevp-agent: libevp-utils

evp_agent: libevp-agent libevp-utils

sdkenc: flatcc

# cmake dependencies
wasm-micro-runtime: wasm-micro-runtime/build/Makefile
flatcc: flatcc/build/Makefile
mbedtls: mbedtls/build/Makefile
