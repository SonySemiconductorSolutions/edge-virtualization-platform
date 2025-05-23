# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk

DEPS =\
	evp/app/backend.i\
	evp/app/backend.py\
	evp/app/blob.py\
	evp/app/client.py\
	evp/app/command.py\
	evp/app/configuration.py\
	evp/app/exceptions.py\
	evp/app/executor.py\
	evp/app/__init__.py\
	evp/app/state.py\
	evp/app/telemetry.py\
	external/lib/libevp-app-sdk-bundle.a\

TARGET = $(LIBDIR)/python

all: $(TARGET)

dist-stamp: $(DEPS)
	CFLAGS='$(CFLAGS)' LDFLAGS='$(LDFLAGS)' CC=$(CC) python -m build
	set -e; for f in dist/*.whl; do \
		plat=$$(python3 get_manylinux_platform.py $$f); \
		auditwheel repair --plat $$plat $$f; \
	done
	touch $@

$(TARGET): dist-stamp
	mkdir -p $@
	cp wheelhouse/* $@

clean:
	rm -rf $(TARGET)
	rm -rf dist
	rm -rf wheelhouse
	rm -f dist-stamp
