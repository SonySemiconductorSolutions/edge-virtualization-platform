# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk

FLATCC=$(PROJECTDIR)/bin/flatcc

all: stamp

stamp: sdk.fbs
	$(FLATCC) \
		-a \
		--json-printer \
		sdk.fbs
	mkdir -p $(INCDIR)/sdkenc
	cp *.h $(INCDIR)/sdkenc
	touch $@

clean:
	rm -f *.h stamp
