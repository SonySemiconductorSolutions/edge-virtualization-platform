# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk

all: libparson.a

libparson.a: parson.o
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $@
	cp $@ $(LIBDIR)
	cp parson.h $(INCDIR)
