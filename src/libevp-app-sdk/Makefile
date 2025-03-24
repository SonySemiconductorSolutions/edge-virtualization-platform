# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk
-include $(PROJECTDIR)/.config

MORE_CPPFLAGS = \
	-I../libevp-agent \
	-I../libevp-agent/sdkrpc \
	-DEVPMODULESDK \
	-fPIC \

obj-y += \
	absts2relms_realtime_roundup.o\
	gettime.o\
	local_socket.o \
	notification.o \
	sdk_callback_native.o \
	sdk_common.o \
	sdk_execute.o \
	stream/null.o \
	stream/stream.o \
	stream/posix.o \
	relms2absts_realtime.o\
	sdkrpc/client_io.o \
	xcalloc.o\
	xmalloc.o\

obj-$(CONFIG_EVP_SDK_SOCKET) += \
	sdk.o \
	sdkrpc/client.o \

all: libevp-app-sdk.a libevp-app-sdk-bundle.a

libevp-app-sdk.o: $(obj-y)
	$(LD) -r -o $@ $(MORE_LDFLAGS) $(obj-y) -X -x
	$(OBJCOPY) --keep-global-symbols=symbols.list $@

libevp-app-sdk.a: libevp-app-sdk.o
	$(AR) $(PROJ_ARFLAGS) $@ $?
	cp $@ $(LIBDIR)

libevp-app-sdk-bundle.o: libevp-app-sdk.o
	$(LD) -r -o $@ -L$(LIBDIR) libevp-app-sdk.o $(DEPLIBS)

libevp-app-sdk-bundle.a: libevp-app-sdk-bundle.o
	$(AR) $(PROJ_ARFLAGS) $@ $?
	cp $@ $(LIBDIR)

clean:
	rm -f $(LIBDIR)/libevp-app-sdk*.a
	find . -name '*.o' | xargs rm -f
	find . -name '*.d' | xargs rm -f

sdk.o:
	$(CC) $(PROJ_CFLAGS) -c -Wno-cast-align sdk.c
