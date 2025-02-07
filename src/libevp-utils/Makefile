# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

-include $(PROJECTDIR)/.config
include $(PROJECTDIR)/scripts/rules.mk

OBJS += \
	chan_alloc.o\
	chan_dealloc.o\
	chan_dequeue.o\
	chan_item_alloc.o\
	chan_item_dealloc.o\
	chan_enqueue.o\
	chan_recv.o\
	chan_recv_helper.o\
	chan_tryrecv.o\
	chan_timedrecv.o\
	chan_send.o\
	chan_size.o\
	djb2.o\
	string_map_alloc.o\
	string_map_count.o\
	string_map_dealloc.o\
	string_map_forall.o\
	string_map_insert.o\
	string_map_lookup.o\

all: libevp-utils.a

libevp-utils.a: $(OBJS)
	$(AR) $(PROJ_ARFLAGS) $@ $?
	$(RANLIB) $@
	cp $@ $(LIBDIR)

clean:
	rm -f $(LIBDIR)/libevp-utils.a
