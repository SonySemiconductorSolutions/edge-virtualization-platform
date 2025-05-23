# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

# Put a dummy all rule here only to force having it
# as default rule in all the Makefiles
all:

# Macros related to the version of the agent
VERSION = 1.48.0
SDK_VERSION = 1.0.0

# Default value for configuration macros
O       = o
TOOL    = gnu
ARCH    = `uname -m`
SYS     = posix
KBUILD_DEFCONFIG = configs/default.config

# Define common locations that can be used in all the
# Makefiles.
INCDIR    = $(PROJECTDIR)/include
BINDIR    = $(PROJECTDIR)/bin
LIBDIR    = $(PROJECTDIR)/lib
SCRIPTDIR = $(PROJECTDIR)/scripts

# Locations for includes
CPPINCLUDES = -I$(INCDIR)
ASINCLUDES= -I$(INCDIR)
LDINCLUDES= -L$(LIBDIR)

# Include optional personal preferences
-include $(PROJECTDIR)/config.mk

# Include configuration definitions
include $(SCRIPTDIR)/build/tool/$(TOOL).mk
include $(SCRIPTDIR)/build/sys/$(SYS).mk

# Definitions of command line for cc, as, ld
PROJ_CPPFLAGS =\
	$(CPPINCLUDES)\
	$(MORE_CPPFLAGS)

PROJ_CFLAGS =\
	$(PROJ_CPPFLAGS)\
	$(MORE_CFLAGS)\
	$(SYS_CFLAGS)\
	$(TOOL_CFLAGS)\
	$(CFLAGS)

PROJ_CXXFLAGS =\
	$(PROJ_CPPFLAGS)\
	$(MORE_CFLAGS)\
	$(SYS_CFLAGS)\
	$(TOOL_CXXFLAGS)\
	$(CFLAGS)

PROJ_LDFLAGS =\
	$(MORE_LDFLAGS)\
	$(SYS_LDFLAGS)\
	$(TOOL_LDFLAGS)\
	$(LDINCLUDES)\
	$(LDFLAGS)

PROJ_ASFLAGS =\
	$(MORE_ASFLAGS)\
	$(SYS_ASFLAGS)\
	$(TOOL_ASFLAGS)\
	$(ASINCLUDES)\
	$(ASFLAGS)

PROJ_ARFLAGS =\
	$(MORE_ARFLAGS)\
	$(SYS_ARFLAGS)\
	$(TOOL_ARFLAGS)\
	$(ARFLAGS)

PROJ_RLFLAGS =\
	$(MORE_RLFLAGS)\
	$(SYS_RLFLAGS)\
	$(TOOL_RLFLAGS)\
	$(RLFLAGS)

PROJ_LDLIBS =\
	$(MORE_LDLIBS)\
	$(SYS_LDLIBS)\
	$(TOOL_LDLIBS)\
	$(LIBS)

# Definition of tools
CXX = $(CROSS_COMPILE)$(COMPXX)
CC = $(CROSS_COMPILE)$(COMP)
AS = $(CROSS_COMPILE)$(ASM)
LD = $(CROSS_COMPILE)$(LINKER)
AR = $(CROSS_COMPILE)$(ARCHIVE)
CPP = $(CROSS_COMPILE)$(PRECOMP)
NM = $(CROSS_COMPILE)$(NAMES)
RANLIB = $(CROSS_COMPILE)$(RLIB)
OBJCOPY = $(CROSS_COMPILE)$(OCOPY)
OBJDUMP = $(CROSS_COMPILE)$(ODUMP)

# Generic rules
.SUFFIXES:
.SUFFIXES: .a .c .cpp .lst .dump .elf .i .o .wo .s .wasm

.s.o:
	$(AS) $(PROJ_ASFLAGS) $< -o $@

.S.o:
	$(CPP) $(PROJ_CPPFLAGS) $< | $(AS) $(PROJ_ASFLAGS) -o $@

.c.o:
	$(CC) $(PROJ_CFLAGS) -o $@ -c $<

.cpp.o:
	$(CC) $(PROJ_CXXFLAGS) -o $@ -c $<

.c.wo:
	$(CC) $(PROJ_CFLAGS) -o $@ -c $<

.o.elf:
	$(CC) $(PROJ_LDFLAGS) -o $@ $< $(PROJ_LDLIBS)

.wo.wasm:
	$(CC) $(PROJ_LDFLAGS) -o $@ $<

.c.s:
	$(CC) $(PROJ_CFLAGS) -S -o $@ $<

.c.i:
	$(CPP) $(PROJ_CPPFLAGS) -o $@ $<

.o.dump:
	trap "rm -f $$$$.dump" EXIT QUIT INT TERM;\
	$(OBJDUMP) -D $< > $$$$.dump && mv $$$$.dump $@

.elf.dump:
	trap "rm -f $$$$.dump" EXIT QUIT INT TERM;\
	$(OBJDUMP) -D $< > $$$$.dump && mv $$$$.dump $@

.o.lst:
	trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
	$(NM) $< > $$$$.lst && mv $$$$.lst $@

.elf.lst:
	trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
	$(NM) $< > $$$$.lst && mv $$$$.lst $@

.a.lst:
	trap "rm -f $$$$.lst" EXIT QUIT INT TERM;\
	$(NM) $< > $$$$.lst && mv $$$$.lst $@

# FORCE rule will force to rebuild any target depending
# on it. It doesn't depend on any extension and it
# works in cases where the PHONY extension doesn't work
# Anyway, we put a .PHONY dependency just in case.
FORCE:
.PHONY: FORCE

# Rules to implement the recursive makefile structure
# for clean, distclean and all targets. DIRS variable
# must be defined before this file is included.
$(DIRS): FORCE
	+@cd $@ && $(MAKE)

clean: clean-dirs clean-files clean-cmake

clean-files: FORCE
	rm -f *.wo *.o *.so *.a *.d

clean-dirs: FORCE
	+@set -e;\
	for i in $(DIRS);\
	do\
		cd $$i;\
		$(MAKE) clean;\
		cd -;\
	done

distclean: clean distclean-dirs distclean-cmake

distclean-dirs: FORCE
	+@set -e;\
	for i in $(DIRS);\
	do\
		cd $$i;\
		$(MAKE) distclean;\
		cd -;\
	done

# CMake rules
%/build/Makefile: %/CMakeLists.txt
	CC=$(CC) \
	CXX=$(CXX) \
	SYS=$(SYS) \
	ARCH=$(ARCH) \
	CFLAGS='$(CFLAGS)' \
	MBEDTLS_CFLAGS='$(MBEDTLS_CFLAGS)' \
	MBEDTLS_USER_CONFIG_FILE='$(MBEDTLS_USER_CONFIG_FILE)' \
	$(SCRIPTDIR)/cmake-$*.sh $(PWD)/$(PROJECTDIR)

%: %/build/Makefile FORCE
	cd $@/build && $(MAKE) install

clean-cmake: FORCE
	+@set -e;\
	for i in `ls -d */build/CMakeFiles 2>/dev/null`;\
	do\
		cd `dirname $$i`;\
		$(MAKE) clean;\
		cd -;\
	done

distclean-cmake: FORCE
	@echo */build/CMakeFiles | sed s'/CMakeFiles//' | xargs rm -rf
