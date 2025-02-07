# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

COMPXX = g++
COMP = gcc
OCOPY = objcopy
ODUMP = objdump
ASM = as
LINKER = ld
RLIB = ranlib
ARCHIVE = ar
PRECOMP = cpp
NAMES = nm

SANITIZER_ENABLED=\
	-fsanitize=address\
	-fsanitize-address-use-after-scope\
	-fsanitize=alignment\
	-fsanitize=bool\
	-fsanitize=bounds\
	-fsanitize=enum\
	-fsanitize=object-size\
	-fsanitize=pointer-overflow\
	-fsanitize=returns-nonnull-attribute\
	-fsanitize=shift\
	-fsanitize=undefined\
	-fsanitize=unreachable\
	-fsanitize=signed-integer-overflow\
	-fsanitize=vla-bound\

GCC_WARNINGS =\
	-Waddress\
	-Warray-bounds\
	-Wbool-compare\
	-Wcast-align\
	-Wchar-subscripts\
	-Wclobbered\
	-Wcomment\
	-Wempty-body\
	-Wformat\
	-Wimplicit\
	-Wimplicit-int\
	-Wincompatible-pointer-types\
	-Wlogical-op\
	-Wold-style-declaration\
	-Wold-style-definition\
	-Woverlength-strings\
	-Wreturn-type\
	-Wsequence-point\
	-Wsign-compare\
	-Wsizeof-array-argument\
	-Wsizeof-pointer-memaccess\
	-Wstrict-aliasing\
	-Wstrict-overflow\
	-Wstrict-prototypes\
	-Wswitch\
	-Wtrigraphs\
	-Wundef\
	-Wuninitialized\
	-Wunused-function\
	-Wunused-label\
	-Wunused-value\
	-Wunused-variable\
	-Wvla\

ARCHIVE_FLAGS = -U

TOOL_LDLIBS =\
	$(PROFILE_LDLIBS)\

TOOL_CFLAGS =\
	$(SANITIZER_$(SANITIZER))\
	$(PROFILE_CFLAGS)\
	$(GCC_WARNINGS)\
	-MD\

TOOL_LDFLAGS=\
	$(SANITIZER_$(SANITIZER))\
	$(PROFILE_LDFLAGS)\

-include $(SCRIPTDIR)/build/tool/$(COVERAGE).mk
-include $(obj-y:.o=.d)
