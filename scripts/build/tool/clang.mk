# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

include $(SCRIPTDIR)/build/tool/gnu.mk

CLANG_WARNINGS=\
	-Wthread-safety\
	-Wno-unknown-warning-option\

SANITIZER_ENABLED=\
	-fsanitize=address\
	-fsanitize-address-use-after-scope\
	-fsanitize=alignment\
	-fsanitize=bool\
	-fsanitize=bounds\
	-fsanitize=enum\
	-fsanitize=integer\
	-fsanitize=implicit-integer-truncation\
	-fsanitize=implicit-integer-arithmetic-value-change\
	-fsanitize=implicit-conversion\
	-fsanitize=object-size\
	-fsanitize=pointer-overflow\
	-fsanitize=returns-nonnull-attribute\
	-fsanitize=shift\
	-fsanitize=undefined\
	-fsanitize=unreachable\
	-fsanitize=vla-bound\

TOOL_ASFLAGS = -c

TOOL_CFLAGS =\
	$(SANITIZER_$(SANITIZER))\
	$(PROFILE_CFLAGS)\
	$(GCC_WARNINGS)\
	$(CLANG_WARNINGS)\
	-MD

TOOL_LDFLAGS=\
	$(SANITIZER_$(SANITIZER))\
	$(PROFILE_LDFLAGS)\

COMP = clang
COMPXX = clang++
ASM = clang
LINKER = ld.lld
OBJCOPY = llvm-objcopy
OBJDUMP = llvm-objdump
