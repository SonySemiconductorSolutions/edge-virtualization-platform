# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

include $(SCRIPTDIR)/build/tool/gnu.mk

compile_commands.json:
	bear -- $(MAKE)

# To make cppcheck returns an error when defects are found
# it is needed to add --error-exitcode=1

analysis: compile_commands.json FORCE
	trap "cat analysis.txt" EXIT INT TERM QUIT; \
	cppcheck --project=compile_commands.json \
		--suppress=missingIncludeSystem \
		--suppress=readdirCalled \
		--enable=information,portability,warning \
		--library=posix \
		--quiet \
		--template='{file}:{line}:{column}:{severity}:{message} [{id}]'\
		--file-filter=src/libevp-agent/*.c \
		--file-filter=src/libevp-agent/hub/*.c \
		--file-filter=src/libevp-agent/hub/tb/*.c \
		--file-filter=src/libevp-agent/models/*.c \
		--file-filter=src/libevp-agent/mqtt_pal/*.c \
		--file-filter=src/libevp-agent/stream/*.c \
		--file-filter=src/libevp-agent/sdkenc/*.c \
		--file-filter=src/libevp-agent/sdkenc/decode/*.c \
		--file-filter=src/libevp-agent/sdkrpc/*.c \
		--file-filter=src/libevp-app-sdk/sdkrpc/*.c \
		--file-filter=src/libevp-app-sdk/*.c 2> analysis.txt
