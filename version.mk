# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

VERSION = 1.48.4
COMMIT_HASH = $(shell git describe --always --abbrev=0 --dirty --match "NOT A TAG")

define VERSION_BODY
#define AGENT_VERSION "$(VERSION)"
#define AGENT_COMMIT_HASH "$(COMMIT_HASH)"
endef
export VERSION_BODY

version_h ?= ./version.h

$(version_h): FORCE
	mkdir -p $(dir $@); echo "$$VERSION_BODY" > $@

FORCE:
.PHONY: FORCE
