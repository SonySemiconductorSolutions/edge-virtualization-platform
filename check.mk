# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

BUILDROOT ?= $(CURDIR)
CLANG_FORMAT ?= clang-format
BASHATE ?= bashate

# Exclusion rules
EXCLUDE += include/evp_mbedtls_config.h
EXCLUDE += include/internal/cdefs.h
EXCLUDE += include/internal/time.h
EXCLUDE += include/internal/queue.h
EXCLUDE += src/libparson/parson.h
EXCLUDE += src/libparson/parson.c
EXCLUDE += src/libevp-agent/mqtt.c
EXCLUDE += src/libevp-agent/sdkenc/%.c
EXCLUDE += src/libevp-agent/sdkenc/%.h
EXCLUDE += src/libevp-agent/webclient/%
EXCLUDE += src/libevp-agent/MQTT-C/%
EXCLUDE += src/libevp-agent/netlib/%
EXCLUDE += src/libevp-agent/xlog_color.h

# Get all c and h files in repos
UNFILTERED_FILES = $(shell git ls-files '*.[ch]')
SOURCE_FILES = $(filter-out $(EXCLUDE), $(UNFILTERED_FILES))

# List all files under Sony and Apache license control
# exclude:
# - json
# - txt
# - empty files
# - *.config files
# - binary files
# - Other special files
ALL_FILES = $(shell git ls-files --exclude='*.json' --exclude='*.txt')
JSON_FILES = $(shell git ls-files '*.json')
TEXT_FILES = $(shell git ls-files '*.txt')
CONFIG_FILES = $(shell git ls-files '*.config')
BINARY_FILES = $(shell git ls-files '*.wasm.x86_64')
NOT_LICENSE_SUPPORTED += LICENSE
LICENSED_FILES = $(filter-out $(EXCLUDE) $(JSON_FILES) $(TEXT_FILES) $(CONFIG_FILES) $(BINARY_FILES) $(NOT_LICENSE_SUPPORTED), $(ALL_FILES))

check: check-python check-format check-license check-make check-shell ## check code formatting
.PHONY: check

check-python:
	@echo Checking python formatting
	@$(BUILDROOT)/scripts/checker-python.sh
.PHONY: check-python

check-format: $(SOURCE_FILES)
	@echo Checking C formatting
	@$(CLANG_FORMAT) --dry-run -Werror $^
.PHONY: check-format

fix-format: $(SOURCE_FILES)
	@echo Fixing C formatting
	@$(CLANG_FORMAT) -i $^
.PHONY: fix-format

check-license:
	@echo Checking license header
	@$(BUILDROOT)/tools/check-license.sh $(LICENSED_FILES)
.PHONY: check-license

check-make:
	@echo Checking Makefile formatting
	@$(BUILDROOT)/tools/check-make.sh
.PHONY: check-make

check-shell:
	@echo Checking shell script formatting
	@git ls-files '*.sh' | xargs $(BASHATE) -iE006 -eE005,E042,E043
.PHONY: check-shell

check-docs:
	@echo Checking docs files
	@rstcheck docs/**/*.rst
.PHONY: check-docs
