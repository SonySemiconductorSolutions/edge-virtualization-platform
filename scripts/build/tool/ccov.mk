# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROFILE_CFLAGS  = -fprofile-instr-generate -fcoverage-mapping -g -Og
PROFILE_LDFLAGS  = -fprofile-instr-generate -fcoverage-mapping -Og

CI_FILTER=\
	src/libevp-utils/*.c\
	src/libevp-agent/*.c\
	src/libevp-agent/models/*.c\
	src/libevp-agent/hub/*.c\
	src/libevp-agent/hub/tb/*.c\

coverage/cov.lcov: FORCE
	@echo [$@]
	trap "rm -f $$$$.tmp" EXIT INT TERM;\
	find . -name '*.profraw' |\
	xargs llvm-profdata merge -o coverage/cov.profdata -sparse
	find . -name '*.elf' |\
	xargs llvm-cov export --instr-profile coverage/cov.profdata --format lcov > $$$$.tmp &&\
	mv $$$$.tmp $@

coverage/filtered.lcov: coverage/cov.lcov
	@echo [$@]
	trap "rm -f $$$$.tmp" EXIT INT TERM;\
	find . -name '*.elf' |\
	xargs llvm-cov export --instr-profile coverage/cov.profdata --format lcov \
	--sources $(CI_FILTER) \
	--object > $$$$.tmp &&\
	mv $$$$.tmp $@

coverage: FORCE
	@echo [$@]
	rm -rf coverage
	mkdir -p coverage
	$(MAKE) coverage/cov.lcov
	genhtml --branch-coverage -o coverage coverage/cov.lcov

coverage-ci: FORCE
	@echo [$@]
	rm -rf coverage
	mkdir -p coverage
	$(MAKE) coverage/filtered.lcov
	genhtml --branch-coverage -o coverage coverage/filtered.lcov
