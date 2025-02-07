# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROFILE_CFLAGS  = --coverage -Og
PROFILE_LDLIBS  = --coverage

coverage: FORCE
	rm -rf coverage
	mkdir -p coverage
	lcov -c -d . --rc lcov_branch_coverage=1 -o coverage/cov.info
	genhtml --branch-coverage -o coverage coverage/cov.info

