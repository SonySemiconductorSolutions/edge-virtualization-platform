# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

SYS_CFLAGS = -pthread -DMBEDTLS_USER_CONFIG_FILE="<evp_mbedtls_config.h>"
SYS_LDFLAGS = -pthread
SYS_LDLIBS = -lpthread -lrt -ldl
