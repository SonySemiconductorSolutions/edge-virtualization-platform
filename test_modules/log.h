/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define log_module(myname, fmt, ...)                                          \
	fprintf(stderr, "[%s|%s-%04d] " fmt,                                  \
		myname == NULL ? "NO-NAME" : myname, __FILE__, __LINE__,      \
		##__VA_ARGS__)
