/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include "blob_http.h"

struct evp_agent_platform;
struct mod_fs_mmap_handle;
struct module;

int plat_register(const struct evp_agent_platform *p);
void *plat_wasm_mem_read(void *, void *, size_t, const void *);
void *plat_wasm_mem_write(void *, const void *, size_t, void *);
void *plat_wasm_stack_mem_alloc(size_t);
void plat_wasm_stack_mem_free(void *);
size_t plat_wasm_strlen(void *, const char *);
void plat_xlog(int, const char *, int, const char *, va_list);
struct mod_fs_mmap_handle *plat_mod_fs_file_mmap(struct module *module,
						 const void **data,
						 size_t *size, bool exec,
						 int *error);
int plat_mod_fs_file_munmap(struct mod_fs_mmap_handle *handle);
int plat_mod_fs_sink(unsigned http_status, char **buffer, int offset,
		     int datend, int *buflen, void *arg);
int plat_mod_fs_download_finished(struct module *module, struct blob_work *wk);
int plat_mod_fs_file_unlink(struct module *module);
int plat_mod_fs_handle_custom_protocol(struct module *module,
				       const char *downloadUrl);
void plat_mod_fs_init(void);
void plat_mod_fs_prune(void);
void plat_out_of_memory(const char *, int, const char *, size_t);
void *plat_secure_malloc(size_t size);
void plat_secure_free(void *ptr);
char *plat_mod_mem_mng_strdup(const char *ptr);
int plat_mod_check_hash(struct module *module, const unsigned char *ref,
			size_t ref_len, char **result);
#endif
