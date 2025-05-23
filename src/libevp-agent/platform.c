/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <evp/agent.h>

#include "blob_http.h"
#include "fsutil.h"
#include "internal/util.h"
#include "path.h"
#include "platform.h"
#include "xlog.h"

#include "hash.h"

static struct evp_agent_platform g_platform;

int
plat_register(const struct evp_agent_platform *p)
{
	/* Both these functions should be set (or not set) */
	if ((p->secure_malloc && !p->secure_free) ||
	    (!p->secure_malloc && p->secure_free))
		return EFAULT;

	g_platform = *p;
	return 0;
}

void *
plat_wasm_mem_read(void *handle, void *to, size_t siz, const void *from)
{
	if (g_platform.wasm_mem_read)
		return g_platform.wasm_mem_read(handle, to, siz, from);
	return memcpy(to, from, siz);
}

void *
plat_wasm_mem_write(void *handle, const void *from, size_t siz, void *to)
{
	if (g_platform.wasm_mem_write)
		return g_platform.wasm_mem_write(handle, from, siz, to);
	return memcpy(to, from, siz);
}

void *
plat_wasm_stack_mem_alloc(size_t size)
{
	if (g_platform.wasm_stack_mem_alloc)
		return g_platform.wasm_stack_mem_alloc(size);
	return malloc(size);
}

void
plat_wasm_stack_mem_free(void *ptr)
{
	if (g_platform.wasm_stack_mem_free)
		return g_platform.wasm_stack_mem_free(ptr);
	free(ptr);
}

void
plat_xlog(int lvl, const char *file, int line, const char *fmt, va_list ap)
{
	if (g_platform.dlog) {
		g_platform.dlog(lvl, file, line, fmt, ap, g_platform.user);
		return;
	}

	xlog(lvl, file, line, fmt, ap);
}

size_t
plat_wasm_strlen(void *handle, const char *s)
{
	if (g_platform.wasm_strlen)
		return g_platform.wasm_strlen(handle, s);
	return strlen(s);
}

struct mod_fs_mmap_handle {
	void *addr;
	size_t size;
};

struct mod_fs_mmap_handle *
plat_mod_fs_file_mmap(struct module *module, const void **data, size_t *size,
		      bool exec, int *error)
{
	if (g_platform.mod_fs_file_mmap)
		return g_platform.mod_fs_file_mmap(module, data, size, exec,
						   error);

	int fd = -1;
	void *addr = MAP_FAILED;
	struct mod_fs_mmap_handle *ret = NULL;
	char *filename = path_get_module(evp_agent_module_get_id(module));

	if (filename == NULL) {
		*error = errno;
		xlog_error("module_path failed: %d", errno);
		goto failure;
	}

	fd = open(filename, O_RDWR);
	if (fd == -1) {
#if defined(__NuttX__)
		/* Workaround for NuttX-sim */
		if (errno == EBADF)
			errno = ENOENT;
#endif
		*error = errno;
		xlog_error("%s: error on open %s: %d", __func__, filename,
			   errno);
		goto failure;
	}

	struct stat sb;
	if (fstat(fd, &sb) == -1) {
		*error = errno;
		xlog_error("%s: error on stat: %d", __func__, *error);
		goto failure;
	}

	addr = mmap(NULL, sb.st_size,
		    PROT_READ | (exec ? PROT_WRITE | PROT_EXEC : 0),
		    MAP_PRIVATE, fd, 0);

	if (addr == MAP_FAILED) {
		*error = errno;
		xlog_error("%s: error on mmap: %d", __func__, errno);
		goto failure;
	}

	struct mod_fs_mmap_handle *handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		*error = errno;
		xlog_error("%s: error on malloc: %d", __func__, *error);
		goto failure;
	}

	*handle =
		(struct mod_fs_mmap_handle){.addr = addr, .size = sb.st_size};

	*data = addr;
	*size = sb.st_size;
	ret = handle;
	goto end;

failure:
	if (addr != MAP_FAILED && munmap(addr, sb.st_size) < 0) {
		*error = errno;
		xlog_error("%s: error on munmap: %d", __func__, errno);
	}

end:
	if (fd >= 0 && close(fd) != 0) {
		*error = errno;
		xlog_error("%s: error on close: %d", __func__, errno);
	}

	free(filename);
	return ret;
}

int
plat_mod_fs_file_munmap(struct mod_fs_mmap_handle *handle)
{
	if (g_platform.mod_fs_file_munmap)
		return g_platform.mod_fs_file_munmap(handle);

	if (!handle)
		return 0;

	int rv = munmap(handle->addr, handle->size);
	if (rv) {
		xlog_error("munmap failed: %d", errno);
	}

	free(handle);
	return rv;
}

int
plat_mod_fs_sink(unsigned http_status, char **buffer, int offset, int datend,
		 int *buflen, void *arg)
{
	if (g_platform.mod_fs_sink)
		return g_platform.mod_fs_sink(http_status, buffer, offset,
					      datend, buflen, arg);

	int ret = -1, fd = -1;
	char *filename = NULL;
	struct module *m = arg;

	if (http_status / 100 != 2) {
		ret = 0;
		goto end;
	}

	if (m == NULL) {
		xlog_error("unexpected null struct module instance");
		goto end;
	}

	if (datend < offset) {
		xlog_error("datend=%d < offset=%d", datend, offset);
		goto end;
	}

	filename = path_get_module(evp_agent_module_get_id(m));
	if (filename == NULL) {
		xlog_error("module_path failed");
		goto end;
	}

	fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0700);
	if (fd == -1) {
		xlog_error("%s: error on open %s: %d", __func__, filename,
			   errno);
		goto end;
	}

	size_t len = datend - offset;
	ssize_t n = write(fd, *buffer + offset, len);
	if (n < 0) {
		xlog_error("%s: error on write %s: %d", __func__, filename,
			   errno);
		evp_agent_module_set_failure_msg(m,
						 "Error when saving module");
		goto end;
	}

	ret = 0;

end:
	if (fd >= 0 && close(fd)) {
		xlog_error("close %s failed with %d", filename, errno);
	}

	free(filename);
	return ret;
}

int
plat_mod_fs_download_finished(struct module *module, struct blob_work *wk)
{
	if (g_platform.mod_fs_download_finished)
		return g_platform.mod_fs_download_finished(module, wk);

	xlog_info("platform download complete for %s",
		  evp_agent_module_get_id(module));
	return 0;
}

int
plat_mod_fs_file_unlink(struct module *module)
{
	if (g_platform.mod_fs_file_unlink)
		return g_platform.mod_fs_file_unlink(module);

	xlog_info("platform unlink called for %s",
		  evp_agent_module_get_id(module));

	char *path = path_get_module(evp_agent_module_get_id(module));
	if (path == NULL) {
		xlog_error("module_path failed");
		return -1;
	}

	int ret = unlink(path);
	if (ret) {
		xlog_error("unlink %s failed with %d", path, errno);
	}

	free(path);
	return ret;
}

static int
copy_file(struct module *module, const char *source)
{
	int ret = -1, fd_input = -1, fd_output = -1;
	char *dest = NULL;

	if ((fd_input = open(source, O_RDONLY)) == -1) {
		xlog_error("open %s failed with %d", source, errno);
		goto end;
	}

	dest = path_get_module(evp_agent_module_get_id(module));
	if (dest == NULL) {
		xlog_error("module_path failed");
		goto end;
	}

	fd_output = creat(dest, 0700);
	if (fd_output == -1) {
		xlog_error("creat %s failed with %d", dest, errno);
		goto end;
	}

	char buffer[BUFSIZ];
	ssize_t n;
	while ((n = read(fd_input, buffer, sizeof(buffer))) > 0) {
		if (write(fd_output, buffer, n) != n) {
			xlog_error("write failed with %d", errno);
			goto end;
		}
	}

	ret = 0;

end:
	if (fd_input >= 0 && close(fd_input)) {
		xlog_error("close fd_input failed with %d", errno);
	}

	if (fd_output >= 0 && close(fd_output)) {
		xlog_error("close fd_output failed with %d", errno);
	}

	free(dest);
	return ret;
}

int
plat_mod_fs_handle_custom_protocol(struct module *module,
				   const char *downloadUrl)
{
	if (g_platform.mod_fs_handle_custom_protocol)
		return g_platform.mod_fs_handle_custom_protocol(module,
								downloadUrl);

	if (!strncmp(downloadUrl, "file://", 7)) {
		return copy_file(module, downloadUrl + 7);
	}

	xlog_error("unsupported URL %s", downloadUrl);
	return -1;
}

void
plat_mod_fs_init(void)
{
	if (g_platform.mod_fs_init) {
		g_platform.mod_fs_init();
		return;
	}

	int ret;
	const char *module_dir = path_get(MODULE_PATH_ID);
	ret = mkdir(module_dir, 0700);
	if (ret != 0 && errno != EEXIST)
		/* Abort assessment:
		 * This is likely a FS error. The file should exist and should
		 * be removed. A FS error should not cause program to exit, but
		 * this is likely to be a non reliable device state and
		 * aborting should not be an issue.
		 */
		// TODO: Review exit (xerr) (runtime error)
		//       Prefer xlog_abort[if]
		xerr(1, "Failed to create MODULE_DIR %s", module_dir);
}

void
plat_mod_fs_prune(void)
{
	if (g_platform.mod_fs_prune) {
		g_platform.mod_fs_prune();
		return;
	}

	/*
	 * remove unused files under MODULE_DIR
	 *
	 * with the current implementation, we can even remove all modules.
	 * however, we keep loaded modules below. it can be useful
	 * eg. in case we support offline operation
	 */

	int ret;
	const char *module_dir = path_get(MODULE_PATH_ID);
	DIR *dir = opendir(module_dir);

	if (dir == NULL) {
		xlog_abort("opendir(3): %d (%s)", errno, strerror(errno));
	}
	struct dirent *d;

	/*
	 * cppcheck doesn't follow xlog_abort well and doesnt detects
	 * the exit inside xlog_abort
	 */
	// cppcheck-suppress nullPointerRedundantCheck
	while ((d = readdir(dir)) != NULL) {
		if (!strcmp(d->d_name, "..") || !strcmp(d->d_name, ".")) {
			continue;
		}
		// Get module name from module package dir identified with
		// suffix `.d`
		char *name = strdup(d->d_name);
		size_t l = strlen(name);
		if (name[l - 2] == '.' && name[l - 1] == 'd') {
			name[l - 2] = '\0';
		}
		ret = evp_agent_module_is_in_use(name);
		free(name);
		if (ret) {
			xlog_trace("module_impl_prune: keeping %s", d->d_name);
			continue;
		}
		xlog_info("module_impl_prune: removing unused %s", d->d_name);

		char *path;
		xasprintf(&path, "%s/%s", module_dir, d->d_name);
		if (d->d_type == DT_DIR) {
			rmtree(path);
		} else {
			ret = unlink(path);
		}
		free(path);
		if (ret == -1) {
			/* Abort assessment
			 * This is likely a FS error. The file should exist and
			 * should be removed. A FS error should not cause
			 * program to exit, but this is likely to be a non
			 * reliable device state and aborting should not be an
			 * issue.
			 */
			// TODO: Review exit (xerr) (runtime error)
			//       Prefer xlog_abort[if]
			xerr(1, "unlink");
		}
	}
	ret = closedir(dir);
	if (ret != 0) {
		xlog_abort("closedir(2): %d (%s)", errno, strerror(errno));
	};
}

void
plat_out_of_memory(const char *file, int line, const char *where, size_t siz)
{
	if (g_platform.out_of_memory)
		g_platform.out_of_memory(file, line, where, siz);
	fprintf(stderr, "evp_agent: %s:%d: %s: out of memory requesting %zu\n",
		file, line, where, siz);
	abort();
}

void *
plat_secure_malloc(size_t size)
{
	if (g_platform.secure_malloc && g_platform.secure_free)
		return g_platform.secure_malloc(size);

	return malloc(size);
}

void
plat_secure_free(void *ptr)
{
	if (g_platform.secure_malloc && g_platform.secure_free) {
		g_platform.secure_free(ptr);
		return;
	}
	free(ptr);
}

char *
plat_mod_mem_mng_strdup(const char *ptr)
{
	if (g_platform.mod_mem_mng_strdup) {
		return g_platform.mod_mem_mng_strdup(ptr);
	}
	return strdup(ptr);
}

int
plat_mod_check_hash(struct module *module, const unsigned char *ref,
		    size_t ref_len, char **result)
{
	if (g_platform.mod_check_hash) {
		return g_platform.mod_check_hash(module, ref, ref_len, result);
	}
	return check_hash(module, ref, ref_len, result);
}
