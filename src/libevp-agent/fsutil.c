/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/stat.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <internal/util.h>

#include "fsutil.h"

#if defined(__NuttX__)
#include "nuttx/version.h"
#endif

#if defined(__NuttX__) && CONFIG_VERSION_MAJOR < 12
#define O_DIRECTORY 0
#endif

/*
 * NOTE: NuttX didn't have ftw/nftw/fts etc until ftw/nftw was
 * implemented recently. https://github.com/apache/nuttx/pull/1486
 */
/* NOTE: NuttX has d_type */

int
rmtree(const char *name)
{
	DIR *dir;
	int ret;

	dir = opendir(name);
	if (dir == NULL) {
		return -1;
	}
	while (true) {
		struct dirent *d = readdir(dir);
		unsigned int dtype;
		char *dname;

		if (d == NULL) {
			break;
		}
		if (!strcmp(d->d_name, "..") || !strcmp(d->d_name, ".")) {
			continue;
		}
		dtype = d->d_type;
		xasprintf(&dname, "%s/%s", name, d->d_name);
		if (dtype == DT_UNKNOWN) {
			struct stat st;

			ret = stat(dname, &st);
			if (ret == -1) {
				/* Abort assessment:
				 * This is strangely aborting if a FS call to
				 * stat or unlink fails and does not give
				 * rmtree caller to decide if aborting or not
				 * in case of FS error. This should not abort.
				 */
				// TODO: Review exit (xerr)
				//       Preferable to use xlog_error[if]
				xerr(1, "stat on %s", dname);
			}
			if ((st.st_mode & S_IFMT) == S_IFDIR) {
				dtype = DT_DIR;
			}
		}
		if (dtype == DT_DIR) {
			/* XXX naive implementation */
			ret = rmtree(dname);
		} else {
			ret = unlink(dname);
		}
		if (ret == -1) {
			/* Abort assessment:
			 * This is strangely aborting if a FS call to stat or
			 * unlink fails and does not give rmtree caller to
			 * decide if aborting or not in case of FS error. This
			 * should not abort.
			 */
			// TODO: Review exit (xerr)
			//       Preferable to use xlog_error[if]
			xerr(1, "rmdir/unlink on %s", dname);
		}
		free(dname);
	}
	ret = closedir(dir);
	if (ret == 0) {
		ret = rmdir(name);
	} else {
		xwarnx("Error closing dir %s.", name);
	}
	return ret;
}

/*
 * careful_open: a slightly "secure" version of open()
 *
 * Resolve the given path by looking up component names one-by-one,
 * ensuring that:
 *   - no symbolic links are involved.
 *   - no ".." components are involved.
 */

/* Nuttx may not have support O_NOFOLLOW  and openat() */
#if defined(__NuttX__) &&                                                     \
	!(CONFIG_VERSION_MAJOR >= 12 && CONFIG_VERSION_MINOR >= 1)
int
careful_open(const char *path, int oflags, int *fdp)
{
	mode_t mode = 0666;

	/*
	 * a fallback implementation
	 *
	 * - NuttX v11.0 doesn't have openat.
	 */
	int fd = open(path, oflags, mode);
	if (fd == -1) {
		return errno;
	}
	*fdp = fd;
	return 0;
}

#else /* defined(__NuttX__) && !(CONFIG_VERSION_MAJOR >= 12 &&                \
	 CONFIG_VERSION_MINOR >= 1) */

int
careful_open(const char *path, int oflags, int *fdp)
{
	// TODO: Replace assert (programming error)
	assert(path != NULL);
	mode_t mode = 0666;
	if (path[0] == 0) {
		return ENOTSUP;
	}

	/* Detect if relative path */
	const char *first = "/";
	if (path[0] != '/') {
		first = ".";
	}
	int dirfd = open(first, O_RDONLY | O_DIRECTORY);
	if (dirfd == -1) {
		return errno;
	}
	const char *p = path;
	int fd;
	while (true) {
		char name[NAME_MAX];
		size_t name_len;
		const char *sep = strchr(p, '/');
		bool last = (sep == NULL);
		if (last) {
			name_len = strlen(p);
		} else {
			name_len = sep - p;
		}
		if (name_len == 0) {
			if (last) {
				/*
				 * a path ending with a slash.
				 * reject for now.
				 * XXX iirc, such a path is posixly-valid
				 * XXX either fix or document
				 */
				close(dirfd);
				return EINVAL;
			}
			/* skip slashes */
			p++;
			continue;
		}
		if (name_len + 1 > sizeof(name)) {
			close(dirfd);
			return ENAMETOOLONG;
		}
		memcpy(name, p, name_len);
		name[name_len] = 0;
		if (!strcmp(name, "..")) { /* XXX a bit loose */
			close(dirfd);
			/* XXX either fix or document */
			return EPERM;
		}
		if (last) {
			/*
			 * Note: O_NONBLOCK below is to avoid blocking on a
			 * FIFO.
			 *
			 * - SUSv4 2018 says:
			 * "it is unspecified whether the file status flags
			 * will include the O_NONBLOCK flag"
			 *
			 * - Even if it's included in the file flag, it should
			 * not have ill effects on regular files. (Unless the
			 * caller uses fancy things like lockf().)
			 */
			fd = openat(dirfd, name,
				    oflags | O_NOFOLLOW | O_NONBLOCK, mode);
		} else {
			int dir_oflags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW;
			fd = openat(dirfd, name, dir_oflags);
		}
		close(dirfd);
		if (fd == -1) {
			int error = errno;
			return error;
		}
		if (last) {
			/* ensure that it's a regular file */
			struct stat st;
			int ret = fstat(fd, &st);
			if (ret == -1) {
				int error = errno;
				close(fd);
				return error;
			}
			if (!S_ISREG(st.st_mode)) {
				close(fd);
				return EPERM;
			}
			break;
		}
		dirfd = fd;
		p += name_len;
	}
	*fdp = fd;
	return 0;
}
#endif

void *
read_file(const char *path, size_t *sizep, bool add_nul)
{
	struct stat st;
	void *p = NULL;
	size_t size;
	ssize_t ssz;
	int fd;
	int ret;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
#if defined(__NuttX__) && defined(CONFIG_SIM_HOSTFS)
		/*
		 * Note: NuttX hostfs as of writing this doesn't translate
		 * errno well. Assume ENOENT.
		 */
		if (errno == EBADF) {
			errno = ENOENT;
		}
#endif
		return NULL;
	}
	ret = fstat(fd, &st);
	if (ret == -1) {
		goto bail;
	}
	size = st.st_size;
	p = malloc(size + add_nul);
	if (p == NULL) {
		goto bail;
	}
	if (add_nul) {
		((char *)p)[size] = 0;
	}
	ssz = read(fd, p, size);
	if (ssz < 0 || (size_t)ssz != size) {
		int error;
		if (ssz == -1) {
			error = errno;
		} else {
			error = EIO;
		}
		free(p);
		errno = error;
		p = NULL;
		goto bail;
	}
	*sizep = size;
bail:
	close(fd);
	return p;
}

/*
 * sync_parent_dir: sync the parent directory of the file
 *
 * Note: fsync() should flush anything necessary to open the file
 * after an ungraceful shutdown. It includes the directory entry
 * in the parent directory. So, it's usually redundant to call
 * this function after fsync on the file.
 * However, in the real world, there are a lot of OSes and filesystems
 * without proper implementation of fsync. It often makes sense to
 * do this just in case.
 */

int
sync_parent_dir(const char *filename)
{
#if defined(__NuttX__)
	/*
	 * What to do for NuttX?
	 *
	 * - NuttX doesn't have sync(2).
	 *
	 * - open+fsync doesn't work for NuttX.
	 *
	 *   - NuttX has opendir as a syscall. It doesn't seem to be
	 *     expected to open(2) a directory.
	 *
	 *   - NuttX's littlefs integration maps open(2) to lfs_file_open,
	 *     which seems to reject directories.
	 *
	 *   - https://github.com/apache/nuttx/pull/5224
	 *
	 * - For filesystems where directory operations are synchronous,
	 *   This no-op implementation is just ok.
	 *   littlefs falls into this category.
	 */
	return 0;
#else
	char *dir_name;
	char *slash;
	int fd;
	int ret;
	int saved_errno;

	/*
	 * something similar to:
	 *
	 * fd = open(dirname(filename));
	 */
	dir_name = xstrdup(filename);
	slash = strrchr(dir_name, '/');
	// TODO: Replace assert (programming error)
	assert(slash != NULL);
	*slash = 0;
	fd = open(dir_name, O_RDONLY);
	if (fd < 0) {
		goto bail;
	}
	ret = fsync(fd);
	if (ret != 0) {
		goto bail;
	}
	free(dir_name);
	return close(fd);

bail:
	saved_errno = errno;
	free(dir_name);
	if (fd >= 0) {
		close(fd);
	}
	errno = saved_errno;
	return -1;
#endif
}
