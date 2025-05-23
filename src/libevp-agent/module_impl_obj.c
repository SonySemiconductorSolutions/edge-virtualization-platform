/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This is a parital implementaion of module_impl_ops.
 *
 * Intended to be used by module impls which are based on
 * on a single downloadable file.
 */

#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/util.h>

#include "blob.h"
#include "cdefs.h"
#include "evp/agent.h"
#include "manifest.h"
#include "module.h"
#include "module_impl.h"
#include "module_impl_ops.h"
#include "platform.h"
#include "xlog.h"

bool
module_impl_obj_downloading(const struct module *m)
{
	return m->blob_work != NULL;
}

int
module_impl_obj_download_cancel(struct module *m)
{
	if (m->blob_work != NULL) {
		int ret = blob_work_cancel(m->blob_work);
		if (ret != 0) {
			return ret;
		}

		blob_work_free(m->blob_work);
		m->blob_work = NULL;
	}
	return 0;
}

int
module_impl_obj_load(struct module *m, const struct Module *modspec)
{
	int ret;
	if (m->blob_work != NULL) {
		struct blob_work *wk = m->blob_work;
		if (wk->wk.status != WORK_STATUS_DONE &&
		    wk->wk.status != WORK_STATUS_CANCELLED) {
			/* download has not started yet */
			/* TODO: stop calling this function repeatedly while
			 * waiting for the download to start */
			/* xlog_debug("download has not started yet"); */
			return EAGAIN;
		}

		if ((wk->wk.status == WORK_STATUS_DONE &&
		     wk->result != BLOB_RESULT_SUCCESS) ||
		    wk->wk.status == WORK_STATUS_CANCELLED) {
			if (evp_agent_module_set_failure_msg(
				    m, "Download failed HTTP Response = %u",
				    wk->http_status)) {
				xlog_error("evp_agent_module_set_failure_msg "
					   "failed");
			}

			/* download failed or cancelled*/
			plat_mod_fs_download_finished(m, wk);
			blob_work_free(wk);

			m->blob_work = NULL;
			return EIO;
		}
		/* Download succedded */
		ret = plat_mod_fs_download_finished(m, wk);
		blob_work_free(wk);
		m->blob_work = NULL;
	}

	char *result = NULL;
	ret = plat_mod_check_hash(m, modspec->hash, modspec->hashLen, &result);

	if (ret == 0) {
		if (result == NULL) {
			xlog_info("module_load: hash correct.");
		} else {
			xlog_warning("module_load: hash did not match.");
			xpthread_mutex_lock(m->failureMessageMutex);
			free(m->failureMessage);
			m->failureMessage = result;
			xpthread_mutex_unlock(m->failureMessageMutex);

			/*
			 * Remove the module with an unexpected hash.
			 * There's little point to keep it.
			 * This might or might not fix the problem
			 * by re-fetching the module.
			 */
			plat_mod_fs_file_unlink(m);
			return EINVAL;
		}
	} else if (ret != ENOENT) {
		/* some IO error in check_hash */
		return ret;
	}

	int error = m->ops->load_obj(m, m->moduleId);
	if (error == ENOENT) {
		/* file was not found. need to download it */
		if (strncmp(modspec->downloadUrl, "http://", 7) &&
		    strncmp(modspec->downloadUrl, "https://", 8)) {
			if (plat_mod_fs_handle_custom_protocol(
				    m, modspec->downloadUrl)) {
				return EINVAL;
			}
		} else {
			struct blob_work *wk = blob_work_alloc();
			if (wk == NULL) {
				return errno;
			}
			m->blob_work = wk;
			wk->type = BLOB_TYPE_AZURE_BLOB;
			wk->op = BLOB_OP_GET;
			wk->url = xstrdup(modspec->downloadUrl);
			wk->webclient_sink_callback = plat_mod_fs_sink;
			wk->webclient_sink_callback_arg = (void *)m;
			blob_work_set_proxy(wk);
			blob_work_enqueue(wk);
			return EAGAIN;
		}
	} else if (error != 0) {
		xlog_error("Failed to load module with error %d", error);
		/*
		 * Don't overwrite the message from
		 * ops->module_load_obj if any.
		 */
		if (m->failureMessage == NULL) {
			xasprintf(&m->failureMessage,
				  "Failed to load (error=%d)", error);
		}
		/*
		 * While the hash of the module file was correct,
		 * we couldn't load it for some reasons.
		 */
		return EINVAL;
	}
	evp_agent_module_clear_failure_msg(m);
	return 0;
}

void
module_impl_obj_init(void *param)
{
	plat_mod_fs_init();
}

void
module_impl_obj_prune(void)
{
	plat_mod_fs_prune();
}

void
module_impl_obj_destroy(void)
{
}
