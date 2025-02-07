/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdlib.h>

#include <wasm_export.h>

#include <internal/util.h>

#include "cdefs.h"
#include "config.h"
#include "module_api_wasm.h"
#include "sdk_local_wasm.h"
#include "xlog.h"

#ifdef CONFIG_EVP_MODULE_IMPL_WASM_NATIVE_LIBS
#include <dlfcn.h>
#endif

#define EXPORT_EVP_SDK(a, b)                                                  \
	{                                                                     \
		#a,                                                           \
		a##_wasm,                                                     \
		b,                                                            \
	}

typedef int (*export_fun_t)(char **, NativeSymbol **);

static NativeSymbol wasm_exported_symbols[] = {
	EXPORT_EVP_SDK(EVP_initialize, "()i"),
	EXPORT_EVP_SDK(EVP_getWorkspaceDirectory, "(ii)i"),
	EXPORT_EVP_SDK(EVP_setConfigurationCallback, "(iii)i"),
	EXPORT_EVP_SDK(EVP_sendState, "(i$*~ii)i"),
	EXPORT_EVP_SDK(EVP_setMessageCallback, "(iii)i"),
	EXPORT_EVP_SDK(EVP_setRpcCallback, "(iii)i"),
	EXPORT_EVP_SDK(EVP_blobOperation, "(iiiiiii)i"),
	EXPORT_EVP_SDK(EVP_BlobRequestHttpExt_initialize, "()i"),
	EXPORT_EVP_SDK(EVP_BlobRequestHttpExt_addHeader, "(iii)i"),
	EXPORT_EVP_SDK(EVP_BlobRequestHttpExt_addAzureHeader, "(i)i"),
	EXPORT_EVP_SDK(EVP_BlobRequestHttpExt_setUrl, "(ii)i"),
	EXPORT_EVP_SDK(EVP_BlobRequestHttpExt_free, "(i)"),
	EXPORT_EVP_SDK(EVP_sendMessage, "(i$*~ii)i"),
	EXPORT_EVP_SDK(EVP_sendTelemetry, "(iiiii)i"),
	EXPORT_EVP_SDK(EVP_sendRpcResponse, "(iI$iii)i"),
	EXPORT_EVP_SDK(EVP_processEvent, "(ii)i"),
	EXPORT_EVP_SDK(EVP_streamInputOpen, "(i$iii)i"),
	EXPORT_EVP_SDK(EVP_streamOutputOpen, "(i$i)i"),
	EXPORT_EVP_SDK(EVP_streamClose, "(ii)i"),
	EXPORT_EVP_SDK(EVP_streamWrite, "(ii*~)i")};

static const char **native_libs;
static size_t nr_native_libs;

/*
 * This is a temporary solution to provide an interface that
 * allows to register native symbols in a way that the platform
 * can override the default behaviour. This solution is using a
 * weak definition but a better solution should restructure the
 * code to provide a good interface to allow the platform
 * to provide a hook to get the symbols for any module
 * implementation.
 */
#pragma weak get_native_lib

int
get_native_lib(char **namep, NativeSymbol **symbolsp)
{
	return 0;
}

void
wasm_add_native_lib(const char *fname)
{
	size_t siz;

	nr_native_libs++;
	siz = nr_native_libs * sizeof(*native_libs);
	native_libs = xrealloc(native_libs, siz);
	native_libs[nr_native_libs - 1] = fname;
}

static export_fun_t
load_native_lib(const char *fname)
{
#ifdef CONFIG_EVP_MODULE_IMPL_WASM_NATIVE_LIBS
	void *hdl;
	export_fun_t fun;

	xlog_info("loading dynamic library '%s'", fname);

	hdl = dlopen(fname, RTLD_NOW);
	if (!hdl) {
		// Exit (xlog_abort): library error
		xlog_abort("error loading dynamic library '%s:%s'", fname,
			   dlerror());
	}

	fun = dlsym(hdl, "get_native_lib");
	if (!fun) {
		// Exit (xlog_abort): library error
		xlog_abort("wasm dynamic library without get_native_lib");
	}

	return fun;
#else
	return NULL;
#endif
}

static void
register_native_syms(export_fun_t fun)
{
	bool ok;
	char *module_name = NULL;
	NativeSymbol *symbols = NULL;
	int nsymbols = -1;

	nsymbols = (*fun)(&module_name, &symbols);
	if (nsymbols == 0) {
		return;
	}

	if (nsymbols < 0 || !module_name || !symbols) {
		// Exit (xlog_abort): library error
		xlog_abort("get_native_lib interface failed");
	}

	ok = wasm_runtime_register_natives(module_name, symbols, nsymbols);
	if (!ok) {
		// Exit (xlog_abort): wasm runtime error
		xlog_abort("wasm_runtime_register_natives with extended "
			   "symbols failed");
	}
}

void
module_api_init_wasm(void)
{
	size_t i;
	bool ok;

	ok = wasm_runtime_init();
	if (!ok) {
		// Exit (xlog_abort): wasm runtime error
		xlog_abort("wasm_runtime_init failed");
	}

	ok = wasm_runtime_register_natives(
		"env", wasm_exported_symbols,
		__arraycount(wasm_exported_symbols));
	if (!ok) {
		// Exit (xlog_abort): wasm runtime error
		xlog_abort("wasm_runtime_register_natives with basic symbols "
			   "failed");
	}

	register_native_syms(get_native_lib);

	for (i = 0; i < nr_native_libs; i++) {
		export_fun_t fun;

		fun = load_native_lib(native_libs[i]);

		if (fun) {
			register_native_syms(fun);
		}
	}
	free(native_libs);
}
