/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <nuttx/compiler.h>
#include <nuttx/symtab.h>

#include <sys/stat.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <internal/util.h>

#include "cdefs.h"
#include "evp/sdk.h"

#define SYM(sym) {(FAR const char *)#sym, (FAR const void *)sym}

/* Note: the prototype is not important for our purpose. */
#define EXTERN_CXXSYM(sym) void sym(void);
#define CXXSYM(sym)        {(FAR const char *)#sym, (FAR const void *)sym}

/*
 * We use mangled C++ symbols directly here.
 *
 * It's an evil hack. However, only alternative I can think of is
 * to compile a C++ source and extract symbols from the object,
 * using tools like nm(1). It isn't neat or portable either.
 *
 * Revisit: automate a bit if the list of symbols is growing.
 */

EXTERN_CXXSYM(_ZdlPv);  /* operator delete(void*) */
EXTERN_CXXSYM(_ZdaPv);  /* operator delete[](void*) */
EXTERN_CXXSYM(_Znwm);   /* operator new(unsigned long) */
EXTERN_CXXSYM(_Znam);   /* operator new[](unsigned long) */
EXTERN_CXXSYM(_Znwj);   /* operator new(unsigned int) */
EXTERN_CXXSYM(_Znaj);   /* operator new[](unsigned int) */
EXTERN_CXXSYM(_ZdlPvm); /* operator delete(void*, unsigned long) */
EXTERN_CXXSYM(_ZdaPvm); /* operator delete[](void*, unsigned long) */

/*
 * Symbols provided to modules.
 */

static const struct symtab_s g_exports[] = {
	/*
	 * EVP SDK symbols
	 */
	SYM(EVP_blobOperation),
	SYM(EVP_getWorkspaceDirectory),
	SYM(EVP_initialize),
	SYM(EVP_processEvent),
	SYM(EVP_sendMessage),
	SYM(EVP_sendRpcResponse),
	SYM(EVP_sendState),
	SYM(EVP_sendTelemetry),
	SYM(EVP_setConfigurationCallback),
	SYM(EVP_setMessageCallback),
	SYM(EVP_setRpcCallback),

	/*
	 * Random "standard" symbols from the OS
	 *
	 * XXX todo: define the right set of functions
	 *
	 * XXX todo: consider to generate somehow automatically.
	 *     cf. MKSYMTAB in NuttX
	 *
	 * XXX todo: or, allow dlsymtab() to use multiple symtabs so that
	 *     we can use both of our symtab and the system one.
	 */
	SYM(__errno),
	SYM(asprintf),
	SYM(atoi),
	SYM(clock_gettime),
	SYM(fabs),
	SYM(free),
	SYM(isspace),
	SYM(localtime),
	SYM(malloc),
	SYM(memcpy),
	SYM(memmove),
	SYM(memset),
	SYM(printf),
	SYM(rand),
	SYM(realloc),
	SYM(sleep),
	SYM(snprintf),
	SYM(sprintf),
	SYM(srand),
	SYM(strchr),
	SYM(strcmp),
	SYM(strdup),
	SYM(strlen),
	SYM(strncmp),
	SYM(strndup),
	SYM(strstr),
	SYM(strtod),
	SYM(time),
#if defined(__NuttX__)
	/* _assert is required by nuttx's assert(3) implementation. */
	SYM(_assert),
#endif

	/*
	 * OS filesystem interfaces
	 */

	SYM(close),
	SYM(fstat),
	SYM(fsync),
	SYM(ftruncate),
	SYM(lseek),
	SYM(open),
	SYM(read),
	SYM(rename),
	SYM(stat),
	SYM(truncate),
	SYM(unlink),
	SYM(write),

	/* directory */

	SYM(chdir),
	SYM(getcwd),
	SYM(mkdir),
	SYM(rmdir),

	/* DIR */

	SYM(closedir),
	SYM(opendir),
	SYM(readdir),
	SYM(rewinddir),
	SYM(seekdir),
	SYM(telldir),

	/* FILE */

	SYM(fclose),
	SYM(feof),
	SYM(ferror),
	SYM(fflush),
	SYM(fopen),
	SYM(fputs),
	SYM(fread),
	SYM(fseek),
	SYM(ftell),
	SYM(fwrite),
	SYM(rewind),

#if defined(CONFIG_HAVE_CXX)
	/* C++ stuff */
	/* operator delete(void*) */
	CXXSYM(_ZdlPv),
	/* operator delete[](void*) */
	CXXSYM(_ZdaPv),
#if defined(CONFIG_ARCH_SIZET_LONG)
	/* operator new(unsigned long) */
	CXXSYM(_Znwm),
	/* operator new[](unsigned long) */
	CXXSYM(_Znam),
/* XXX notyet C++14 */
#if 0
	/* operator delete(void*, unsigned long) */
	CXXSYM(_ZdlPvm),
	/* operator delete[](void*, unsigned long) */
	CXXSYM(_ZdaPvm),
#endif /* C++14 */
#else  /* defined(CONFIG_ARCH_SIZET_LONG) */
	/* operator new(unsigned int) */
	CXXSYM(_Znwj),
	/* operator new[](unsigned int) */
	CXXSYM(_Znaj),
#endif /* defined(CONFIG_ARCH_SIZET_LONG) */
#endif /* defined(CONFIG_HAVE_CXX) */
};

void
module_api_init_dlfcn(void)
{
	int rc = dlsymtab(g_exports, __arraycount(g_exports));
	if (rc != OK) {
		/* Abort assessment:
		 * This should not return something else than OK.
		 * This is an assertion and can result in aborting.
		 */
		// TODO: Review exit (programming error)
		//       Prefer xlog_abort[if]
		xerrx(1, "dlsymtab returned %d", rc);
	}
}
