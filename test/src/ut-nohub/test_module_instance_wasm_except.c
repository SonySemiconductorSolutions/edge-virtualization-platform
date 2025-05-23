/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <evp/sdk.h>
#include <parson.h>
#include <wasm_export.h>

#include <internal/util.h>

#include "hub.h"
#include "manifest.h"
#include "module_impl.h"
#include "module_impl_ops.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "module_instance_impl_ops.h"

#define WASM_RUNTIME_EXCEPTION_MESSAGE "The exception"
#define EXCEPTION_MESSAGE                                                     \
	"wasm_application_execute_main "                                      \
	"failed: " WASM_RUNTIME_EXCEPTION_MESSAGE

/*
 * Mocking
 */

/* WASM */

bool
__wrap_wasm_application_execute_main(wasm_module_inst_t *module_inst,
				     int32_t argc, char *argv[])
{
	return false;
}

int
__wrap_evp_agent_notification_publish(struct evp_agent_context *ctxt,
				      const char *event, const void *args)
{
	return 0;
}

const char *
__wrap_wasm_runtime_get_exception(wasm_module_inst_t module_inst)
{
	return WASM_RUNTIME_EXCEPTION_MESSAGE;
}

wasm_module_t
__wrap_wasm_runtime_load(uint8_t *buf, uint32_t size, char *error_buf,
			 uint32_t error_buf_size)
{
	return (wasm_module_t) "FAKE MODULE";
}

wasm_module_inst_t
__wrap_wasm_runtime_instantiate(const wasm_module_t module,
				uint32_t default_stack_size,
				uint32_t host_managed_heap_size,
				char *error_buf, uint32_t error_buf_size)
{
	return (wasm_module_inst_t) "FAKE INSTANCE";
}

void
__wrap_wasm_runtime_set_wasi_args_ex(
	wasm_module_t module, const char *dir_list[], uint32_t dir_count,
	const char *map_dir_list[], uint32_t map_dir_count, const char *env[],
	uint32_t env_count, char *argv[], int argc, int stdinfd, int stdoutfd,
	int stderrfd)
{
}

void
__wrap_wasm_runtime_set_custom_data(wasm_module_inst_t module_inst,
				    void *custom_data)
{
}

/* evp-agent */

void *
__wrap_read_file(const char *path, size_t *sizep, bool add_nul)
{
	char *txt = xstrdup("FAKE WASM");
	*sizep = strlen(txt) + 1;
	return txt;
}

int
__wrap_module_log_cap_open(const char *inst, const char *stream)
{
	return 1;
}

void
__wrap_module_log_cap_close(const char *inst, const char *stream)
{
}

bool
__wrap_module_impl_wasm_loaded(const struct module *m)
{
	return true;
}

struct mod_fs_mmap_handle *
__wrap_plat_mod_fs_file_mmap(struct module *module, const void **data,
			     size_t *size, bool exec, int *error)
{
	*size = 1;
	*data = (const void *)0x1337;
	return (void *)0x1337;
}

int
__wrap_plat_mod_fs_file_munmap(struct mod_fs_mmap_handle *handle)
{
	return 0;
}

static int
setup(void **state)
{
	const struct module_impl_ops *ops =
		module_impl_ops_get_by_name("wasm");

	assert_non_null(ops);

	struct module_instance *instance = malloc(sizeof(*instance));

	assert_non_null(instance);

	*instance = (struct module_instance){
		.name = "FAKE INSTANCE",
		.moduleId = "FAKE MODULE",
		.ops = ops,
	};

	struct ModuleInstanceSpec spec = {};
	struct module module = {
		.moduleId = "FAKE MODULE",
		.ops = ops,
		.is_downloaded = true,
	};
	struct module_instance *m = instance;
	int ret;

	m->sdk_handle = sdk_handle_alloc();

	// Start a fake instance just to engage wasm_runner
	ret = ops->instance->start(m, &spec, ".", &module);
	assert_int_equal(ret, 0);

	*state = instance;
	return 0;
}

static int
teardown(void **state)
{
	struct module_instance *m = *state;

	free(m->failureMessage);
	m->failureMessage = NULL;
	m->ops->instance->stop(m);
	sdk_handle_destroy(m->sdk_handle);
	sdk_handle_free(m->sdk_handle);
	free(m);
	return 0;
}

// Duplicate static function code to access internal module instance status
static enum module_instance_status
module_instance_get_status(struct module_instance *m)
{
	enum module_instance_status status;
	xpthread_mutex_lock(&m->lock);
	status = m->status;
	xpthread_mutex_unlock(&m->lock);
	return status;
}

void
test_instance_runtime_exception(void **state)
{
	struct module_instance *m = *state;

	while (module_instance_get_status(m) !=
	       MODULE_INSTANCE_STATUS_STOPPED) {
		print_message(
			"[   INFO   ] Wait for module instance to stop\n");
		sleep(1);
	}

	const char *stat = m->ops->instance->stat(m);
	assert_non_null(stat);
	assert_string_equal(stat, "self-exiting");
	assert_non_null(m->failureMessage);
	assert_string_equal(m->failureMessage, EXCEPTION_MESSAGE);
}

int
main(void)
{

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(
			test_instance_runtime_exception, setup, teardown),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
