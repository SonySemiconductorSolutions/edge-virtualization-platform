/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EVP_AGENT_H
#define EVP_AGENT_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

enum evp_agent_status {
	EVP_AGENT_STATUS_INIT,       // agent has been created but not started
	EVP_AGENT_STATUS_READY,      // agent is initialised but not connected
	EVP_AGENT_STATUS_CONNECTING, // agent is waiting for CONNACK
	EVP_AGENT_STATUS_CONNECTED,  // agent is connected to hub
	EVP_AGENT_STATUS_DISCONNECTING, // agent is waiting for network
					// operations to finish
	EVP_AGENT_STATUS_DISCONNECTED,  // agent is disconnected from network
	EVP_AGENT_STATUS_STOPPED        // agent has been stopped
};

struct EVP_client;
struct evp_agent_context;
struct module;
struct mod_fs_mmap_handle;
struct blob_work;

struct evp_agent_platform {
	void *user;
	void *(*wasm_mem_read)(void *, void *, size_t, const void *);
	void *(*wasm_mem_write)(void *, const void *, size_t, void *);
	void (*dlog)(int, const char *, int, const char *, va_list, void *);
	void *(*wasm_stack_mem_alloc)(size_t);
	void (*wasm_stack_mem_free)(void *);
	size_t (*wasm_strlen)(void *, const char *s);
	int (*mod_fs_sink)(unsigned http_status, char **buffer, int offset,
			   int datend, int *buflen, void *arg);
	/**
	 * \brief Platform function to map a module file into the memory
	 *
	 * This function should try to load the module pointed to by `module`,
	 * and should return a non-null handle to be passed to
	 * `mod_fs_file_munmap` later. It should set `error` to `ENOENT` in
	 * case the file is not found, and to something else different than
	 * zero if there is some other error.
	 *
	 * Not being able to find the file is fine, as it is going to be
	 * downloaded later. The function may not set the error to 0 in case of
	 * success, this means that we must have *error set to zero before we
	 * call this function.
	 *
	 * \param module Opaque pointer to a module
	 * \param data Output pointer to an output pointer to the memory where
	 * the module has been mapped.
	 * \param size Output pointer to the size of
	 * the mapped file in memory module has been mapped.
	 * \param exec if true, the file should be mapped to Instruction bus or
	 * have executable permissions. If false, memory should be mapped to
	 * Data bus.
	 * \param error Output pointer to an int that represents the error
	 * number. The function must set this error to ENOENT in case the file
	 * is not found, or some other error. The function does not need to set
	 * this to zero in case of success.
	 *
	 * \return Returns a handle that can be passed to mod_fs_file_munmap
	 */
	struct mod_fs_mmap_handle *(*mod_fs_file_mmap)(struct module *module,
						       const void **data,
						       size_t *size, bool exec,
						       int *error);
	/**
	 * \brief Platform function to unmap a module file from the memory
	 *
	 * This function should unload the module loaded in the handle.
	 *
	 * \param handle A handle that was returned by `mod_fs_file_mmap`
	 *
	 * \return Returns zero in case of success or anything in case of
	 * error.
	 */
	int (*mod_fs_file_munmap)(struct mod_fs_mmap_handle *handle);
	/**
	 * \brief Platform function to unlink (delete) a module from storage
	 *
	 * This function should delete the module from local storage.
	 *
	 * \param module Opaque pointer to a module
	 *
	 * \return Returns zero in case of success or anything in case of
	 * error.
	 */
	int (*mod_fs_file_unlink)(struct module *module);
	/**
	 * \brief Callback for download finished
	 *
	 * This function will be called when the download succesfully finished,
	 * cancelled or errored.
	 *
	 * \param module Opaque pointer to a module
	 * \param wk Pointer to the blob worker
	 *
	 * \return Returns zero in case of success or anything in case of
	 * error.
	 */
	int (*mod_fs_download_finished)(struct module *module,
					struct blob_work *wk);
	/**
	 * \brief Custom protocol module downloadUrl handler
	 *
	 * This function is used to handle other protocols than http or https.
	 *
	 * \param module Opaque pointer to a module
	 * \param downloadUrl The URL set in the module.
	 *
	 * \return Returns zero in case of success or anything in case of
	 * error.
	 */
	int (*mod_fs_handle_custom_protocol)(struct module *module,
					     const char *downloadUrl);
	/**
	 * \brief Initialize module storage
	 *
	 * This function will be called when the agent starts, to initialize
	 * the module storage.
	 */
	void (*mod_fs_init)(void);
	/**
	 * \brief Cleanup module storage
	 *
	 * This function is used to delete all unused modules from the storage.
	 */
	void (*mod_fs_prune)(void);
	void (*out_of_memory)(const char *, int, const char *, size_t);

	/**
	 * \brief Secure malloc
	 *
	 * This function should allocate memory in the secure or internal heap.
	 *
	 * It has the same semantics as malloc(3).
	 *
	 * \param size The size in bytes to allocate.
	 *
	 * \return a pointer to the allocated memory or NULL in case of
	 failure.
	 */
	void *(*secure_malloc)(size_t size);

	/**
	 * \brief Secure free
	 *
	 * This function should free allocated memory in the secure or internal
	 * heap.
	 *
	 * It has the same semantics as free(3).
	 *
	 * \param ptr The pointer to the memory to be deallocated.
	 */
	void (*secure_free)(void *ptr);

	char *(*mod_mem_mng_strdup)(const char *);

	int (*mod_check_hash)(struct module *module, const unsigned char *ref,
			      size_t ref_len, char **result);
};

/**
 * Used for the notifaciton event "deployment/reconcileStatus"
 */
struct reconcileStatusNotify {
	const char *deploymentId;
	const char *reconcileStatus;
};

struct evp_agent_notification_wasm_stopped {
	const char *name;
	enum wasm_stopped_status {
		EVP_AGENT_WASM_STOPPED_GRACEFULLY,
		EVP_AGENT_WASM_STOPPED_EXCEPTION,
		EVP_AGENT_WASM_STOPPED_CANCELLED
	} status;
};

struct evp_agent_notification_blob_result {
	int result;
	int error;
	unsigned int http_status;
};

struct evp_agent_notification_stp_error {
	int error;
	const char *error_msg;
};

typedef void (*evp_log_handler_t)(int lvl, const char *file, int line,
				  const char *fmt, va_list ap);

struct evp_agent_context *evp_agent_setup(const char *progname);
int evp_agent_start(struct evp_agent_context *ctxt);
bool evp_agent_ready(struct evp_agent_context *ctxt);
enum evp_agent_status evp_agent_get_status(struct evp_agent_context *ctxt);
int evp_agent_loop(struct evp_agent_context *ctxt);
int evp_agent_stop(struct evp_agent_context *ctxt);
void evp_agent_free(struct evp_agent_context *ctxt);
void evp_agent_wakeup(const char *name);

/**
 * Set the platform methods
 * This method can be called only before `evp_agent_start`
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \param p pointer to platform methods.
 * \return Returns zero on success, non-zero otherwise.
 */
int evp_agent_platform_register(struct evp_agent_context *ctxt,
				const struct evp_agent_platform *p);

/*
 * Send a message to the agent
 */
void evp_agent_send(struct evp_agent_context *ctxt, const char *topic,
		    const char *payload);

/*
 * Connect agent to the network
 */
int evp_agent_connect(struct evp_agent_context *ctxt);

/*
 * Disconnect agent from the network
 */
int evp_agent_disconnect(struct evp_agent_context *ctxt);

/*
 * Create a backdoor instance with the given name
 */
struct EVP_client *evp_agent_add_instance(struct evp_agent_context *ctxt,
					  const char *name);

/*
 * Get a handle to a configured instance
 */
struct EVP_client *evp_agent_get_instance(struct evp_agent_context *ctxt,
					  const char *name);

/*
 * Stop a running instance
 */
int evp_agent_stop_instance(struct evp_agent_context *ctxt, const char *name);

/*
 * Undeploy all modules by replacing the current deployment with an empty one.
 */
int evp_agent_undeploy_all(struct evp_agent_context *ctxt);

/*
 * Checks whether the deployment reconciliation loop has settled on an empty
 * deployment.
 */
int evp_agent_empty_deployment_has_completed(struct evp_agent_context *ctxt);

/**
 * Set logger handler to override default logging handler.
 */
int evp_agent_set_log_handler(evp_log_handler_t handler);

/**
 * Subscribes to an event using a custom callback.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \param event Human-readable string that uniquely identifies the event.
 * It is recommended that event categories are defined similarly to
 * directories i.e., using the forward slash '/' character. For example:
 * \c "event-group/event" .
 * \param cb User-defined callback to attach to a given event. Several
 * callbacks can be attached to a single event by calling this function
 * repeatedly.
 * \param user_data Opaque pointer to user-defined data. The library shall
 * make no attempts to dereference this pointer, and it can be safely
 * assigned to a null pointer.
 * \note This function shall create a deep copy of all of its arguments.
 * \note This function is called under the EVP agent context. In order to
 * ensure the stability of the EVP agent, it is recommended that
 * long-running or blocking user-defined tasks are either avoided or moved
 * to a separate thread.
 * \return Returns zero on success, non-zero otherwise.
 * \warning \c ctxt is currently ignored by this API but it is meant for
 * future use, so please assign it a valid pointer for future compatibility.
 */
int evp_agent_notification_subscribe(
	struct evp_agent_context *ctxt, const char *event,
	int (*cb)(const void *args, void *user_data), void *user_data);

/**
 * Triggers a specific event that will call its associated callbacks.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \param event Human-readable string that uniquely identifies the event.
 * \param args Event-specific arguments. The callback is then responsible
 * to cast this data to the appropriate type.
 * \return Returns zero on success, non-zero otherwise.
 */
int evp_agent_notification_publish(struct evp_agent_context *ctxt,
				   const char *event, const void *args);

/**
 * Returns the moduleId of a module
 *
 * \param module Opaque pointer to a module object.
 * \return Returns the ID of the module.
 */
const char *evp_agent_module_get_id(const struct module *module);

/**
 * Sets the failureMessage of a module
 *
 * \param module Opaque pointer to a module object.
 */
int evp_agent_module_set_failure_msg(struct module *module, const char *fmt,
				     ...);

/**
 * Checks if the module is loaded by the agent (in use)
 *
 * \param moduleId the ID of the module to be checked.
 * \return Returns true if module is loaded by the Agent
 */
bool evp_agent_module_is_in_use(const char *moduleId);

/**
 * Clears the failureMessage of a module
 *
 * \param module Opaque pointer to a module object.
 */
void evp_agent_module_clear_failure_msg(struct module *module);

/*
 * Send config update notification.
 */
int evp_notify_config(const struct evp_agent_context *ctxt,
		      const char *instance, const char *name,
		      const char *value);

/**
 * Pause agent deployment capability.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \returns zero on success
 * \returns EAGAIN if deployment cannot be paused yet due to a running
 * operation.
 * User needs to poll again to check that deployment has been successfully
 * paused to guaranty no deployment is in progress.
 *
 * \note User can subscribe to `deployment/reconcileStatus` to be notified when
 * deployment has been successfully paused.
 */
int evp_agent_request_pause_deployment(struct evp_agent_context *ctxt);

/**
 * Resume agent deployment capability.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \returns zero
 */
int evp_agent_resume_deployment(struct evp_agent_context *ctxt);

/**
 * Register a new system app.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \returns Opaque pointer to internal sysapp-related data if successful,
 * null pointer otherwise.
 */
struct SYS_client *
evp_agent_register_sys_client(struct evp_agent_context *ctxt);

/**
 * Unregister an existing system app.
 *
 * \param ctxt Opaque pointer to internal agent-related data.
 * \param c Opaque pointer to internal sysapp-related data.
 * \returns Zero when successful, non-zero otherwise.
 */
int evp_agent_unregister_sys_client(struct evp_agent_context *ctxt,
				    struct SYS_client *c);

#endif
