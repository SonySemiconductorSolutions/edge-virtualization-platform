/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if !defined(__SDK_BASE_H__)
#define __SDK_BASE_H__

#if defined(__cplusplus)
extern "C" {
#endif

#include <stddef.h>

/** @file */

#if defined(DOXYGEN)
/**
 * An opaque structure to represent an EVP client.
 *
 * This client is used by EVP module instances to communicate with
 * the EVP agent running locally on the same device.
 *
 * An EVP module instance can obtain the pointer to the client
 * by calling @ref EVP_initialize.
 *
 * The majority of SDK API functions take a pointer to this structure.
 */
struct EVP_client {};
#else
struct EVP_client;
#endif

/* @cond internals
 * By intentionally leaving this doxygen section "internals" out of the
 * ENABLED_SECTIONS listing in the Doxyfile, these typedefs are left out
 * of the documentation autogen.
 * */

#if !defined(__has_extension)
#define __has_extension(a) 0
#endif

/*
 * C++ static_assert is available since C++11.
 * (C++17 made the second argument optional.)
 *
 * _Static_assert was introduced by C11.
 *
 * According to https://gcc.gnu.org/wiki/C11Status,
 * _Static_assert is available since gcc 4.6
 */

#if defined(__cplusplus) && __cplusplus >= 201103L
#define EVP_CTASSERT(a) static_assert(a, #a)
#elif __STDC_VERSION__ >= 201112L ||                                          \
	__GNUC__ * 0x100 + __GNUC_MINOR__ >= 0x406 ||                         \
	__has_extension(c_static_assert)
#define EVP_CTASSERT(a) _Static_assert(a, #a)
#else
#define EVP_CTASSERT(a) /* nothing */
#warning Using a no-op EVP_CTASSERT
#endif

/* @endcond */

/**
 * @brief The type to represent either a success or an error.
 * Used as the return value of several of the functions in this SDK.
 */
typedef enum {
	/**
	 * At least one event has been processed.
	 */
	EVP_OK = 0,

	/**
	 * The module instance is requested to stop.
	 * It should exit performing cleanup as soon as possible.
	 */
	EVP_SHOULDEXIT = 1,

	/**
	 * The specified period has elapsed without any events.
	 */
	EVP_TIMEDOUT = 2,

	/**
	 * An error ocurred.
	 */
	EVP_ERROR = 3,

	/**
	 * Invalid parameter.
	 */
	EVP_INVAL = 4,

	/**
	 * Memory allocation failed.
	 */
	EVP_NOMEM = 5,

	/**
	 * Too big payload.
	 */
	EVP_TOOBIG = 6,

	/**
	 * Failure because of temporary conditions.
	 */
	EVP_AGAIN = 7,

	/**
	 * Protocol error when communicating with the agent.
	 */
	EVP_AGENT_PROTOCOL_ERROR = 8,

	/**
	 * The request failed bacause of conflicting existing entries.
	 */
	EVP_EXIST = 9,

	/**
	 * Invalid address was detected.
	 *
	 * Note: An application should not rely on such a detection.
	 * It's the responsibility of applications to always specify
	 * vaild addresses.
	 */
	EVP_FAULT = 10,

	/**
	 * A request was denied. It could mean the agent cannot be
	 * transmitting due to a full queue.
	 */
	EVP_DENIED = 11,

	/**
	 * The request is still not supported by the implementation.
	 */
	EVP_NOTSUP = 12,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_RESULT_dummy = 0x3fffffff,
#endif
} EVP_RESULT;

EVP_CTASSERT(sizeof(EVP_RESULT) == sizeof(int));

/**
 * @brief The type to represent the reason of the callback invocation.
 */
typedef enum {
	/**
	 * The State has been received by the next hop entity.
	 * (Typically the agent within the device. It will try its best to
	 * deliver the State to the Cloud reliably.)
	 *
	 * Note that this doesn't mean the State has reached to the Cloud.
	 */
	EVP_STATE_CALLBACK_REASON_SENT = 0,

	/**
	 * The State has been overwritten by another EVP_sendState call with
	 * the same topic. Note that the SDK only cares the latest State for
	 * a topic.
	 */
	EVP_STATE_CALLBACK_REASON_OVERWRITTEN = 1,

	/**
	 * The State has been cancelled because the module instance is going
	 * to exit. This gives the module instance a chance to cleanup the
	 * associated resources before exiting.
	 * Users must not send any more requests to the agent when this code is
	 * received, and instead users must call @ref EVP_processEvent until
	 * all events are flushed.
	 */
	EVP_STATE_CALLBACK_REASON_EXIT = 2,

	/**
	 * A request was denied for transmission. This means the agent could
	 * not enqueue the request due to a full queue.
	 */
	EVP_STATE_CALLBACK_REASON_DENIED = 3,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_STATE_CALLBACK_REASON_dummy = 0x3fffffff,
#endif
} EVP_STATE_CALLBACK_REASON;

EVP_CTASSERT(sizeof(EVP_STATE_CALLBACK_REASON) == sizeof(int));

/**
 * @brief The type to represent the reason of the callback invocation.
 */
typedef enum {
	/**
	 * The message has been received by the next hop entity.
	 * (Typically the agent within the device. It will try its best to
	 * deliver the message to the Cloud reliably.)
	 * Note that this doesn't mean the message has reached to the Cloud.
	 */

	EVP_MESSAGE_SENT_CALLBACK_REASON_SENT = 0,

	/**
	 * The message has not been processed because it is invalid.
	 * For example, the topic is not defined and cannot be forwarded.
	 */
	EVP_MESSAGE_SENT_CALLBACK_REASON_ERROR = 1,

	/**
	 * The message has been cancelled because the module instance is
	 * going to exit. This gives the module instance a chance to cleanup
	 * the associated resources before exiting.
	 * Users must not send any more requests to the agent when this code is
	 * received, and instead users must call \ref EVP_processEvent until
	 * all events are flushed.
	 */
	EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT = 2,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_MESSAGE_SENT_CALLBACK_REASON_dummy = 0x3fffffff,
#endif
} EVP_MESSAGE_SENT_CALLBACK_REASON;

EVP_CTASSERT(sizeof(EVP_MESSAGE_SENT_CALLBACK_REASON) == sizeof(int));

/**
 * @brief The type to represent the reason of the callback invocation.
 */
typedef enum {
	/**
	 * The telemetry data has been received by the next hop entity.
	 * (Typically the agent within the device. It will try to deliver it
	 * to the Cloud.)
	 *
	 * Note that this doesn't mean the data has reached to the Cloud.
	 */
	EVP_TELEMETRY_CALLBACK_REASON_SENT = 0,
	/**
	 * The telemetry data has not been processed because it is invalid.
	 * For example, it was not a valid JSON.
	 */
	EVP_TELEMETRY_CALLBACK_REASON_ERROR = 1,
	/**
	 * The telemetry data has been cancelled because the module instance is
	 * going to exit. This gives the module instance a chance to cleanup
	 * the associated resources before exiting.
	 * Users must not send any more requests to the agent when this code is
	 * received, and instead users must call \ref EVP_processEvent until
	 * all events are flushed.
	 */
	EVP_TELEMETRY_CALLBACK_REASON_EXIT = 2,

	/**
	 * A request was denied for transmission. This means the agent could
	 * not enqueue the request due to a full queue.
	 */
	EVP_TELEMETRY_CALLBACK_REASON_DENIED = 3,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_TELEMETRY_CALLBACK_REASON_dummy = 0x3fffffff,
#endif
} EVP_TELEMETRY_CALLBACK_REASON;

EVP_CTASSERT(sizeof(EVP_TELEMETRY_CALLBACK_REASON) == sizeof(int));

/**
 * @brief The type to represent the reason of the callback invocation.
 */
typedef enum {
	/**
	 * The RPC response has been received by the next hop entity.
	 * (Typically the agent within the device. It will try to deliver it
	 * to the Cloud.)
	 *
	 * Note that this doesn't mean the data has reached to the Cloud.
	 */
	EVP_RPC_RESPONSE_CALLBACK_REASON_SENT = 0,
	/**
	 * The RPC response has not been processed because of an error.
	 */
	EVP_RPC_RESPONSE_CALLBACK_REASON_ERROR = 1,
	/**
	 * The RPC response has been cancelled because the module instance is
	 * going to exit. This gives the module instance a chance to cleanup
	 * the associated resources before exiting.
	 * Users must not send any more requests to the agent when this code is
	 * received, and instead users must call \ref EVP_processEvent until
	 * all events are flushed.
	 */
	EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT = 2,
	/**
	 * A request was denied for transmission. This means the agent could
	 * not enqueue the request due to a full queue.
	 */
	EVP_RPC_RESPONSE_CALLBACK_REASON_DENIED = 3,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_RPC_RESPONSE_CALLBACK_REASON_dummy = 0x3fffffff,
#endif
} EVP_RPC_RESPONSE_CALLBACK_REASON;

EVP_CTASSERT(sizeof(EVP_RPC_RESPONSE_CALLBACK_REASON) == sizeof(int));

/**
 * @brief The type to specify a status condition for a RPC response
 * 	      to the Hub.
 */
typedef enum {
	/**
	 * The RPC request executed successfully and the response
	 * contains the results of the execution.
	 */
	EVP_RPC_RESPONSE_STATUS_OK = 0,

	/**
	 * The originating RPC request specified a method that is not
	 * implemented, so it is reported back as not found.
	 */
	EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND = 1,

	/**
	 * The RPC request executed with error and the response
	 * contains the error message
	 */
	EVP_RPC_RESPONSE_STATUS_ERROR = 2,

	/**
	 * Used internally to verify correctness of status codes
	 * received from the module
	 */
	_EVP_RPC_RESPONSE_STATUS_MAX,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_RPC_RESPONSE_STATUS_REASON_dummy = 0x3fffffff,
#endif
} EVP_RPC_RESPONSE_STATUS;

EVP_CTASSERT(sizeof(EVP_RPC_RESPONSE_STATUS) == sizeof(int));

/**
 * @brief The type to represent a workspace type.
 */
typedef enum {
	/**
	 * Default type of Workspace.
	 */
	EVP_WORKSPACE_TYPE_DEFAULT = 0,

#if !defined(DOXYGEN)
	/**
	 * A placeholder to ensure the enum size.
	 */
	_EVP_WORKSPACE_TYPE_dummy = 0x3fffffff,
#endif
} EVP_WORKSPACE_TYPE;

EVP_CTASSERT(sizeof(EVP_WORKSPACE_TYPE) == sizeof(int));

/**
 *  Function prototype for the callback passed to the function
 *  @ref EVP_setConfigurationCallback.
 *
 *  @param topic        Destination topic.
 *  @param config       The buffer to pass as configuration.
 *  @param configlen    The size of the configuration data for sending.
 *  @param userData     An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_CONFIGURATION_CALLBACK)(const char *topic,
					   const void *config,
					   size_t configlen, void *userData);

/**
 * Function prototype for the callback passed to State message-dealing
 * functions such as @ref EVP_sendState.
 *
 *  @param reason       The cause code for executing the callback.
 *  @param userData     An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_STATE_CALLBACK)(EVP_STATE_CALLBACK_REASON reason,
				   void *userData);

/**
 *  Function prototype for the callback passed to generic message-dealing
 *  functions such as @ref EVP_sendMessage.
 *
 *  @param reason       The cause code for executing the callback.
 *  @param userData     An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_MESSAGE_SENT_CALLBACK)(
	EVP_MESSAGE_SENT_CALLBACK_REASON reason, void *userData);

/**
 *  Function prototype for the callback passed to the function
 *  @ref EVP_setMessageCallback.  Executed when a message is received
 *  on the configured ``topic``.
 *
 *  @param topic            Destination topic.
 *  @param msgPayload       The buffer to pass as configuration.
 *  @param msgPayloadLen    The size of the configuration data for sending.
 *  @param userData         An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_MESSAGE_RECEIVED_CALLBACK)(const char *topic,
					      const void *msgPayload,
					      size_t msgPayloadLen,
					      void *userData);

/**
 * Function prototype for the callback passed to @ref EVP_sendTelemetry.
 *
 *  @param reason       The cause code for executing the callback.
 *  @param userData     An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_TELEMETRY_CALLBACK)(EVP_TELEMETRY_CALLBACK_REASON reason,
				       void *userData);

/**
 * Function prototype for the callback passed to @ref EVP_setRpcCallback.
 *
 *  @param id            The request Id for @ref EVP_sendRpcResponse.
 *  @param methodName    The name of method.
 *  @param params        The call parameters. A string representation of
 *                       a JSON value.
 */
typedef void (*EVP_RPC_REQUEST_CALLBACK)(EVP_RPC_ID id, const char *methodName,
					 const char *params, void *userData);

/**
 *  Function prototype for the callback passed to @ref EVP_sendRpcResponse.
 *
 *  @param reason       The cause code for executing the callback.
 *  @param userData     An arbitrary blob of data to pass to the callback.
 */
typedef void (*EVP_RPC_RESPONSE_CALLBACK)(
	EVP_RPC_RESPONSE_CALLBACK_REASON reason, void *userData);

/** @brief Initialize the SDK.
 *
 * Performs the required initialization operations for the module instance.
 *
 * This should be called by the main thread of the module instance.
 * Otherwise, the behaviour is undefined.
 *
 * This should not be called more than once for a module instance.
 * Otherwise, the behaviour is undefined.
 *
 * @returns `struct EVP_client *` for the calling module instance.
 */
struct EVP_client *EVP_initialize(void);

/** @brief Returns the absolute path of the workspace directory
 *         for the calling Module Instance.
 *
 * The workspace directory with the default type (@ref
 * EVP_WORKSPACE_TYPE_DEFAULT) has the following characteristics:
 *
 *  - Initially, the workspace directory is empty.
 *
 *  - The workspace directory is left intact across a reboot of the Module
 *    Instace and/or the device. It can contain the contents left by the
 *    Module Instance before a reboot.
 *
 *  - The Module Instance has an exclusive access to its workspace directory
 *    during its lifetime.
 *
 *  - The Module Instance can access the workspace directory directly, using
 *    the OS interfaces like `open()` and `mkdir()`.
 *
 *  - The Module Instance can request file operations on the workspace
 *    directory via the SDK. For example, upload from/download to a file
 *    on the workspace directory.
 *
 *  - The Module Instance should only use regular files and directories on
 *    the workspace directory. If it attempts to create other file types,
 *    the behavior is undefined.
 *
 *  - The agent will remove files in the workspace directory after
 *    the corresponding Module Instance has gone away. That is, at some point
 *    after a successful deployment of a new Deployment which doesn't contain
 *    the Module Instance anymore.
 *
 * @param h    struct EVP_client *
 * @param type @ref EVP_WORKSPACE_TYPE_DEFAULT
 *
 * @return The absolute path to the workspace directory.
 */
const char *EVP_getWorkspaceDirectory(struct EVP_client *h,
				      EVP_WORKSPACE_TYPE type);

/** @brief Register a callback function for Configuration.
 *
 * This should not be called more than once for a struct EVP_client *.
 * Otherwise, the behaviour is undefined.
 *
 * The callback `cb` will be called in the context of this function or of
 * @ref EVP_processEvent.
 *
 * The callback will be called on the following events at least:
 *
 *  - When the callback function is registered.
 *  - When the SDK received the latest Configuration.
 *
 * The SDK might coalesce multiple events into one.
 * In that case, the callback will be called with the latest Configuration.
 *
 * The SDK might choose to invoke this callback more frequently than
 * necessary. The callback function should not assume that the given
 * Configuration was updated.
 *
 * All pointers given to the callback, including topic and
 * Configuration, are only valid until the callback function
 * returns. The callback function should make a copy if necessary.
 *
 * @param h         struct EVP_client *.
 * @param cb        The callback function.
 * @param userData  The SDK passes this value to the callback as it is.
 *                  The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_setConfigurationCallback(struct EVP_client *h,
					EVP_CONFIGURATION_CALLBACK cb,
					void *userData);

/** @brief Schedule to send the specified State for the specified topic.
 *
 * The callback `cb` will be called in the context of this function or of
 * @ref EVP_processEvent, when the request has been sent or cancelled.
 * It will be invoked with one of the reasons defined by
 * @ref EVP_STATE_CALLBACK_REASON.
 *
 * It's the caller's responsibility to keep the specified `topic` and `state`
 * valid until the callback is called. Otherwise, the behaviour is undefined.
 * (The SDK implementation might choose to keep pointers of them without
 * making copies.)
 *
 * @param h         struct EVP_client *.
 * @param topic     Destination topic.
 * @param state     State data.
 * @param statelen  State size in bytes.
 * @param cb        The callback function.
 * @param userData  The SDK passes this value to the callback as it is.
 *                  The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_sendState(struct EVP_client *h, const char *topic,
			 const void *state, size_t statelen,
			 EVP_STATE_CALLBACK cb, void *userData);

/** @brief Schedule to send the specified message.
 *
 * The callback will be called in the context of this function or of
 * EVP_processEvent(), when the request has been sent or cancelled.
 * It will be invoked with one of the reasons defined by
 * @ref EVP_MESSAGE_SENT_CALLBACK_REASON.
 *
 * It's the caller's responsibility to keep the specified topic and State
 * valid until the callback is called.
 * Otherwise, the behaviour is undefined.
 * (The SDK implementation might choose to keep pointers of them without
 * making copies.)
 *
 * @param h         struct EVP_client *.
 * @param topic     Destination topic.
 * @param state     State data.
 * @param statelen  State size in bytes.
 * @param cb        The callback function.
 * @param userData  The SDK passes this value to the callback as it is.
 *                  The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_sendMessage(struct EVP_client *h, const char *topic,
			   const void *state, size_t statelen,
			   EVP_MESSAGE_SENT_CALLBACK cb, void *userData);

/**
 * @brief Describe a telemetry data
 *
 * A Key-Value pair to be sent as a telemetry.
 * Both of the key and value should be a valid UTF-8 string.
 * The value should be a string representation of a valid JSON value.
 */
struct EVP_telemetry_entry {
	const char *key;   /**< A key */
	const char *value; /**< A JSON value */
};

/** @brief Schedule to send the telemetry.
 *
 * The callback will be called in the context of this function or of
 * EVP_processEvent(), when the request has been sent or cancelled.
 * It will be invoked with one of the reasons defined by
 * @ref EVP_TELEMETRY_CALLBACK_REASON.
 *
 * It's the caller's responsibility to keep the specified entries and
 * data referenced by them valid until the callback is called.
 * Otherwise, the behaviour is undefined.
 * (The SDK implementation might choose to keep pointers of them without
 * making copies.)
 *
 * @param h         struct EVP_client *.
 * @param entries   The array of the telemetry data.
 * @param nentries  The size of the array.
 * @param cb        The callback function.
 * @param userData  The SDK passes this value to the callback as it is.
 *                  The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT
EVP_sendTelemetry(struct EVP_client *h,
		  const struct EVP_telemetry_entry *entries, size_t nentries,
		  EVP_TELEMETRY_CALLBACK cb, void *userData);

/** @brief Wait for an event and process it.
 *
 * This function is intended to be called in the main loop of
 * the module instance.
 * It waits for an event (e.g. Configuration update) and process it.
 * It processes one pending event per call.
 *
 * @param h            struct EVP_client *.
 *
 * @param timeout_ms   Timeout in milliseconds:
 *                      0 means immediate.
 *                      -1 means forever.
 *
 * @returns @ref EVP_OK          When at least one event has been processed.
 * @returns @ref EVP_TIMEDOUT    When the period specified by `timeout_ms`
 *                               has elapsed without any events.
 * @returns @ref EVP_SHOULDEXIT  When the module instance is requested to stop
 *                               and all events have been already dispatched.
 *                               It should exit performing cleanup as soon as
 *                               possible.
 *
 * @see @ref EVP_STATE_CALLBACK_REASON_EXIT
 * @see @ref EVP_MESSAGE_SENT_CALLBACK_REASON_EXIT
 * @see @ref EVP_TELEMETRY_CALLBACK_REASON_EXIT
 * @see @ref EVP_RPC_RESPONSE_CALLBACK_REASON_EXIT
 * @see @ref EVP_BLOB_CALLBACK_REASON_EXIT
 */
EVP_RESULT EVP_processEvent(struct EVP_client *h, int timeout_ms);

/** @brief Specifies a callback to invoke on every incoming message.
 *
 * This should not be called more than once for a struct EVP_client *.
 * Otherwise, the behaviour is undefined.
 *
 * The callback will be called in the context of EVP_processEvent,
 * upon reception of a message on any of the subscribed topics.
 *
 * Messages which have been arrived before a successful call of this
 * function might or might not be delivered to the specified callback.
 *
 * @param h             struct EVP_client *.
 * @param incoming_cb   The callback function.
 * @param userData      The SDK passes this value to the callback as it is.
 *                      The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_setMessageCallback(struct EVP_client *h,
				  EVP_MESSAGE_RECEIVED_CALLBACK incoming_cb,
				  void *userData);

/** @brief Specifies a callback to invoke on every incoming RPC call.
 *
 * This should not be called more than once for a struct EVP_client *.
 * Otherwise, the behaviour is undefined.
 *
 * The callback will be called in the context of EVP_processEvent,
 * upon reception of a RPC request.
 *
 * RPC calls which have been arrived before a successful call of this
 * function might or might not be delivered to the specified callback.
 *
 * For each invocation of the specified callback,
 * @ref EVP_sendRpcResponse should be called exactly once with
 * the ID given by the callback and struct EVP_client * specified to
 * this function.
 * It's the caller's responsibility to ensure that.
 * Otherwise, the behaviour is undefined.
 *
 * @param h             struct EVP_client *.
 * @param cb            The callback function.
 * @param userData      The SDK passes this value to the callback as it is.
 *                      The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK Success.
 */
EVP_RESULT EVP_setRpcCallback(struct EVP_client *h,
			      EVP_RPC_REQUEST_CALLBACK cb, void *userData);

/** @brief Schedule to send the specified RPC response.
 *
 * This function can be used within the context of
 * @ref EVP_RPC_REQUEST_CALLBACK.
 *
 * The callback will be called in the context of this function or of
 * EVP_processEvent(), when the request has been sent or cancelled.
 * It will be invoked with one of the reasons defined by
 * @ref EVP_RPC_RESPONSE_CALLBACK_REASON.
 *
 * For implementing named methods, the SDK provides a method-not-found
 * response by setting the status flag to
 * @ref EVP_RPC_RESPONSE_STATUS_METHOD_NOT_FOUND. In that case, the
 * value of 'response' will be ignored.
 *
 * See the entire set  * of values of the @ref EVP_RPC_RESPONSE_STATUS
 * enum for values to use in other situations.
 *
 * It's the caller's responsibility to keep the specified parameters
 * valid until the callback is called. Otherwise, the behavior is
 * undefined (The SDK implementation might choose to keep pointers
 * of them without making copies).
 *
 * @param h         struct EVP_client *.
 * @param id        The request ID from @ref EVP_RPC_REQUEST_CALLBACK,
 *                  to which you want to reply.
 * @param response  The response. It should be a string representation of
 *                  a valid JSON value.
 * @param status    A value from the @ref EVP_RPC_RESPONSE_STATUS enum.
 * @param cb        The callback function.
 * @param userData  The SDK passes this value to the callback as it is.
 *                  The SDK doesn't care if it's a valid pointer.
 *
 * @return @ref EVP_OK in case of success.
 * @return @ref EVP_TOOBIG when the payload is larger than the agent
 *         can handle (i.e. due to device constraints).
 * @return @ref EVP_INVAL if the response is NULL.
 */
EVP_RESULT EVP_sendRpcResponse(struct EVP_client *h, EVP_RPC_ID id,
			       const char *response,
			       EVP_RPC_RESPONSE_STATUS status,
			       EVP_RPC_RESPONSE_CALLBACK cb, void *userData);

/**
 * @brief The type used to represent a stream.
 */
typedef int EVP_STREAM;

/**
 * @brief The type used to represent a peer identifier.
 */
typedef unsigned long EVP_STREAM_PEER_ID;

/**
 * @brief The callback type used to represent a read-available stream
 * operation.
 *
 * @param id		Peer identifier. Whereas this remains as an
 * 					opaque type, applications can rely on
 * different identifiers meaning different connections to a given stream.
 * @param buf		Buffer containing the input data.
 * @param n			Buffer length.
 * @param userData	An opaque pointer to user-defined data, as defined
 * by @ref EVP_streamInputOpen .
 */
typedef void (*EVP_STREAM_READ_CALLBACK)(EVP_STREAM_PEER_ID id,
					 const void *buf, size_t n,
					 void *userData);

/**
 * @brief Opens an output stream.
 *
 * Streams allow for device-to-device and module-to-module
 * communication, using an interface somewhat similar to BSD sockets.
 * However, the actual implementation depends on which stream type has
 * been selected from the deployment manifest.
 *
 * @param h 			struct EVP_client *.
 * @param name 			Null-terminated string with the stream name.
 * 						This must match the name of one
 * of the streams defined on the deployment manifest.
 * @param[out] stream	On success, it shall be assigned to a
 * 						non-negative integer.
 * Otherwise, it shall be assigned to a negative integer.
 *
 * @return 	@ref EVP_OK Success.
 * 			@ref EVP_INVAL if the stream was not defined by the
 * 			deployment manifest or the stream was not defined for
 * output.
 * 			@ref EVP_EXIST if a stream with the same @ref name has
 * 			already been opened.
 * 			@ref EVP_NOMEM if memory could not be allocated.
 * 			@ref EVP_ERROR if an unexpected error occurred.
 */
EVP_RESULT EVP_streamOutputOpen(struct EVP_client *h, const char *name,
				EVP_STREAM *stream);

/**
 * @brief Opens an input stream.
 *
 * Streams allow for device-to-device and module-to-module
 * communication, using an interface somewhat similar to BSD sockets.
 * However, the actual implementation depends on which stream type has
 * been selected from the deployment manifest.
 *
 * @param h 			struct EVP_client *.
 * @param name 			Null-terminated string with the stream name.
 * 						This must match the name of one
 * of the streams defined on the deployment manifest.
 * @param cb			Callback that shall be executed when input data
 * 						becomes available.
 * @param userData		Opaque pointer to user-defined data that shall
 * 						be passed to @ref cb .
 * @param[out] stream	On success, it shall be asssigned to a
 * 						non-negative integer.
 * Otherwise, it shall be assigned to a negative integer.
 *
 * @return 	@ref EVP_OK Success.
 * 			@ref EVP_INVAL if the stream was not defined by the
 * 			deployment manifest or the stream was not defined for
 * input.
 * 			@ref EVP_EXIST if a stream with the same @ref name has
 * 			already been opened.
 * 			@ref EVP_NOMEM if memory could not be allocated.
 * 			@ref EVP_ERROR if an unexpected error occurred.
 */
EVP_RESULT EVP_streamInputOpen(struct EVP_client *h, const char *name,
			       EVP_STREAM_READ_CALLBACK cb, void *userData,
			       EVP_STREAM *stream);

/**
 * @brief Closes a stream previously opened with @ref EVP_streamOpen.
 *
 * @param h			struct EVP_client *.
 * @param stream	Stream identifier.
 *
 * @return 	@ref EVP_OK Success.
 * 			@ref EVP_INVAL if the stream was not defined by the
 * 			deployment manifest.
 * 			@ref EVP_ERROR if an unexpected error occurred.
 */
EVP_RESULT EVP_streamClose(struct EVP_client *h, EVP_STREAM stream);

/**
 * @brief Sends a buffer over a stream previously opened with
 * @ref EVP_streamOpen.
 *
 * @param h			struct EVP_client *.
 * @param stream	Stream identifier.
 * @param buf		Buffer to send.
 * @param n			Buffer length.
 *
 * @return 	@ref EVP_OK Success.
 * 			@ref EVP_INVAL if the stream was not defined by the
 * 			deployment manifest or was not configured for output.
 * 			@ref EVP_ERROR if an unexpected error occurred.
 */
EVP_RESULT EVP_streamWrite(struct EVP_client *h, EVP_STREAM stream,
			   const void *buf, size_t n);

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* !defined(__SDK_BASE_H__) */
