/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CONTAINER_SPEC_H
#define CONTAINER_SPEC_H

#include <parson.h>

#include "manifest.h"

/* Define our own return value for flagging errors */
#define ECONTSPEC 2001

/**
 * @brief
 * Parses a raw container spec from the incoming instance spec JSON object,
 * if it finds the relevant field(s).
 * \param [inout] spec the module instance being assembled.
 * \param [in] obj JSON value containing the instance spec JSON object
 * \param [inout] failureMessage string that will be written in case an
 * error validating or parsing the raw container specification happens.
 * \return Zero on success. Otherwise, an errno value is returned.
 */
int container_spec_extra_parse_evp1(struct ModuleInstanceSpec *spec,
				    const JSON_Object *obj,
				    char **failureMessage);
int container_spec_extra_parse_evp2(struct ModuleInstanceSpec *spec,
				    const JSON_Object *obj,
				    char **failureMessage);

/**
 * @brief
 * Injects module instance bind mount string into an existing JSON object.
 *
 * This function takes a JSON object with the following format:
 *
 * \code
 * {
 * "HostConfig": {
 * 	"Binds": [
 * 		...
 * 	]
 * 	},
 * }
 * \endcode
 *
 * And injects a JSON string inside the "Binds" JSON array, with the following
 * format:
 *
 * <module-instance-dir>:EVP_SHARED_DIR
 *
 * \param [inout] v JSON value containing the JSON object above.
 * \param [out] error Human-readable error string. Must be freed by the caller,
 * so callers must not assume it will always be initialized by the function
 * to a null pointer.
 * \param name Module instance name.
 * \param host_src Path to host module instance directory.
 * \return Zero on success. Otherwise, an errno value is returned.
 */
int container_spec_extra_assign_mounts(JSON_Value *v, char **error,
				       const char *name, const char *host_src);

#endif /* CONTAINER_SPEC_H */
