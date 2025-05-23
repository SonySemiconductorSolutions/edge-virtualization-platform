/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <parson.h>

#include <internal/evp_config.h>
#include <internal/util.h>

#include "base64.h"
#include "container_spec.h"
#include "module_instance.h"
#include "module_instance_impl.h"
#include "path_docker.h"
#include "signature_verification.h"
#include "xlog.h"

int
container_spec_extra_assign_mounts(JSON_Value *v, char **error,
				   const char *name, const char *host_src)
{
	int retcode = -1;
	if (v == NULL) {
		return retcode;
	}

	JSON_Object *o = json_value_get_object(v);
	if (o == NULL) {
		return retcode;
	}

	JSON_Object *host = json_object_get_object(o, "HostConfig");
	if (host == NULL) {
		json_object_set_value(o, "HostConfig",
				      json_value_init_object());
		host = json_object_get_object(o, "HostConfig");
	}

	JSON_Array *binds = json_object_get_array(host, "Binds");
	if (binds == NULL) {
		json_object_set_value(host, "Binds", json_value_init_array());
		binds = json_object_get_array(host, "Binds");
	}
	char *s = NULL;
	xasprintf(&s, "%s:%s", host_src, EVP_SHARED_DIR);

	size_t i, sz;
	sz = json_array_get_count(binds);
	for (i = 0; i < sz; ++i) {
		const char *name = json_array_get_string(binds, i);
		if (!strcmp(s, name)) {
			free(s);
			return 0;
		}
	}

	if (json_array_append_string(binds, s) != JSONSuccess) {
		xasprintf(error,
			  "Failed to append bind '%s' for module "
			  "instance '%s'",
			  s, name);
		xlog_error("%s", *error);
		retcode = ENOMEM;
	} else {
		retcode = 0;
	}
	free(s);
	return retcode;
}

/*
 * This function implements handling of the rawContainerSpec
 * backdoor mechanism for docker module instances.
 */
static int
container_spec_extra_pre_validate(char **failureMessage,
				  const struct ModuleInstanceSpec *spec,
				  const char *rawContainerSpec,
				  const char *rawContainerSpecSignature)
{
	int retcode = 0;

	char *public_key_DER_b64 = config_get_string(
		EVP_CONFIG_RAWCONTAINERSPEC_SIGNVERIF_PUBKEY);
	if (public_key_DER_b64 == NULL) {
		xasprintf(failureMessage,
			  "Public key for verifying signature of "
			  "module instance '%s' is not provided",
			  spec->name);
		return ECONTSPEC;
	}

	int ret;
	mbedtls_pk_context public_key;
	void *signature_ASN = NULL;
	size_t signature_ASN_len;

	mbedtls_pk_init(&public_key);

	ret = parse_public_key_base64_enc(
		public_key_DER_b64, strlen(public_key_DER_b64), &public_key);
	if (ret != 0) {
		xasprintf(failureMessage,
			  "Could not parse public key for verifying "
			  "signature of "
			  "module instance '%s'",
			  spec->name);
		retcode = ECONTSPEC;
		goto exit;
	}

	ret = base64_decode(rawContainerSpecSignature,
			    strlen(rawContainerSpecSignature), &signature_ASN,
			    &signature_ASN_len);
	if (ret != 0) {
		xasprintf(failureMessage,
			  "Could not decode signature for "
			  "module instance '%s'",
			  spec->name);
		retcode = ECONTSPEC;
		goto exit;
	}

	ret = validate_signature(rawContainerSpec, strlen(rawContainerSpec),
				 signature_ASN, signature_ASN_len,
				 &public_key);
	if (ret != 0) {
		xasprintf(failureMessage,
			  "Signature verification of rawContainer "
			  "spec for "
			  "module instance '%s' has failed",
			  spec->name);
		retcode = ECONTSPEC;
		goto exit;
	}
exit:
	free(public_key_DER_b64);
	mbedtls_pk_free(&public_key);
	free(signature_ASN);

	return retcode;
}

static int
container_spec_extra_decode(char **failureMessage,
			    struct ModuleInstanceSpec *spec,
			    const char *rawContainerSpec)
{
	int retcode = 0;
	if (rawContainerSpec != NULL) {
		void *spec_stringified = NULL;
		size_t spec_stringified_len;

		if (base64_decode_append_nul(
			    rawContainerSpec, strlen(rawContainerSpec),
			    &spec_stringified, &spec_stringified_len) != 0) {
			xasprintf(failureMessage,
				  "Could not decode rawContainerSpec for "
				  "module instance '%s'",
				  spec->name);
			retcode = ECONTSPEC;
			goto exit;
		}
		spec->rawContainerSpec = json_parse_string(spec_stringified);
		if (spec->rawContainerSpec == NULL) {
			retcode = ECONTSPEC;
			xasprintf(failureMessage,
				  "failed to parse rawContainerSpec: %.*s",
				  (int)spec_stringified_len,
				  (const char *)spec_stringified);
		}

	exit:
		free(spec_stringified);
	}
	return retcode;
}

int
container_spec_extra_parse_evp1(struct ModuleInstanceSpec *spec,
				const JSON_Object *obj, char **failureMessage)
{
	const JSON_Value *raw_spec =
		json_object_get_value(obj, "rawContainerSpec");

	if (raw_spec != NULL) {
		spec->rawContainerSpec = json_value_deep_copy(raw_spec);
		if (spec->rawContainerSpec == NULL) {
			return ENOMEM;
		}
	}
	return 0;
}

int
container_spec_extra_parse_evp2(struct ModuleInstanceSpec *spec,
				const JSON_Object *obj, char **failureMessage)
{
	const char *raw_spec_sign =
		json_object_get_string(obj, "rawContainerSpecSignature");
	const char *raw_spec = json_object_get_string(obj, "rawContainerSpec");

	if (raw_spec == NULL && raw_spec_sign == NULL) {
		return 0;
	} else if (raw_spec != NULL && raw_spec_sign == NULL) {
		xasprintf(failureMessage,
			  "No raw container spec signature provided for "
			  "module instance '%s'",
			  spec->name);
		return ECONTSPEC;
	} else if (raw_spec == NULL && raw_spec_sign != NULL) {
		xasprintf(
			failureMessage,
			"Signature provided but no actual container spec for "
			"module instance '%s'",
			spec->name);
		return ECONTSPEC;
	} else {
		int ret = container_spec_extra_pre_validate(
			failureMessage, spec, raw_spec, raw_spec_sign);
		if (ret != 0) {
			return ret;
		}
		ret = container_spec_extra_decode(failureMessage, spec,
						  raw_spec);
		return ret;
	}
}
