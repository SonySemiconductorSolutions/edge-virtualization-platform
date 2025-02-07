/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

/*
 * SDKRPC_MAX_xxx_SIZE: the max values for record_hdr::size of
 * the corresponding type.
 *
 * They are arbitrary limits to avoid the needs to allocate too big
 * receive buffers. The assumption here is that they are big enough to
 * serve the functionalities. That is, it isn't intended to impose
 * extra limitations.
 */

#define SDKRPC_MAX_REQUEST_SIZE  131072
#define SDKRPC_MAX_RESPONSE_SIZE 131072

struct record_hdr {
	uint32_t size; /* The size of the record, not including record_hdr */
	uint32_t zero; /* Always 0 */
	uint64_t xid;  /* Unique ID of the request. The server copies it in the
			  corresponding response. */
};
