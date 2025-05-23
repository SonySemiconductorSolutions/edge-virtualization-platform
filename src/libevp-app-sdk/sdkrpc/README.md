<!--
SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

# sdkrpc

## Overview

This implements a simple record exchange protocol used
by CONFIG_EVP_SDK_SOCKET.

The client is a part of [evpmodulesdk](../evpmodulesdk).

The server is a part of the evp agent, [sdk_worker.c](../sdk_worker.c).

## Protocol

A client and a server talk over a unix domain socket,
by passing records each other.

Usually, the client sends a request record and the server receives it,
and then the server sends a response record and the client receives it,
and the cycle repeats until the client exits.

To avoid a deadlock, it's the responsibility of the client to drain
the receive buffer even when it would be blocked on the send buffer.

Each record is a flatbuffers-encoded binary, prepended by
[struct record_hdr](record_hdr.h).

You can find the flatbuffers schema at [sdk.fbs](../sdkenc/sdk.fbs).
