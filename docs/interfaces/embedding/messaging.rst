.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:function:: int evp_agent_send(struct evp_agent_context *ctxt, const char *topic, const char *payload)

    Send a message to the agent.

    :param ctxt: Opaque pointer to internal agent-related data.
    :param topic: Topic string to send.
    :param payload: Payload string to send.

    :returns: Returns zero in case of success or non-zero in case of error.
