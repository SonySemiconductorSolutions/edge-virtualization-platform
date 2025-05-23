.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:function:: int evp_agent_connect(struct evp_agent_context *ctxt)

    Connect the agent to the Hub.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns: Returns zero in case of success or non-zero in case of error.

.. c:function:: int evp_agent_disconnect(struct evp_agent_context *ctxt)

    Disconnect the agent from the Hub.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns: Returns zero in case of success or non-zero in case of error.
