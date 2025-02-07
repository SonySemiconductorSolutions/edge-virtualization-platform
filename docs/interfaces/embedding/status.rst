.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:enum:: evp_agent_status

    :Values:
        
        .. c:enumerator:: EVP_AGENT_STATUS_INIT
            
            agent has been created but not started

        .. c:enumerator:: EVP_AGENT_STATUS_READY

            agent is initialised but not connected

        .. c:enumerator:: EVP_AGENT_STATUS_CONNECTING
            
            agent is waiting for CONNACK

        .. c:enumerator:: EVP_AGENT_STATUS_CONNECTED
            
            agent is connected to hub

        .. c:enumerator:: EVP_AGENT_STATUS_DISCONNECTING
            
            agent is waiting for network operations to finish

        .. c:enumerator:: EVP_AGENT_STATUS_DISCONNECTED
            
            agent is disconnected from network

        .. c:enumerator:: EVP_AGENT_STATUS_STOPPED
            
            agent has been stopped

.. c:function:: enum evp_agent_status evp_agent_get_status(struct evp_agent_context *ctxt)

	Query the current state of the agent.
	
.. c:function:: bool evp_agent_ready(struct evp_agent_context *ctxt)

	Query the readiness of the agent after startup.

	:param ctxt: Agent context pointer object

	:returns: 
	
		:c:var:`true` if agent is not in
		:c:enumerator:`~evp_agent_status.EVP_AGENT_STATUS_INIT` state.
