.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

.. c:function:: int evp_agent_stop_instance(struct evp_agent_context *ctxt, const char *name)

    Stop a running instance.

    :param ctxt: Opaque pointer to internal agent-related data.
    :param name: Instance name to stop.

    :returns: Returns zero in case of success or non-zero in case of error.

.. c:function:: int evp_agent_undeploy_all(struct evp_agent_context *ctxt)

    Undeploy instances.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns: Returns zero in case of success or non-zero in case of error.

.. c:function:: int evp_agent_empty_deployment_has_completed(struct evp_agent_context *ctxt)

    Checks whether the deployment reconciliation loop
    has settled on an empty deployment.

    :param ctxt: Opaque pointer to internal agent-related data.

    :returns: Returns zero in case of success or non-zero in case of error.

.. c:function:: int evp_agent_request_pause_deployment(struct evp_agent_context *ctxt)

    Pause agent deployment capability.

    :param ctxt: Opaque pointer to internal agent-related data.
    :returns: zero on success
    :returns: :c:var:`EAGAIN` if deployment cannot be paused yet
        due to a running operation.
        User needs to poll again to check
        that deployment has been successfully
        paused to guaranty no deployment
        is in progress.

    .. note::

        User can subscribe to
        `deployment/reconcileStatus`
        to be notified when
        deployment has been
        successfully paused.

.. c:function:: int evp_agent_resume_deployment(struct evp_agent_context *ctxt)

    Resume agent deployment capability.

    :param ctxt: Opaque pointer to internal agent-related data.
    :returns: zero

