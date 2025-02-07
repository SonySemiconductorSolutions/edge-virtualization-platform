.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0


.. c:function:: const char *evp_agent_module_get_id(const struct module *module)

    Returns the moduleId of a module

    :param module: Opaque pointer to a module object.
    :return: Returns the ID of the module.

.. c:function:: int evp_agent_module_set_failure_msg(struct module *module, const char *fmt, ...)

    Sets the failureMessage of a module

    :param module: Opaque pointer to a module object.


.. c:function:: bool evp_agent_module_is_in_use(const char *moduleId)

    Checks if the module is loaded by the agent (in use)

    :param moduleId: the ID of the module to be checked.
    :return: Returns true if module is loaded by the Agent

.. c:function:: void evp_agent_module_clear_failure_msg(struct module *module)

    Clears the failureMessage of a module

    :param module: Opaque pointer to a module object.
