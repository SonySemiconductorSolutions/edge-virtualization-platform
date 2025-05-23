<!--
SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

# EVP Module Python SDK

## How to build

First, build evp-agent, in the root of the repo, do:

```bash
make KBUILD_DEFCONFIG=configs/linux-docker.config
```

This will build the dependencies, the SDK and the Agent with support for the "Remote SDK"

Install cython dependencies:

```bash
sudo apt-get update && sudo apt-get install -y python3-dev python3-build
```

Now, build the python package:

```bash
cd src/python-evp-app-sdk
python -m build
```

## Installing

Use pip to build and install from the source

```bash
pip install .
```

Use pip to install the package wheel

```bash
pip install dist/evp-app-0.1-cp312-cp312-linux_x86_64.whl
```

## Using

Import the required APIs in your module:

Example:

```py
#!/bin/env python3
from evp.app.module import EVP_initialize, EVP_processEvent
from evp.app.module import EVP_SHOULDEXIT, EVP_OK
from evp.app.module import PyEVP_setConfigurationCallback, PyEVP_sendState

MODULE_NAME = "CONFIG-ECHO"


class Config:
    topic = None
    config = None
    config_len = None

    def cb(self, topic, config, configlen, userData):
        print(
            f"topic={topic}, config={config}, configlen={configlen}, userData={userData}"
        )
        self.topic = topic
        self.config = config
        self.config_len = configlen


def state_cb(reason, userData): ...


def main():
    print(f"{MODULE_NAME}: started!")

    conf = Config()

    client = EVP_initialize()

    PyEVP_setConfigurationCallback(client, conf.cb, 0)

    while True:
        print(f"{MODULE_NAME}: main loop")
        result = EVP_processEvent(client, 1000)
        print(f"{MODULE_NAME}: EVP_processEvent returned {result}")
        if result == EVP_SHOULDEXIT:
            print(f"{MODULE_NAME}: exiting the main loop")
            break

        if conf.config:
            print(
                f"{MODULE_NAME}: Sending State (topic={conf.topic}, size={len(conf.topic)})"
            )
            result = PyEVP_sendState(
                client,
                conf.topic,
                conf.config,
                conf.config_len,
                state_cb,
                None,
            )
            assert result == EVP_OK
            conf.topic = None
            conf.config = None


if __name__ == "__main__":
    main()
```

## Package a module

EVP Python Modules require to be packaged as a python package.
See [Packaging Python Projects](https://packaging.python.org/en/latest/tutorials/packaging-projects/) for reference.

This can be done with a minimal `setup.py` file
in the directory containing the module source:

```py
from setuptools import setup

setup(
    name="config-echo",
    py_modules=["config_echo.py"],
    requires=["evp-app"],
)
