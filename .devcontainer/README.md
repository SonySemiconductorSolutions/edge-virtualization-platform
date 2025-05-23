<!--
SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

## Devcontainer

Devcontainers are the easiest way to replicate the environment we usually
use for development and in the CI.

More information available on https://containers.dev/supporting

## How to start using VS Code

Install the devcontainers extension, open the repository root as the workspace
root, and select option "Reopen in Container"

## How to start using OSS tools

Install devcontainer-cli:

We know you have `npm` already installed.

```bash
npm install -g @devcontainers/cli
```

Build and start the devcontainer. Run from root repo dir:

```bash
devcontainer up --config .devcontainer/ubuntu/devcontainer.json --workspace-folder .
```

Run bash in the devcontainer you just created

```bash
devcontainer exec --workspace-folder . bash
```
