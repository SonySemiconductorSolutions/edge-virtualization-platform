<!--
SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation

SPDX-License-Identifier: Apache-2.0
-->

<div align="center">

# Edge Virtualization Platform

A workload agent designed for Edge Computing.

</div>

## Introduction

The *EVP Agent* is a reliable and efficient solution for Edge Sensing application management, capable of improving the security, reliability, and scalability of IoT solutions.

## Getting started on Raspberry Pi

### Download

Download the .deb packages from the [latest release](https://github.com/SonySemiconductorSolutions/edge-virtualization-platform/releases).

### Documentation

Latest documentation can be found on the [Edge Virtualization Platform documentation](https://evp-agent.docs.midokura.com/)

### Install

Install them on the Raspi OS with:

```sh
sudo apt install ./python3-evp-app_*.deb
sudo apt install ./evp-agent-*.deb
```

### Configure

If you are running local console on the Raspberry Pi, this step is not necesary, otherwise, you need to set up the IP address of
the computer running Local Console. Please check Local Console documentation for more information on how to set it up.

```sh
vi /lib/systemd/system/evp-agent.service
```

Find the following line and replace `localhost` with the address of the server where Local Console is reachable:

```
Environment=EVP_MQTT_HOST=localhost
```

You might need to update the port also:

```
Environment=EVP_MQTT_PORT=1883
```

### Start the service

Enable the evp-agent service to start automatically on system boot and also start it now:

```sh
systemctl enable --now evp-agent
```

or if you prefer just start it now:

```sh
systemctl start evp-agent
```

And after a few seconds, the agent should be connected to the Local Console MQTT broker.

### Read logs

You can see the logs of the evp-agent with:

```sh
journalctl -fu evp-agent
```
