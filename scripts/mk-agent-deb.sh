#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

arch=amd64
version=0.0.0

usage()
{
    echo usage: mk-agent-deb[-a arch][-V version] >&2
    exit 1
}

while test $# -gt 0; do
    case "$1" in
    -a)
        arch=${2?`usage`}
        shift 2
        ;;
    -V)
        version=${2?`usage`}
        shift 2
        ;;
    *)
        usage
        ;;
    esac
done

rm -rf dist
trap "rm -rf dist $$.tmp" EXIT HUP INT TERM

case $arch in
aarch64)
    arch=arm64
    ;;
x86_64)
    arch=amd64
    ;;
esac

# create deb package
mkdir -p dist/DEBIAN

cat > dist/DEBIAN/control <<EOF
Package: evp-agent
Section: contrib/misc
Version: $version
Priority: optional
Architecture: $arch
Maintainer: Sony Semiconductor Solutions <engineering@midokura.com>
Depends: libc6 (>= 2.35), ca-certificates
Vcs-Browser: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform
Vcs-Git: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform
Description: EVP Agent for IoT Devices
 This package provides the EVP Agent which allows running
 workloads on edge devices for use in AI apps.
EOF

cat > dist/DEBIAN/copyright <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: evp-agent
Upstream-Contact: Sony Semiconductor Solutions
Source: <https://www.sony-semicon.com/en/index.html>

Files: *
Copyright: 2024 Sony Semiconductor Solutions Corporation
License: Apache-2.0

Files: src/libparson/*
Copyright: (c) 2012 - 2019 Krzysztof Gabis
License: MIT

Files: src/libevp-agent/webclient/webclient.c
Copyright: (C) 2007, 2009, 2011-2012, 2014, 2020 Gregory Nutt.
Copyright: (c) 2002, Adam Dunkels.
Copyright: 2024 Sony Semiconductor Solutions Corporation
License: BSD-3-Clause

Files: src/flatcc
Copyright: 2015 Mikkel F. Jørgensen, dvide.com
License: Apache-2.0

Files: src/mbedtls
License: Apache-2.0, GPL-2.0-or-later
Copyright: The Mbed TLS Contributors.
Files: src/wasm-micro-runtime

Files: include/internal/queue.h
Copyright: (c) 1991, 1993 The Regents of the University of California.
License: BSD-3-Clause

Files: src/libevp-agent/netlib/netlib.h
Copyright (C) 2007, 2009, 2011, 2015, 2017 Gregory Nutt. All rights
Copyright (c) 2002, Adam Dunkels.
License: BSD-3-Clause

Files: src/libevp-agent/netlib/netlib_parseurl.c
Copyright: (C) 2007, 2009, 2011, 2016 Gregory Nutt. All rights reserved.
Copyright: (c) 2004, Adam Dunkels and the Swedish Institute of
License:  BSD-3-Clause
EOF

mkdir -p dist/usr/bin
mkdir -p dist/usr/lib
mkdir -p dist/var/lib/evp_agent
mkdir -p dist/lib/systemd/system

cat >  dist/lib/systemd/system/evp-agent.service <<EOF
[Unit]
Description=Edge Virtualization Platform
After=network-online.target

[Service]
Type=exec
StandardOutput=journal
StandardError=journal
ExecStart=/usr/bin/evp_agent
Environment=EVP_MQTT_HOST=localhost
Environment=EVP_MQTT_PORT=1883
Environment=EVP_DATA_DIR=/var/lib/evp_agent
Environment=EVP_HTTPS_CA_CERT=/etc/ssl/certs/ca-certificates.crt

[Install]
WantedBy=multi-user.target
EOF

cp bin/evp_agent dist/usr/bin/evp_agent
cp lib/libiwasm.so dist/usr/lib/libiwasm.so

dpkg-deb --build dist evp-agent-${version}_$arch.deb
