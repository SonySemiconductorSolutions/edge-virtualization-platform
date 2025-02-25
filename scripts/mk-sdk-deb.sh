#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

arch=amd64
version=0.0.0

usage()
{
    echo "usage: mk-sdk-deb [-a arch] [-V version]" >&2
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
    debarch=arm64
    ;;
x86_64)
    debarch=amd64
    ;;
esac

# create deb package
mkdir -p dist/DEBIAN

cat > dist/DEBIAN/control <<EOF
Package: libevp-app-sdk-dev
Section: contrib/misc
Version: $version
Priority: optional
Architecture: $debarch
Maintainer: Sony Semiconductor Solutions <engineering@midokura.com>
Depends: libc6 (>= 2.35)
Recommends: evp-agent
Vcs-Browser: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform
Vcs-Git: https://github.com/SonySemiconductorSolutions/edge-virtualization-platform
Description: Software Development Kit for EVP applications
 This package provides the required interfaces and libraries
 to build EVP applications.
EOF

cat > dist/DEBIAN/copyright <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: libevp-app-sdk-dev
Upstream-Contact: Sony Semiconductor Solutions
Source: <https://www.sony-semicon.com/en/index.html>

Files: *
Copyright: 2024 Sony Semiconductor Solutions Corporation
License: Apache-2.0

Files: src/flatcc
Copyright: 2015 Mikkel F. Jørgensen, dvide.com
License: Apache-2.0

Files: include/internal/queue.h
Copyright: (c) 1991, 1993 The Regents of the University of California.
License: BSD-3-Clause
EOF

mkdir -p dist/usr/lib/$arch-linux-gnu
mkdir -p dist/usr/include/evp

cp lib/libevp-app-sdk.a dist/usr/lib/$arch-linux-gnu/
cp \
    include/evp/sdk_base.h\
    include/evp/sdk_blob_azure.h\
    include/evp/sdk_blob_evp.h\
    include/evp/sdk_blob.h\
    include/evp/sdk_blob_http_ext.h\
    include/evp/sdk_blob_http.h\
    include/evp/sdk.h\
    include/evp/sdk_sys.h\
    include/evp/sdk_types.h\
    dist/usr/include/evp/

dpkg-deb --build dist libevp-app-sdk-dev-${version}_$debarch.deb
