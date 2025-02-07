#!/bin/sh

# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

CERTS=/etc/ssl/evp-agent
EVP_MQTT_TLS_CLIENT_CERT=${EVP_MQTT_TLS_CLIENT_CERT:-${CERTS}/client.crt}
EVP_MQTT_TLS_CLIENT_KEY=${EVP_MQTT_TLS_CLIENT_KEY:-${CERTS}/client.key}

if ! [ -e ${EVP_MQTT_TLS_CLIENT_CERT} -a -e ${EVP_MQTT_TLS_CLIENT_KEY} ]; then
    mkdir -p ${CERTS}
    echo "TLS key not found. Will generate one for you."
    openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 \
        -keyout ${EVP_MQTT_TLS_CLIENT_KEY} -out ${EVP_MQTT_TLS_CLIENT_CERT} \
        -subj "/C=ES/ST=Barcelona/L=Barcelona/O=Midokura/OU=EVP Device/CN=$(openssl rand -hex 16)"
else
    echo "Identity files already exist: ${EVP_MQTT_TLS_CLIENT_CERT} and ${EVP_MQTT_TLS_CLIENT_KEY}"
fi

echo "Certificate for \"$(openssl x509 -noout -subject -in ${EVP_MQTT_TLS_CLIENT_CERT})\":"
cat ${EVP_MQTT_TLS_CLIENT_CERT}
echo "Make sure it is added to the broker configuration."
