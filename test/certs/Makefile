# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

all: pair.pem
.PHONY: all

$(VERBOSE).SILENT:

ca-key.pem:
	@echo generating $@
	openssl genpkey \
		--quiet\
		-algorithm rsa\
		-pkeyopt rsa_keygen_bits:4096 \
		-out $@

ca-cert.pem: ca-key.pem
	@echo Generating $@
	openssl req \
		-x509 \
		-key ca-key.pem \
		-out $@ \
		-sha256 \
		-noenc \
		-subj "/C=XX/ST=Barcelona/L=Barcelona/O=Midokura/CN=CA"

server-key.pem:
	@echo Generating $@
	openssl genpkey \
		--quiet\
		-algorithm rsa \
		-pkeyopt rsa_keygen_bits:4096 \
		-out $@

server.csr: server-key.pem
	@echo Generating $@
	openssl req \
		-new \
		-out $@ \
		-key server-key.pem \
		-sha256 \
		-noenc \
		-subj "/C=XX/ST=Barcelona/L=Barcelona/O=Midokura/CN=localhost"

server-cert.pem: server.csr ca-cert.pem ca-key.pem
	@echo Generating $@
	openssl x509 \
		-req \
		-in server.csr \
		-CA ca-cert.pem \
		-CAkey ca-key.pem \
		-CAcreateserial \
		-out $@ \
		-sha256

pair.pem: server-cert.pem server-key.pem
	@echo Generating $@
	cat server-cert.pem server-key.pem > $@

clean:
	rm -f *.pem
	rm -f *.csr
	rm -f *.srl

distclean: clean
.PHONY: clean
