# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

GENERATED_HEADERS=sdk_reader.h
GENERATED_HEADERS+=sdk_builder.h
GENERATED_HEADERS+=sdk_verifier.h
GENERATED_HEADERS+=flatbuffers_common_reader.h
GENERATED_HEADERS+=flatbuffers_common_builder.h

FLATCC=flatcc

all: $(GENERATED_HEADERS)
.PHONY: all

$(GENERATED_HEADERS): sdk.fbs
	$(FLATCC) \
	-a \
	--json-printer \
	$<

_clean:
	rm -f $(GENERATED_HEADERS)
.PHONY: _clean
