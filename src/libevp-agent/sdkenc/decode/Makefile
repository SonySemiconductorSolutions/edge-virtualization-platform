# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

FLATCC = ../flatcc
FLATCC_INCLUDE = $(FLATCC)/include
FLATCC_LIB = $(FLATCC)/lib

PROGNAME = decode

CSRCS = decode.c
COBJS = $(CSRCS:.c=.o)

CFLAGS += -I.. -I$(FLATCC_INCLUDE)
CFLAGS += -Os
CFLAGS += -Wall
CFLAGS += -Werror

LIBS += -L$(FLATCC_LIB) -lflatccrt

all: $(PROGNAME)

clean:
	rm -rf $(PROGNAME)
	rm -rf $(COBJS)

$(PROGNAME): $(COBJS)
	$(CC) $(CLINKFLAGS) -o $@ $(COBJS) $(LIBS)

$(COBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# See issue: EVP-551
#
# an equivalent with flatc:
#   printf "%s" "CAAAAAAAAADY////AQAAAAQAAADs////jBh4YQAAAACEvdMNAAAAAAgAFAAEAAwACAAMAAQACAA=" | openssl enc -a -A -d > req.bin
#   flatc --json --raw-binary --root-type Request ../sdk.fbs -- req.bin
#   cat req.json
test: $(PROGNAME)
	printf "%s" "CAAAAAAAAADY////AQAAAAQAAADs////jBh4YQAAAACEvdMNAAAAAAgAFAAEAAwACAAMAAQACAA=" | openssl enc -a -A -d | ./$(PROGNAME) request
	printf "%s" "BAAAAOz///8BAAAABAAAAPz///8EAAQACAAMAAQACAA=" | openssl enc -a -A -d | ./$(PROGNAME) response
