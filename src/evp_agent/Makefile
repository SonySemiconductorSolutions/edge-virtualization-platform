# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

include $(PROJECTDIR)/scripts/rules.mk
-include $(PROJECTDIR)/deps.mk

MORE_LDLIBS =\
	-levp-agent\
	-levp-utils\
	$(DEPLIBS)\
	-lparson\
	-lm\

DEPS =\
	$(FILELIBS)\
	$(LIBDIR)/libevp-agent.a\
	$(LIBDIR)/libevp-utils.a\
	$(LIBDIR)/libparson.a\

all: evp_agent.elf

evp_agent.elf: evp_agent.o config_env.o $(DEPS)
	$(CC) $(PROJ_LDFLAGS) -o $@ evp_agent.o config_env.o $(PROJ_LDLIBS)
	cp $@ $(BINDIR)/evp_agent

clean:
	rm -f evp_agent.elf
