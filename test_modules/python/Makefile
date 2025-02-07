# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = ../..

MODULES =\
	config_echo.$(EXT)\
	download_http_file.$(EXT)\
	rpc.$(EXT)\
	zombie.$(EXT)\
	telemetry_echo2.$(EXT)\
	upload_http_file.$(EXT)\
	upload_http_memory.$(EXT)\

EXT = zip

all: modules

modules: $(MODULES)

%.zip: %
	cd $< && python -m zipfile -c ../`basename $@` __main__.py

clean:
	rm -f *.zip

distclean: clean
