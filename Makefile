# SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
#
# SPDX-License-Identifier: Apache-2.0

PROJECTDIR = .

DIRS = \
	src\
	test\
	test_modules\

include $(PROJECTDIR)/scripts/rules.mk

all: src

depend sdk src libs: lib bin deps.mk include/version.h .config

libs depend: FORCE
	+cd src && $(MAKE) $@

sdk: FORCE
	+cd src && $(MAKE) libevp-app-sdk

lib bin:
	mkdir -p $@

wasm_test_modules: libs
	+cd test_modules && $(MAKE) elf wasm

check: FORCE
	$(MAKE) -f check.mk $@

check_test_config: FORCE
	@if test "$(KBUILD_DEFCONFIG)" != "configs/unit-test-all-hubs-wasm.config";\
	then\
		echo "make: tests only can be executed using the unit-test-all-hubs-wasm configuration";\
		echo "try make KBUILD_DEFCONFIG=configs/unit-test-all-hubs-wasm.config" with a clean tree;\
		exit 1;\
	fi

test: check_test_config libs test_modules

test_modules: libs

signed_test_modules: test_modules
	+cd test_modules && $(MAKE) signed

include/version.h: FORCE
	@curhash=`awk '/AGENT_COMMIT_HASH/ {print $$3}' include/version.h 2>/dev/null` ;\
	newhash=\"`git describe --always --abbrev=0 --dirty --match "NOT A TAG"`\";\
	if test "$$curhash" != "$$newhash"; then\
		trap "rm -f $$$$.tmp" EXIT INT TERM;\
		(echo '#define AGENT_VERSION "$(VERSION)"';\
		 echo "#define AGENT_COMMIT_HASH $$newhash") > $$$$.tmp &&\
		mv $$$$.tmp include/version.h;\
	fi

config: .config

.config:
	srctree=src/libevp-agent/linux \
	KCONFIG_CONFIG=$(KBUILD_DEFCONFIG) \
	python3 -m genconfig \
		--config-out .config \
		--header-path include/config.h

deps.mk: .config
	$(SCRIPTDIR)/mkdeps.sh
	cat $@

dist: all
	$(SCRIPTDIR)/mk-agent-deb.sh -V $(VERSION) -a $(ARCH)

clean:
	cd test && $(MAKE) clean
	rm -rf bin lib
	rm -rf include/nng include/psa
	rm -rf include/flatcc include/mbedtls
	rm -rf include/lib_export.h include/version.h include/parson.h
	rm -f include/wasm_c_api.h include/wasm_export.h
	rm -f libevp-app-sdk-*.tar.gz libevp-app-sdk-*.deb
	rm -f compile_commands.json analysis.txt
	rm -rf dist

distclean:
	rm -f .config deps.mk
	rm -f include/config.h
	git submodule foreach \
		'cd $$toplevel && git submodule deinit --force $$sm_path'
