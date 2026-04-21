OUTDIR := out
TITLE_ID := 4200000000000666
SD_ROOT := $(OUTDIR)/sd
TITLE_DIR := $(SD_ROOT)/atmosphere/contents/$(TITLE_ID)
ENABLE_SSL_MITM ?= 0
DECLARE_SSL_MITM ?= 0
ENABLE_SSL_SYSTEM_MITM ?= 0
ENABLE_BOOT2 ?= 0
export ENABLE_SSL_MITM

export NETWORK_MITM_GIT_BRANCH   := $(shell git symbolic-ref --short HEAD)

ifeq ($(strip $(shell git status --porcelain 2> /dev/null)),)
export NETWORK_MITM_GIT_REVISION := $(NETWORK_MITM_GIT_BRANCH)-$(shell git rev-parse --short HEAD)
else
export NETWORK_MITM_GIT_REVISION := $(NETWORK_MITM_GIT_BRANCH)-$(shell git rev-parse --short HEAD)-dirty
endif

NETWORK_MITM_VERSION_MAJOR := $(shell grep 'define NETWORK_MITM_VERSION_MAJOR\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION_MINOR := $(shell grep 'define NETWORK_MITM_VERSION_MINOR\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION_MICRO := $(shell grep 'define NETWORK_MITM_VERSION_MICRO\b' network_mitm/include/networkmitm_version.h | tr -s [:blank:] | cut -d' ' -f3)
NETWORK_MITM_VERSION := $(NETWORK_MITM_VERSION_MAJOR).$(NETWORK_MITM_VERSION_MINOR).$(NETWORK_MITM_VERSION_MICRO)-$(NETWORK_MITM_GIT_REVISION)

all: dist

build:
	make -C Atmosphere-libs/libstratosphere nx_release
	make -C network_mitm all

pack: build
	@mkdir -p $(TITLE_DIR)/flags
	@cp network_mitm/out/nintendo_nx_arm64_armv8a/release/network_mitm.nsp $(TITLE_DIR)/exefs.nsp
ifeq ($(ENABLE_BOOT2),1)
	@touch $(TITLE_DIR)/flags/boot2.flag
else
	@rm -f $(TITLE_DIR)/flags/boot2.flag
endif
	@printf '{\n\t"name"  : "network_mitm",\n\t"tid"   : "%s",\n\t"requires_reboot": false\n}\n' "$(TITLE_ID)" > $(TITLE_DIR)/toolbox.json
	@rm -f $(TITLE_DIR)/mitm.lst
	@touch $(TITLE_DIR)/mitm.lst
ifeq ($(DECLARE_SSL_MITM),1)
	@echo "ssl" >> $(TITLE_DIR)/mitm.lst
ifeq ($(ENABLE_SSL_SYSTEM_MITM),1)
	@echo "ssl:s" >> $(TITLE_DIR)/mitm.lst
endif
endif

dist: pack
	@cd $(SD_ROOT); zip -r ../network_mitm-$(NETWORK_MITM_VERSION).zip ./* > /dev/null; cd ../;

clean:
	make -C Atmosphere-libs/libstratosphere clean
	make -C network_mitm clean

.PHONY: all build pack dist clean
