CROSS_COMPILE?=aarch64-linux-gnu-
ARCH 	:= arm64

#helpers for KBuild, taken from Linux
include Makefile.kbuild
ifndef mixed-build
ifndef config-build
#end of helpers for KBuild

TARGET_CC:=$(CROSS_COMPILE)gcc
TARGET_CPP:=$(CROSS_COMPILE)cpp
TARGET_LD:=$(CROSS_COMPILE)ld
TARGET_OBJCPY:=$(CROSS_COMPILE)objcopy

TOOLS := $(patsubst tools/%/Makefile,%,$(wildcard tools/*/Makefile))
TOOLS_FULLPATH := $(patsubst %,tools/%/%,$(TOOLS))

#variables like bl1tool_BIN
$(foreach t,$(TOOLS),\
	$(eval $(t)_BIN := tools/$(t)/$(t))\
)

all: bl1.bin.signed

#Actually be able to build tools
$(TOOLS_FULLPATH): FORCE
	$(MAKE) -C tools $(notdir $@)

DEFAULT_PRIVKEY := keys/key.privkey
DEFAULT_PUBKEY  := keys/key.pubkey
DEFAULT_HMAC    := keys/key.hmac
DEFAULT_EFUSE   := keys/key.efuse

PRIVKEY ?= $(DEFAULT_PRIVKEY)
PUBKEY  ?= $(DEFAULT_PUBKEY)
HMAC    ?= $(DEFAULT_HMAC)
EFUSE   ?= $(DEFAULT_EFUSE)
KEYS    := $(PRIVKEY) $(PUBKEY) $(HMAC) $(EFUSE)

.PHONY: newkeys

newkeys: $(bl1tool_BIN)
	tools/bl1tool/bl1tool generate_key -r $(DEFAULT_PRIVKEY) -u $(DEFAULT_PUBKEY)
	tools/bl1tool/bl1tool generate_hmac -e $(DEFAULT_EFUSE) -p $(DEFAULT_PUBKEY) -o $(DEFAULT_HMAC)


bl1.bin.signed: bl1.bin $(bl1tool_BIN) $(KEYS)
	tools/bl1tool/bl1tool build -r $(PRIVKEY) -u $(PUBKEY) $< -m $(HMAC) --id1 $(CONFIG_BL1_FOOTER_MODEL_ID1) --pubkey_bl31 $(CONFIG_BL31_PUBKEY_FILE) --force_size 0x2000 -o $@
	tools/bl1tool/bl1tool verify pubkey -e $(EFUSE) $@ || rm $@
	tools/bl1tool/bl1tool verify signature $@ || rm $@
	tools/bl1tool/bl1tool verify checksum $@ || rm $@

bl1.bin.unsigned: bl1.bin $(bl1tool_BIN)
	tools/bl1tool/bl1tool build $< --force_size 0x2000 --unsigned -o $@
	tools/bl1tool/bl1tool verify checksum $@ || rm $@

PHONY += built-in.a

built-in.a: $(build-dir)

bl1.bin: bl1.o
	$(TARGET_OBJCPY) -O binary $< $@

bl1.o: linker.lds built-in.a
	$(TARGET_LD) --whole-archive built-in.a -o $@ --script=linker.lds

linker.lds: linker.lds.S
	$(TARGET_CPP) $< -P -o $@

# Directories & files removed with 'make clean'
CLEAN_FILES += bl1.bin.signed bl1.bin

# Directories & files removed with 'make mrproper'
MRPROPER_FILES += include/config include/generated          \
		  .config .config.old
	       
#prepare removed!!!
PHONY += $(build-dir)
$(build-dir):
	$(Q)$(MAKE) $(build)=$@ need-builtin=1 need-modorder=1 $(single-goals)


# clean - Delete most
#
clean: private rm-files := $(CLEAN_FILES)
	       
# mrproper - Delete all generated files, including .config
#
mrproper: private rm-files := $(MRPROPER_FILES)
mrproper-dirs      := $(addprefix _mrproper_,scripts)

PHONY += $(mrproper-dirs) mrproper
$(mrproper-dirs):
	$(Q)$(MAKE) $(clean)=$(patsubst _mrproper_%,%,$@)

mrproper: clean $(mrproper-dirs)
	$(call cmd,rmfiles)

clean-dirs := $(addprefix _clean_, $(clean-dirs))
PHONY += $(clean-dirs) clean
$(clean-dirs):
	$(Q)$(MAKE) $(clean)=$(patsubst _clean_%,%,$@)

clean: $(clean-dirs)
	$(call cmd,rmfiles)
	@find . $(RCS_FIND_IGNORE) \
		\( -name '*.[od]' \
		\) -type f -print \
		| xargs rm -rf
	$(MAKE) -C tools clean
#last line to be retired later

.PHONY: clean

quiet_cmd_rmfiles = $(if $(wildcard $(rm-files)),CLEAN   $(wildcard $(rm-files)))
      cmd_rmfiles = rm -rf $(rm-files)

endif # config-build
endif # mixed-build

PHONY += FORCE
FORCE:

# Declare the contents of the PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
