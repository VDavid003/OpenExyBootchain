CROSS_COMPILE?=aarch64-linux-gnu-
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

.PHONY: all

# Needed for next rule to work properly, we need to always run the sub-make for tools,
# but we don't want the stuff depending on those tools to always be considered out of date.
FORCE:

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

newkeys: tools/bl1tool
	tools/bl1tool/bl1tool generate_key -r $(DEFAULT_PRIVKEY) -u $(DEFAULT_PUBKEY)
	tools/bl1tool/bl1tool generate_hmac -e $(DEFAULT_EFUSE) -p $(DEFAULT_PUBKEY) -o $(DEFAULT_HMAC)


bl1.bin.signed: bl1.bin $(bl1tool_BIN) $(KEYS)
	tools/bl1tool/bl1tool build -r $(PRIVKEY) -u $(PUBKEY) $< -m $(HMAC) --id1 0x20 --pubkey_bl31 sboot.bin.1.bin.bl31pubkey --force_size 0x2000 -o $@
	tools/bl1tool/bl1tool verify pubkey -e $(EFUSE) $@ || rm $@
	tools/bl1tool/bl1tool verify signature $@ || rm $@
	tools/bl1tool/bl1tool verify checksum $@ || rm $@

#dependency thing
TARGET_CFLAGS += -MMD -MP


OBJS:=test.o test2.o


bl1.bin: bl1.o
	$(TARGET_OBJCPY) -O binary $< $@

bl1.o: $(OBJS) linker.lds
	$(TARGET_LD) $(OBJS) -o $@ --script=linker.lds

linker.lds: linker.lds.S
	$(CPP) $< -P -o $@

%.o: %.S
	$(TARGET_CC) $(TARGET_CFLAGS) -c -o $@ $<

%.o: %.c
	$(TARGET_CC) $(TARGET_CFLAGS) -c -o $@ $<

#dependency thing
-include $(OBJS:.o=.d)

clean :
	-rm -f *.o bl1.bin.signed
	$(MAKE) -C tools clean

.PHONY: clean
