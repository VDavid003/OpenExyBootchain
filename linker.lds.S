#include "include/generated/autoconf.h"

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
TARGET(binary)

SECTIONS
{
    . = CONFIG_BL1_LOAD_ADDRESS;

    .bl1_header CONFIG_BL1_LOAD_ADDRESS : {
        KEEP(*(.bl1_header))
    }

    .text CONFIG_BL1_LOAD_ADDRESS + 0x10 : {
        *(.text.entry)
        *(.text)
    }

    .data : {
        *(.data*)
    }
}
