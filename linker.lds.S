OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
TARGET(binary)

SECTIONS
{
    . = 0x02021800;

    .bl1_header 0x02021800 : {
        KEEP(*(.bl1_header))
    }

    .text 0x02021810 : {
        *(.text.entry)
        *(.text)
    }

    .data : {
        *(.data*)
    }
}
