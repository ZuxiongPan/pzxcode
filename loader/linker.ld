ENTRY(_start)

MEMORY
{
    SRAM : ORIGIN = 0x00100000, LENGTH = 0x00200000 /* 2MB for LOADER */
}

SECTIONS
{
    .text : {
        KEEP(*(.text.loader))
        *(.text*)
        *(.rodata*)
        . = ALIGN(8);
    } > SRAM

    .data : {
        . = ALIGN(8);
        *(.data*)
        . = ALIGN(8);
    } > SRAM

    .bss : {
        . = ALIGN(8);
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    } > SRAM
}
