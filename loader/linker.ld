ENTRY(_start)

MEMORY
{
    SRAM : ORIGIN = 0x00080000, LENGTH = 0x00180000 /* 1.5MB for LOADER */
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
