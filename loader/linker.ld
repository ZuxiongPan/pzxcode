ENTRY(_start)

MEMORY
{
    SRAM_CODE : ORIGIN = 0x00100000, LENGTH = 0x00100000 /* 1MB for TEXT */
    SRAM_DATA : ORIGIN = 0x00200000, LENGTH = 0x00100000  /* 1MB for DATA */
}

SECTIONS
{
    .text : {
        KEEP(*(.text.loader))
        *(.text*)
        *(.rodata*)
        . = ALIGN(8);
    } > SRAM_CODE

    .data : {
        . = ALIGN(8);
        *(.data*)
        . = ALIGN(8);
    } > SRAM_DATA

    .bss : {
        . = ALIGN(8);
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    } > SRAM_DATA
}
