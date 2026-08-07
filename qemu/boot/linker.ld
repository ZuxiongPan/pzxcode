
ENTRY(_start)

MEMORY
{
    MROM : ORIGIN = 0x00000000, LENGTH = 0x00080000 /* 512KB MROM */
    SRAM : ORIGIN = 0x00080000, LENGTH = 0x00100000 /* 12MB SRAM */
}

SECTIONS
{
    .text : {
        KEEP(*(.text.startup))
        *(.text*)
        *(.rodata*)
        . = ALIGN(8);
    } > MROM

    .data : {
        . = ALIGN(8);
        __data_start__ = .;
        *(.data*)
        . = ALIGN(8);
        __data_end__ = .;
    } > SRAM AT > MROM
    
    __data_load_start__ = LOADADDR(.data);

    .bss : {
        . = ALIGN(8);
        __bss_start__ = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end__ = .;
    } > SRAM
}

