/* Flash at 0x08000000 and RAM at 0x20000000, as most STM32 parts map them. */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 1M
    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

ENTRY(reset_handler)

SECTIONS
{
    .vectors : { KEEP(*(.vectors)) } > FLASH
    .text : { *(.text*) } > FLASH
    .rodata : { *(.rodata*) } > FLASH
    .ARM.exidx : { *(.ARM.exidx*) } > FLASH
    .data : { *(.data*) } > RAM AT > FLASH
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } > RAM
    stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
