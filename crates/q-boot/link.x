/* Qbitel EdgeOS Bootloader Linker Script */

MEMORY
{
    /* Bootloader region: 32KB at start of flash */
    FLASH : ORIGIN = 0x08000000, LENGTH = 32K

    /* RAM for bootloader (first 32KB of 512KB) */
    RAM   : ORIGIN = 0x20000000, LENGTH = 32K
}

/* Entry point */
ENTRY(_start)

SECTIONS
{
    /* Vector table must be first */
    .vector_table ORIGIN(FLASH) :
    {
        LONG(_stack_top);           /* Initial SP */
        LONG(_start + 1);           /* Reset handler (thumb) */
        LONG(_nmi_handler + 1);     /* NMI */
        LONG(_hard_fault + 1);      /* HardFault */
        LONG(_mem_manage + 1);      /* MemManage */
        LONG(_bus_fault + 1);       /* BusFault */
        LONG(_usage_fault + 1);     /* UsageFault */
        LONG(0);                    /* Reserved */
        LONG(0);                    /* Reserved */
        LONG(0);                    /* Reserved */
        LONG(0);                    /* Reserved */
        LONG(_svc_handler + 1);     /* SVCall */
        LONG(_debug_monitor + 1);   /* Debug Monitor */
        LONG(0);                    /* Reserved */
        LONG(_pendsv + 1);          /* PendSV */
        LONG(_systick + 1);         /* SysTick */
    } > FLASH

    /* Code */
    .text : ALIGN(4)
    {
        *(.text .text.*)
        . = ALIGN(4);
    } > FLASH

    /* Read-only data */
    .rodata : ALIGN(4)
    {
        *(.rodata .rodata.*)
        . = ALIGN(4);
    } > FLASH

    /* Initialized data (copied from flash to RAM) */
    .data : ALIGN(4)
    {
        _sdata = .;
        *(.data .data.*)
        . = ALIGN(4);
        _edata = .;
    } > RAM AT > FLASH

    _sidata = LOADADDR(.data);

    /* Uninitialized data (zeroed) */
    .bss (NOLOAD) : ALIGN(4)
    {
        _sbss = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    /* Stack */
    .stack (NOLOAD) : ALIGN(8)
    {
        . = . + 4K;
        _stack_top = .;
    } > RAM

    /* Discard */
    /DISCARD/ :
    {
        *(.ARM.exidx .ARM.exidx.*)
        *(.ARM.extab .ARM.extab.*)
    }
}

/* Default handlers */
PROVIDE(_nmi_handler = _default_handler);
PROVIDE(_hard_fault = _default_handler);
PROVIDE(_mem_manage = _default_handler);
PROVIDE(_bus_fault = _default_handler);
PROVIDE(_usage_fault = _default_handler);
PROVIDE(_svc_handler = _default_handler);
PROVIDE(_debug_monitor = _default_handler);
PROVIDE(_pendsv = _default_handler);
PROVIDE(_systick = _default_handler);
