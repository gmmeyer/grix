/*
 * The kernel is loaded at physical PHYS_BASE and runs in the high half at
 * PHYS_BASE + KERNEL_OFFSET. Only .text.boot (and the boot page tables) live at
 * their physical address: that code runs before the MMU is on.
 */
ENTRY(_start)

KERNEL_OFFSET = 0xFFFF000000000000;
PHYS_BASE     = 0x40200000;

SECTIONS
{
    . = PHYS_BASE;

    .text.boot : {
        KEEP(*(.text.boot))
    }

    . = ALIGN(4096);
    .bss.boot (NOLOAD) : {
        *(.bss.boot)
    }

    . = ALIGN(4096);
    . += KERNEL_OFFSET;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_OFFSET) {
        KEEP(*(.text.vectors))
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4096);
    .data : AT(ADDR(.data) - KERNEL_OFFSET) {
        *(.data .data.*)
        *(.got .got.*)
    }

    . = ALIGN(16);
    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_OFFSET) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(4096);
    /* Each CPU's emergency stack and kernel stack
     * (grix_abi::machine::MAX_CPUS of them; the sizes are arch/stack.rs's). */
    .stack (NOLOAD) : AT(ADDR(.stack) - KERNEL_OFFSET) {
        __stacks = .;
        . += __stacks_size;
    }
    /* CPU 0's, which it boots on. */
    __stack_top = __stacks + __stack_slot;

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note .note.*)
    }
}
