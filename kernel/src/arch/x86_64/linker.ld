/*
 * The kernel is loaded at physical PHYS_BASE and runs in the high half at
 * PHYS_BASE + KERNEL_OFFSET. Only .text.boot (and the boot page tables) live at
 * their physical address: that code runs before paging is on. The PVH note
 * (boot.S) gets its own PT_NOTE: that's where the VMM looks for the entry.
 * The large code model's sections (.ltext, ...) go with the others.
 */
ENTRY(_start32)

KERNEL_OFFSET = 0xFFFF800000000000;
PHYS_BASE     = 0x200000;

PHDRS
{
    boot PT_LOAD;
    kernel PT_LOAD;
    note PT_NOTE;
}

SECTIONS
{
    . = PHYS_BASE;

    .text.boot : {
        KEEP(*(.text.boot))
    } :boot

    .note.Xen : {
        KEEP(*(.note.Xen))
    } :boot :note

    . = ALIGN(4096);
    .bss.boot (NOLOAD) : {
        *(.bss.boot)
    } :boot

    . = ALIGN(4096);
    . += KERNEL_OFFSET;
    __kernel_start = .;

    .text : AT(ADDR(.text) - KERNEL_OFFSET) {
        *(.text .text.* .ltext .ltext.*)
    } :kernel

    . = ALIGN(4096);
    .rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) {
        *(.rodata .rodata.* .lrodata .lrodata.*)
    } :kernel

    . = ALIGN(4096);
    .data : AT(ADDR(.data) - KERNEL_OFFSET) {
        *(.data .data.* .ldata .ldata.*)
        *(.got .got.*)
    } :kernel

    . = ALIGN(16);
    .bss (NOLOAD) : AT(ADDR(.bss) - KERNEL_OFFSET) {
        __bss_start = .;
        *(.bss .bss.* .lbss .lbss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } :kernel

    . = ALIGN(4096);
    /* Each CPU's emergency stack and kernel stack
     * (grix_abi::machine::MAX_CPUS of them; the sizes are arch/stack.rs's). */
    .stack (NOLOAD) : AT(ADDR(.stack) - KERNEL_OFFSET) {
        __stacks = .;
        . += __stacks_size;
    } :kernel
    /* CPU 0's, which it boots on. */
    __stack_top = __stacks + __stack_slot;

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack .note.gnu.*)
    }
}
