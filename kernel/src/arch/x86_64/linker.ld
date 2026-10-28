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
    /* A 64 KiB kernel stack per CPU (grix_abi::machine::MAX_CPUS); CPU 0's first. */
    .stack (NOLOAD) : AT(ADDR(.stack) - KERNEL_OFFSET) {
        __stacks = .;
        . += 0x10000;
        __stack_top = .;
        . += 0x10000 * 7;
        /* A page per CPU for double faults (IST 1), CPU 0's at the top. */
        . += 0x1000 * 8;
        __df_stack_top = .;
    } :kernel

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr .comment .note.GNU-stack .note.gnu.*)
    }
}
