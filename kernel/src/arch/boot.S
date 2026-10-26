// Entry point. Runs at the physical load address with the MMU off.
//
// Builds a minimal boot page table that maps physical 0..4 GiB twice:
//   - identity (TTBR0), so this code keeps running when the MMU turns on
//   - high half at KERNEL_OFFSET (TTBR1), where the rest of the kernel is linked
// 0..1 GiB is device memory (UART etc.), 1..4 GiB is normal memory (RAM).
// Rust code later replaces TTBR0 with the user address space.

.section .text.boot, "ax"
.global _start
_start:
    msr     daifset, #0xf

    // If started in EL2, drop to EL1.
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    and     x0, x0, #3
    cmp     x0, #2
    b.ne    1f
    mov     x0, #(1 << 31)              // HCR_EL2.RW: EL1 is AArch64
    msr     hcr_el2, x0
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3                  // EL1 may use the physical timer/counter
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    mov     x0, #0x3c5                  // EL1h, all interrupts masked
    msr     spsr_el2, x0
    adr     x0, 1f
    msr     elr_el2, x0
    eret
1:
    // Zero the two boot page-table pages.
    adrp    x0, boot_l0
    mov     x1, #(4096 * 2 / 8)
2:  str     xzr, [x0], #8
    subs    x1, x1, #1
    b.ne    2b

    adrp    x0, boot_l0
    adrp    x1, boot_l1
    orr     x2, x1, #3                  // table descriptor
    str     x2, [x0]

    // L1[0]: 0..1 GiB, Device-nGnRnE (MAIR idx 0), AF, UXN|PXN.
    ldr     x2, =0x0060000000000401
    str     x2, [x1]
    // L1[1..3]: 1..4 GiB, Normal WB (MAIR idx 1), inner shareable, AF, UXN; EL1-only.
    ldr     x3, =0x0040000000000705
    mov     x4, #1
3:  lsl     x5, x4, #30
    orr     x5, x5, x3
    str     x5, [x1, x4, lsl #3]
    add     x4, x4, #1
    cmp     x4, #4
    b.ne    3b

    // MAIR: attr0 = Device-nGnRnE, attr1 = Normal write-back RW-allocate.
    mov     x0, #0xff00
    msr     mair_el1, x0

    // TCR: 48-bit VA for both halves, 4K granule, WB cacheable walks,
    // TBI0 (top-byte-ignore for user pointers, like Linux). IPS from the CPU, capped at 48 bits.
    ldr     x0, =0x00000020B5103510
    mrs     x1, id_aa64mmfr0_el1
    and     x1, x1, #0xf
    mov     x2, #5
    cmp     x1, x2
    csel    x1, x1, x2, lo
    bfi     x0, x1, #32, #3
    msr     tcr_el1, x0

    adrp    x0, boot_l0
    msr     ttbr0_el1, x0
    msr     ttbr1_el1, x0

    // Enable FP/SIMD for EL0 and EL1 (user code needs it; the kernel is softfloat).
    mov     x0, #(3 << 20)
    msr     cpacr_el1, x0
    isb
    tlbi    vmalle1
    dsb     nsh
    isb

    // SCTLR_EL1: MMU, D-cache, I-cache on; let EL0 use DC ZVA, read CTR_EL0,
    // do cache maintenance, and execute WFI/WFE without trapping.
    ldr     x0, =0x34D5D805
    msr     sctlr_el1, x0
    isb

    // Now running with the MMU on (still via the identity map).
    ldr     x0, =__stack_top
    mov     sp, x0

    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
4:  cmp     x0, x1
    b.hs    5f
    str     xzr, [x0], #8
    b       4b
5:
    ldr     x0, =exception_vectors
    msr     vbar_el1, x0
    isb

    ldr     x0, =kernel_main
    blr     x0
6:  wfe
    b       6b

.ltorg

.section .bss.boot, "aw", @nobits
.balign 4096
.global boot_l0
boot_l0: .space 4096
boot_l1: .space 4096
