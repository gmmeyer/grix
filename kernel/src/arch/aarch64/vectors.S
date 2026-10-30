// Exception vectors and user-mode entry.
//
// Every exception saves a TrapFrame (x0-x30, sp_el0, elr_el1, spsr_el1) on the
// kernel stack and calls `trap_handler(frame, kind)`. `kind` is the vector
// index: 0-3 current EL/SP0, 4-7 current EL/SPx, 8-11 lower EL AArch64, 12-15 AArch32.
//
// One taken in the kernel first checks there's room for its frame on this
// CPU's stack, above its canary (arch/stack.rs): with none, it's an
// overflow, reported from the emergency stack below. tpidr_el1 is the
// lowest sp with room (boot.S, set_stack_limit); tpidrro_el0 holds x0
// meanwhile, cleared before anything returns to EL0.

.equ FRAME_SIZE, 272

.macro VENTRY kind
    .balign 128
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp, #0]
    mov     x0, #\kind
    b       trap_common
.endm

.macro VENTRY_EL1 kind
    .balign 128
    msr     tpidrro_el0, x0
    mrs     x0, tpidr_el1
    cmp     sp, x0
    mrs     x0, tpidrro_el0
    msr     tpidrro_el0, xzr
    b.lo    stack_overflow
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp, #0]
    mov     x0, #\kind
    b       trap_common
.endm

.section .text.vectors, "ax"
.balign 2048
.global exception_vectors
exception_vectors:
    VENTRY 0
    VENTRY 1
    VENTRY 2
    VENTRY 3
    VENTRY_EL1 4
    VENTRY_EL1 5
    VENTRY_EL1 6
    VENTRY_EL1 7
    VENTRY 8
    VENTRY 9
    VENTRY 10
    VENTRY 11
    VENTRY 12
    VENTRY 13
    VENTRY 14
    VENTRY 15

// An exception in the kernel with this CPU's stack used up: on to its
// emergency stack, just below it, to report it (`stack_overflow_report`
// in mod.rs, with the sp it came in at). No more checks: whatever
// happens there is an exception like any other.
stack_overflow:
    mov     x1, sp
    mrs     x0, tpidr_el1
    msr     tpidr_el1, xzr
    sub     x0, x0, #(FRAME_SIZE + 256)  // the stack's bottom (CANARY_SIZE)
    mov     sp, x0
    mov     x0, x1
    bl      stack_overflow_report

trap_common:
    stp     x2, x3, [sp, #16]
    stp     x4, x5, [sp, #32]
    stp     x6, x7, [sp, #48]
    stp     x8, x9, [sp, #64]
    stp     x10, x11, [sp, #80]
    stp     x12, x13, [sp, #96]
    stp     x14, x15, [sp, #112]
    stp     x16, x17, [sp, #128]
    stp     x18, x19, [sp, #144]
    stp     x20, x21, [sp, #160]
    stp     x22, x23, [sp, #176]
    stp     x24, x25, [sp, #192]
    stp     x26, x27, [sp, #208]
    stp     x28, x29, [sp, #224]
    mrs     x1, sp_el0
    stp     x30, x1, [sp, #240]
    mrs     x1, elr_el1
    mrs     x2, spsr_el1
    stp     x1, x2, [sp, #256]

    mov     x1, x0
    mov     x0, sp
    bl      trap_handler

// Back to EL0 with the frame at sp (also how a CPU starts its first thread).
.global trap_return
trap_return:
    ldp     x1, x2, [sp, #256]
    msr     elr_el1, x1
    msr     spsr_el1, x2
    ldp     x30, x1, [sp, #240]
    msr     sp_el0, x1
    ldp     x0, x1, [sp, #0]
    ldp     x2, x3, [sp, #16]
    ldp     x4, x5, [sp, #32]
    ldp     x6, x7, [sp, #48]
    ldp     x8, x9, [sp, #64]
    ldp     x10, x11, [sp, #80]
    ldp     x12, x13, [sp, #96]
    ldp     x14, x15, [sp, #112]
    ldp     x16, x17, [sp, #128]
    ldp     x18, x19, [sp, #144]
    ldp     x20, x21, [sp, #160]
    ldp     x22, x23, [sp, #176]
    ldp     x24, x25, [sp, #192]
    ldp     x26, x27, [sp, #208]
    ldp     x28, x29, [sp, #224]
    add     sp, sp, #FRAME_SIZE
    eret

// Addresses of things linked at their physical address (.text.boot,
// .bss.boot), out of ADRP's reach from the high half.
.global secondary_entry_addr
secondary_entry_addr:
    ldr     x0, =secondary_entry
    ret
.global empty_l0_addr
empty_l0_addr:
    ldr     x0, =empty_l0
    ret
.ltorg

// return_to_frame(frame: x0) -> !: the frame becomes the stack's last, and
// this CPU returns to EL0 from it.
.global return_to_frame_asm
return_to_frame_asm:
    mov     sp, x0
    b       trap_return

// enter_user_asm(entry: x0, user_sp: x1, kernel_stack_top: x2) -> !
// Resets the kernel stack and drops to EL0 with all registers zeroed.
.section .text
.global enter_user_asm
enter_user_asm:
    mov     sp, x2
    msr     elr_el1, x0
    msr     sp_el0, x1
    msr     spsr_el1, xzr               // EL0t, interrupts unmasked
    msr     tpidr_el0, xzr
    mov     x0, #0
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x6, #0
    mov     x7, #0
    mov     x8, #0
    mov     x9, #0
    mov     x10, #0
    mov     x11, #0
    mov     x12, #0
    mov     x13, #0
    mov     x14, #0
    mov     x15, #0
    mov     x16, #0
    mov     x17, #0
    mov     x18, #0
    mov     x19, #0
    mov     x20, #0
    mov     x21, #0
    mov     x22, #0
    mov     x23, #0
    mov     x24, #0
    mov     x25, #0
    mov     x26, #0
    mov     x27, #0
    mov     x28, #0
    mov     x29, #0
    mov     x30, #0
    eret
