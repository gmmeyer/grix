// The vDSO (`vdso.rs`) for arm64: the ELF header, one PT_LOAD for
// everything and a PT_DYNAMIC; the dynamic section, symbols, a SysV hash
// table with one bucket, version definitions (the base one, then
// LINUX_2.6.39 for every symbol), and the code. No section headers: loaders
// don't need them. Offsets are from the start, which the PT_LOAD puts at
// virtual address 0.
    .pushsection .rodata.grix_vdso, "a"
    .balign 4096
    .globl grix_vdso_start
    .globl grix_vdso_end
grix_vdso_start:
.Lv_base:
    .byte 0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0
    .quad 0
    .short 3, 183
    .long 1
    .quad 0, 64, 0
    .long 0
    .short 64, 56, 2, 64, 0, 0

    .long 1, 5
    .quad 0, 0, 0, .Lv_end - .Lv_base, .Lv_end - .Lv_base, 4096
    .long 2, 4
    .quad .Lv_dyn - .Lv_base, .Lv_dyn - .Lv_base, .Lv_dyn - .Lv_base
    .quad .Lv_dyn_end - .Lv_dyn, .Lv_dyn_end - .Lv_dyn, 8

.Lv_dyn:
    .quad 4, .Lv_hash - .Lv_base
    .quad 5, .Lv_str - .Lv_base
    .quad 6, .Lv_sym - .Lv_base
    .quad 10, .Lv_str_end - .Lv_str
    .quad 11, 24
    .quad 14, .Lv_soname - .Lv_str
    .quad 0x6ffffff0, .Lv_versym - .Lv_base
    .quad 0x6ffffffc, .Lv_verdef - .Lv_base
    .quad 0x6ffffffd, 2
    .quad 0, 0
.Lv_dyn_end:

.Lv_sym:
    .long 0
    .byte 0, 0
    .short 0
    .quad 0, 0
    .long .Lv_n_gettime - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_gettime - .Lv_base, .Lv_gettime_end - .Lv_gettime
    .long .Lv_n_gtod - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_gtod - .Lv_base, .Lv_gtod_end - .Lv_gtod
    .long .Lv_n_getres - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_getres - .Lv_base, .Lv_getres_end - .Lv_getres
    .long .Lv_n_sigreturn - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_sigreturn - .Lv_base, .Lv_sigreturn_end - .Lv_sigreturn

.Lv_hash:
    .long 1, 5
    .long 1
    .long 0, 2, 3, 4, 0

.Lv_verdef:
    .short 1, 1, 1, 1
    .long 0x0deebfa1, 20, 28
    .long .Lv_soname - .Lv_str, 0
    .short 1, 0, 2, 1
    .long 0x075fcb89, 20, 0
    .long .Lv_n_version - .Lv_str, 0

.Lv_versym:
    .short 0, 2, 2, 2, 2

.Lv_str:
    .byte 0
.Lv_soname:
    .asciz "linux-vdso.so.1"
.Lv_n_version:
    .asciz "LINUX_2.6.39"
.Lv_n_gettime:
    .asciz "__kernel_clock_gettime"
.Lv_n_gtod:
    .asciz "__kernel_gettimeofday"
.Lv_n_getres:
    .asciz "__kernel_clock_getres"
.Lv_n_sigreturn:
    .asciz "__kernel_rt_sigreturn"
.Lv_str_end:

    .balign 16
// The time in ns in x10: monotonic for x12 = 0, of day otherwise.
// Clobbers x9, x11, x13-x17.
.Lv_now:
    adr x9, .Lv_base
    sub x9, x9, #4096
1:  ldar x13, [x9]
    tbnz x13, #0, 1b
    ldp x14, x15, [x9, #8]
    ldr x16, [x9, #24]
    isb
    mrs x17, cntvct_el0
    dmb ishld
    ldr x11, [x9]
    cmp x11, x13
    b.ne 1b
    sub x17, x17, x14
    mul x10, x17, x15
    umulh x11, x17, x15
    extr x10, x11, x10, #32
    cbz x12, 2f
    add x10, x10, x16
2:  ret

// clock_gettime(clock, ts): REALTIME, REALTIME_COARSE and TAI are the time
// of day; MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE and BOOTTIME
// monotonic, as the system call has them.
.Lv_gettime:
    cmp w0, #11
    b.hi 9f
    mov w10, #0x821
    lsr w10, w10, w0
    and x12, x10, #1
    mov w11, #0xd2
    lsr w11, w11, w0
    orr w11, w11, w10
    tbz w11, #0, 9f
    mov x6, x30
    bl .Lv_now
    mov x30, x6
    mov x11, #0xca00
    movk x11, #0x3b9a, lsl #16
    udiv x12, x10, x11
    msub x13, x12, x11, x10
    stp x12, x13, [x1]
    mov x0, #0
    ret
9:  mov x8, #113
    svc #0
    ret
.Lv_gettime_end:

// gettimeofday(tv, tz): a timezone is the system call's.
.Lv_gtod:
    cbnz x1, 9f
    cbz x0, 8f
    mov x12, #1
    mov x6, x30
    bl .Lv_now
    mov x30, x6
    mov x11, #1000
    udiv x10, x10, x11
    mov x11, #0x4240
    movk x11, #0xf, lsl #16
    udiv x12, x10, x11
    msub x13, x12, x11, x10
    stp x12, x13, [x0]
8:  mov x0, #0
    ret
9:  mov x8, #169
    svc #0
    ret
.Lv_gtod_end:

.Lv_getres:
    mov x8, #114
    svc #0
    ret
.Lv_getres_end:

// What unwinders recognize as a signal frame's return (as arch::sigframe::TRAMPOLINE).
.Lv_sigreturn:
    mov x8, #139
    svc #0
.Lv_sigreturn_end:
.Lv_end:
grix_vdso_end:
    .popsection
