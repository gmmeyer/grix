// The vDSO (`vdso.rs`) for x86_64: the ELF header, one PT_LOAD for
// everything and a PT_DYNAMIC; the dynamic section, symbols, a SysV hash
// table with one bucket, version definitions (the base one, then LINUX_2.6
// for every symbol, as Linux's x86_64 vDSO has them), and the code. No
// section headers: loaders don't need them. Offsets are from the start,
// which the PT_LOAD puts at virtual address 0. The clock's parameters are
// in the page before it (`VVAR`).
    .pushsection .rodata.grix_vdso, "a"
    .balign 4096
    .globl grix_vdso_start
    .globl grix_vdso_end
grix_vdso_start:
.Lv_base:
    .byte 0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0
    .quad 0
    .short 3, 62
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
    .long .Lv_n_time - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_time - .Lv_base, .Lv_time_end - .Lv_time
    .long .Lv_n_getres - .Lv_str
    .byte 0x12, 0
    .short 1
    .quad .Lv_getres - .Lv_base, .Lv_getres_end - .Lv_getres

.Lv_hash:
    .long 1, 5
    .long 1
    .long 0, 2, 3, 4, 0

.Lv_verdef:
    .short 1, 1, 1, 1
    .long 0x0deebfa1, 20, 28
    .long .Lv_soname - .Lv_str, 0
    .short 1, 0, 2, 1
    .long 0x03ae75f6, 20, 0
    .long .Lv_n_version - .Lv_str, 0

.Lv_versym:
    .short 0, 2, 2, 2, 2

.Lv_str:
    .byte 0
.Lv_soname:
    .asciz "linux-vdso.so.1"
.Lv_n_version:
    .asciz "LINUX_2.6"
.Lv_n_gettime:
    .asciz "__vdso_clock_gettime"
.Lv_n_gtod:
    .asciz "__vdso_gettimeofday"
.Lv_n_time:
    .asciz "__vdso_time"
.Lv_n_getres:
    .asciz "__vdso_clock_getres"
.Lv_str_end:

    .balign 16
// The time in ns in %rax: monotonic for %r8 = 0, of day otherwise.
// Clobbers %rdx, %r9, %r10, %r11.
.Lv_now:
    leaq .Lv_base - 4096(%rip), %r9
1:  movq (%r9), %r10
    testb $1, %r10b
    jnz 1b
    lfence
    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    subq 8(%r9), %rax
    mulq 16(%r9)
    shrdq $32, %rdx, %rax
    testq %r8, %r8
    jz 2f
    addq 24(%r9), %rax
2:  movq (%r9), %r11
    cmpq %r10, %r11
    jne 1b
    ret

// clock_gettime(clock, ts): REALTIME, REALTIME_COARSE and TAI are the time
// of day; MONOTONIC, MONOTONIC_RAW, MONOTONIC_COARSE and BOOTTIME
// monotonic, as the system call has them.
.Lv_gettime:
    cmpl $11, %edi
    ja 9f
    movl $0x8f3, %eax
    btl %edi, %eax
    jnc 9f
    xorl %r8d, %r8d
    movl $0x821, %eax
    btl %edi, %eax
    adcl $0, %r8d
    call .Lv_now
    xorl %edx, %edx
    movl $1000000000, %ecx
    divq %rcx
    movq %rax, (%rsi)
    movq %rdx, 8(%rsi)
    xorl %eax, %eax
    ret
9:  movl $228, %eax
    syscall
    ret
.Lv_gettime_end:

// gettimeofday(tv, tz): a timezone is the system call's.
.Lv_gtod:
    testq %rsi, %rsi
    jnz 9f
    testq %rdi, %rdi
    jz 8f
    movl $1, %r8d
    call .Lv_now
    xorl %edx, %edx
    movl $1000, %ecx
    divq %rcx
    xorl %edx, %edx
    movl $1000000, %ecx
    divq %rcx
    movq %rax, (%rdi)
    movq %rdx, 8(%rdi)
8:  xorl %eax, %eax
    ret
9:  movl $96, %eax
    syscall
    ret
.Lv_gtod_end:

// time(t): seconds of the time of day.
.Lv_time:
    movl $1, %r8d
    call .Lv_now
    xorl %edx, %edx
    movl $1000000000, %ecx
    divq %rcx
    testq %rdi, %rdi
    jz 1f
    movq %rax, (%rdi)
1:  ret
.Lv_time_end:

.Lv_getres:
    movl $229, %eax
    syscall
    ret
.Lv_getres_end:
.Lv_end:
grix_vdso_end:
    .popsection
