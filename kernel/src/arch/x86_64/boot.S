// Boot, x86_64. The VMM enters at _start32 as PVH says (the ELF note
// below): 32-bit protected mode, flat segments, paging off, at physical
// addresses. We map the first 4 GiB (RAM and the devices) twice with 2 MiB
// pages, at 0 (until we've jumped) and at KERNEL_OFFSET (linker.ld), turn
// long mode on, and go to the high half. Nothing here is global: the low
// mapping must not outlive the boot (or a secondary CPU's: they come the
// same way, below, and leave the boot tables for the empty root at once).

    .pushsection .note.Xen, "a", @note
    .p2align 2
    .long 4                 // namesz
    .long 4                 // descsz
    .long 18                // XEN_ELFNOTE_PHYS32_ENTRY
    .asciz "Xen"
    .long _start32
    .popsection

    .pushsection .text.boot, "ax"
    .code32
    .globl _start32
_start32:
    cli
    cld
    // The tables are in .bss.boot, which the loader zeroed.
    movl $boot_pdpt + 3, %eax
    movl %eax, boot_pml4
    movl %eax, boot_pml4 + 256 * 8
    movl %eax, empty_pml4 + 256 * 8
    movl $boot_pd + 3, %eax
    xorl %ecx, %ecx
1:  movl %eax, boot_pdpt(, %ecx, 8)
    addl $4096, %eax
    incl %ecx
    cmpl $4, %ecx
    jb 1b
    // 2048 2 MiB pages: present, writable, large.
    xorl %ecx, %ecx
2:  movl %ecx, %eax
    shll $21, %eax
    orl $0x83, %eax
    movl %eax, boot_pd(, %ecx, 8)
    movl %ecx, %edx
    shrl $11, %edx
    movl %edx, boot_pd + 4(, %ecx, 8)
    incl %ecx
    cmpl $2048, %ecx
    jb 2b

    xorl %ebp, %ebp         // CPU 0
long_mode:
    movl $boot_pml4, %eax
    movl %eax, %cr3
    movl %cr4, %eax
    orl $0x20, %eax         // PAE
    movl %eax, %cr4
    movl $0xc0000080, %ecx  // EFER: long mode, no-execute, syscall
    rdmsr
    orl $0x901, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80010001, %eax   // paging, write protect (in the kernel too), protection
    movl %eax, %cr0
    lgdt boot_gdtr
    ljmp $0x08, $start64

    .code64
start64:
    movl $0x10, %eax
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %ss
    xorl %eax, %eax
    movl %eax, %fs
    movl %eax, %gs
    movabsq $start_high, %rax
    testl %ebp, %ebp
    jz 1f
    movabsq $ap_high, %rax
1:  jmp *%rax

    .p2align 3
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff    // 64-bit code
    .quad 0x00cf92000000ffff    // data
boot_gdtr:
    .short boot_gdtr - boot_gdt - 1
    .long boot_gdt

// The other CPUs. CPU 0 copies ap_trampoline..ap_trampoline_end to
// AP_TRAMPOLINE (physical, page-aligned, below 1 MiB: a startup IPI's
// vector is its page) and starts each with INIT and a startup IPI there
// (`irq::start_ap`). It runs in real mode at CS = AP_TRAMPOLINE >> 4, so
// its addresses are relative to it: into 32-bit protected mode with a
// flat GDT of its own, then into long mode with the boot tables, as CPU 0
// came.
    .set AP_TRAMPOLINE, 0x8000
    .code16
    .globl ap_trampoline
ap_trampoline:
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    lgdtl (ap_gdtr - ap_trampoline)
    movl %cr0, %eax
    orl $1, %eax
    movl %eax, %cr0
    ljmpl $0x08, $(AP_TRAMPOLINE + ap_trampoline32 - ap_trampoline)
    .code32
ap_trampoline32:
    movl $0x10, %eax
    movl %eax, %ds
    movl %eax, %es
    movl %eax, %ss
    movl $1, %ebp           // not CPU 0
    movl $long_mode, %eax
    jmp *%eax
    .p2align 3
ap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff    // 32-bit code
    .quad 0x00cf92000000ffff    // data
ap_gdtr:
    .short ap_gdtr - ap_gdt - 1
    .long AP_TRAMPOLINE + ap_gdt - ap_trampoline
    .globl ap_trampoline_end
ap_trampoline_end:
    .code64
    .popsection

    .pushsection .bss.boot, "aw", @nobits
    .p2align 12
    .globl boot_pml4
    .globl empty_pml4
boot_pml4:  .space 4096
// A root with only the kernel's half: what a CPU with no process holds.
empty_pml4: .space 4096
boot_pdpt:  .space 4096
boot_pd:    .space 4 * 4096
    .popsection

    .pushsection .text, "ax"
start_high:
    movabsq $__stack_top, %rsp
    movabsq $__bss_start, %rdi
    movabsq $__bss_end, %rcx
    subq %rdi, %rcx
    xorl %eax, %eax
    rep stosb
    call arch_init
    call kernel_main
    ud2

// A secondary CPU in the high half: its number is its APIC ID; its
// stack, its frame at the top (smp::secondary_main), Rust below it.
ap_high:
    movl $1, %eax
    cpuid
    shrl $24, %ebx
    movl %ebx, %edi
    leaq 1(%rbx), %rax
    shlq $16, %rax              // STACK_SIZE
    movabsq $__stacks, %rsi
    addq %rax, %rsi
    subq $192, %rsi             // size_of::<TrapFrame>()
    movq %rsi, %rsp
    andq $-16, %rsp
    call ap_main
    ud2

// The trampoline's place and size (physical, as above).
    .globl ap_trampoline_phys
ap_trampoline_phys:
    movabsq $ap_trampoline, %rax
    ret
    .globl ap_trampoline_len
ap_trampoline_len:
    movabsq $(ap_trampoline_end - ap_trampoline), %rax
    ret

// The boot tables' addresses (physical: they're linked where they're
// loaded, too far from the kernel's code for RIP-relative references).
    .globl boot_pml4_phys
boot_pml4_phys:
    movabsq $boot_pml4, %rax
    ret
    .globl empty_pml4_phys
empty_pml4_phys:
    movabsq $empty_pml4, %rax
    ret
    .popsection
