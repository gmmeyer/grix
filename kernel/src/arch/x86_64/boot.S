// Boot, x86_64. The VMM enters at _start32 as PVH says (the ELF note
// below): 32-bit protected mode, flat segments, paging off, at physical
// addresses. We map the first 4 GiB (RAM and the devices) twice with 2 MiB
// pages, at 0 (until we've jumped) and at KERNEL_OFFSET (linker.ld), turn
// long mode on, and go to the high half. Nothing here is global: the low
// mapping must not outlive the boot.

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
    jmp *%rax

    .p2align 3
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff    // 64-bit code
    .quad 0x00cf92000000ffff    // data
boot_gdtr:
    .short boot_gdtr - boot_gdt - 1
    .long boot_gdt
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
