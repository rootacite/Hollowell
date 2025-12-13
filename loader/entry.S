
# entry.S

.global _emain
.global main
.hidden main

.section .data, "aw", @progbits
_envp:
.8byte 0
_auxv:
.8byte 0
_pargc:
.8byte 0

.text

_emain:
    pushq   %rdi
    pushq   %rsi
    pushq   %rcx
    pushq   %rdx

    addq    $32, %rsp

    movq    %rsp, _pargc(%rip)
    movq    %rsp, %rdi
    movq    (%rdi), %rdi
    incq    %rdi
    imulq   $8, %rdi, %rdi
    movq    %rsp, %rsi
    addq    $8, %rsi
    addq    %rdi, %rsi
    movq    %rsi, _envp(%rip)

    subq    $32, %rsp
.Lauxv_loop:
    movq    (%rsi), %rdi
    test    %rdi, %rdi
    je     .Lauxv
    addq    $8, %rsi
    jmp    .Lauxv_loop

.Lauxv:
    addq    $8, %rsi
    movq    %rsi, _auxv(%rip)

    pushq   %rbp
    movq    %rsp, %rbp

    sub     $16, %rsp
    andq    $0xfffffffffffffff0, %rsp
    movq    _auxv(%rip), %rdi
    call    loader

    movq    %rbp, %rsp
    popq    %rbp

    popq    %rdx
    popq    %rcx
    popq    %rsi
    popq    %rdi

    test    %rax, %rax
    je      .Lexit
    int3
    jmp     *%rax

.Lexit:
    mov     $60, %rax
    mov     $0, %rdi
    syscall

main:
    ret
