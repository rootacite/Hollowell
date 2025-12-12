
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
    movq    %rsp, _pargc(%rip)
    movq    %rsp, %rdi
    movq    (%rdi), %rdi
    incq    %rdi
    imulq   $8, %rdi, %rdi
    movq    %rsp, %rsi
    addq    $8, %rsi
    addq    %rdi, %rsi
    movq    %rsi, _envp(%rip)

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
    pushq   %rdx

    movq    _auxv(%rip), %rdi
    call    loader

    popq   %rdx
    movq    %rbp, %rsp
    popq    %rbp

    test    %rax, %rax
    je      .Lexit
    jmp     *%rax

.Lexit:
    mov     $60, %rax
    mov     $0, %rdi
    syscall

main:
    ret