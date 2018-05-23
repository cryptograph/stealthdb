%macro DEF 1
  global %1:function
  %1:
%endmacro

section .text

DEF obs_int32_eq
    xor eax, eax
    cmp edi, esi
    sete al
    ret

DEF obs_int32_lt
    xor eax, eax
    cmp edi, esi
    setl al
    ret

DEF obs_int32_select
    test edx, edx
    cmovne edi, esi
    mov eax, edi
    ret

obs_int32_bits:
  xor eax, eax
  cmp edi, 65535
  seta al
  shl eax, 4
  mov ecx, eax
  shr edi, cl
  xor edx, edx
  cmp edi, 255
  seta dl
  lea ecx, [8*rdx]
  shr edi, cl
  lea eax, [rax + 8*rdx]
  xor edx, edx
  cmp edi, 15
  seta dl
  lea ecx, [4*rdx]
  shr edi, cl
  lea eax, [rax + 4*rdx]
  xor edx, edx
  cmp edi, 3
  seta dl
  lea ecx, [rdx + rdx]
  shr edi, cl
  lea eax, [rax + 2*rdx]
  shr edi, 1
  or eax, edi
  ret

DEF obs_int32_pow
  push r14
  push rbx

  mov r14d, edi
  mov edi, esi
  call obs_int32_bits
  mov edi, r14d
  mov r14d, eax

  mov eax, 1

  .loop:
    mov ebx, 1
    mov ecx, r14d
    shl ebx, cl
    and ebx, esi

    mov r8d, eax

    imul eax, eax
    imul r8d, edi
    imul edi, edi

    xor edx, edx
    test ebx, ebx
    setne dl
    neg edx
    mov ebx, edx

    and ebx, r8d
    mov ecx, edx
    not ecx
    and eax, ecx
    or eax, ebx

    and edx, edi
    and ecx, r8d
    or ecx, edx

    test r14d, r14d

    lea edx, [r14 - 1]
    mov r14d, edx
    mov edi, ecx
  jg .loop

  pop rbx
  pop r14
  ret
