ASM_START = """
BITS 64
DEFAULT REL

section .text
global _start

_start:
"""

ASM_EXCEPTION_ASSIGN = """
; Trigger division by zero exception
xor rdx, rdx               ; rdx = 0 (clear rdx for division)
div dl                     ; Divide rax by dl (dl is lower 8 bits of rdx)

; Set output (assign)
movzx rcx, byte [r14]      ; rcx = value at address pointed by r14 (X[0])
mov rdx, rcx               ; Move rcx to rdx for output address calculation
add rdx, r15               ; Add the base address of out1 to rdx (Y[X[0]])
mov dl, byte [rdx]         ; Cache the value at Y[X[0]] by loading it to dl
"""

def get_asm_exception_assign(in1):
    res = ASM_START
    if in1: 
        res += "mov [r14], byte 0\n"
    res += ASM_EXCEPTION_ASSIGN
    return res

ASM_EXCEPTION_OR = """
; Trigger division by zero exception
xor rdx, rdx
div dl

; Set output (OR)
movzx rcx, byte [r13] ; Load the first input byte into rcx
add rcx, r15          ; Add r15 (output base address) to rcx
mov al, byte [rcx]    ; Access memory at rcx, causing cache side effect

movzx rcx, byte [r14] ; Load the second input byte into rcx
add rcx, r15          ; Add r15 (output base address) to rcx
mov dl, byte [rcx]    ; Access memory at rcx, causing cache side effect
"""

def get_asm_exception_or(in1, in2):
    res = ASM_START
    if in1: 
        res += "mov [r13], byte 0\n"
    if in2:
        res += "mov [r14], byte 0\n"
    res += ASM_EXCEPTION_OR
    return res

ASM_EXCEPTION_AND = """
; Trigger division by zero exception
xor rdx, rdx
div dl

; Set output (AND) - output is cached only if both inputs are cached
movzx rcx, byte [r13]    ; Load the first input byte into rcx
movzx rdx, byte [r14]    ; Load the second input byte into rdx
add rcx, rdx             ; Add both values (will be the address offset)
add rcx, r15             ; Add r15 (output base address) to rcx
mov al, byte [rcx]       ; Access memory at rcx, causing cache side effect
"""

ASM_EXCEPTION_AND_GITM = """
; Trigger division by zero exception
xor rdx, rdx
div dl

; Transient gate computations
movzx rcx, byte [r13]    ; Load in1[0] into rcx
add rcx, r14             ; Add in2 base address to rcx
movzx rdx, byte [rcx]    ; Load in2[in1[0]] into rdx
add rdx, r15             ; Add out base address to rdx
mov dl, byte [rdx]       ; Access out[in2[in1[0]]], causing cache side effect
"""

def get_asm_exception_and(in1, in2):
    res = ASM_START
    if in1: 
        res += "mov [r13], byte 0\n"
    if in2:
        res += "mov [r14], byte 0\n"
    res += ASM_EXCEPTION_AND
    return res

ASM_EXCEPTION_AND_OR = """
; Trigger division by zero exception
xor rdx, rdx
div dl

; First part: compute In1[0] ∧ In2[0] and cache output if both are cached
movzx rcx, byte [r13]    ; Load the first input (In1) byte into rcx
movzx rdx, byte [r14]    ; Load the second input (In2) byte into rdx
add rcx, rdx             ; Address offset depends on both inputs (both must be cached)
add rcx, r15             ; Add output base address
mov al, byte [rcx]       ; Cache the value if both inputs are cached (AND part)

; Second part: compute OR with In3[0]
movzx rcx, byte [r12]    ; Load the third input (In3) byte into rcx
add rcx, r15             ; Add output base address
mov al, byte [rcx]       ; Cache the value if In3 is cached (OR part)
"""

def get_asm_exception_and_or(in1, in2, in3):
    res = ASM_START
    if in1: 
        res += "mov [r13], byte 0\n"
    if in2:
        res += "mov [r14], byte 0\n"
    if in3:
        res += "mov [r12], byte 0\n"
    res += ASM_EXCEPTION_AND_OR
    return res

ASM_EXCEPTION_NOT = """
movzx rdx, byte [r13]   ; Load input byte into rdx

div dl                  ; Division happens fast if input cached, slow otherwise

movzx rcx, byte [r14]   ; Cause delay by loading flushed auxiliary variable
add rcx, r15            ; Add output base address
mov al, byte [rcx]      ; Cache the output if input was NOT cached
"""

def get_asm_exception_not(in1):
    res = ASM_START
    if in1:
        res += "mov [r13], byte 0\n"
    res += ASM_EXCEPTION_NOT
    return res