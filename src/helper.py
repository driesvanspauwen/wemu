from unicorn.x86_const import *
from typing import Set

# Global mapping of x86 register families - each list contains registers that alias
X86_REG_FAMILIES = {
    'rax': [UC_X86_REG_RAX, UC_X86_REG_EAX, UC_X86_REG_AX, UC_X86_REG_AH, UC_X86_REG_AL],
    'rbx': [UC_X86_REG_RBX, UC_X86_REG_EBX, UC_X86_REG_BX, UC_X86_REG_BH, UC_X86_REG_BL],
    'rcx': [UC_X86_REG_RCX, UC_X86_REG_ECX, UC_X86_REG_CX, UC_X86_REG_CH, UC_X86_REG_CL],
    'rdx': [UC_X86_REG_RDX, UC_X86_REG_EDX, UC_X86_REG_DX, UC_X86_REG_DH, UC_X86_REG_DL],
    'rsi': [UC_X86_REG_RSI, UC_X86_REG_ESI, UC_X86_REG_SI, UC_X86_REG_SIL],
    'rdi': [UC_X86_REG_RDI, UC_X86_REG_EDI, UC_X86_REG_DI, UC_X86_REG_DIL],
    'rsp': [UC_X86_REG_RSP, UC_X86_REG_ESP, UC_X86_REG_SP, UC_X86_REG_SPL],
    'rbp': [UC_X86_REG_RBP, UC_X86_REG_EBP, UC_X86_REG_BP, UC_X86_REG_BPL],
    'r8': [UC_X86_REG_R8, UC_X86_REG_R8D, UC_X86_REG_R8W, UC_X86_REG_R8B],
    'r9': [UC_X86_REG_R9, UC_X86_REG_R9D, UC_X86_REG_R9W, UC_X86_REG_R9B],
    'r10': [UC_X86_REG_R10, UC_X86_REG_R10D, UC_X86_REG_R10W, UC_X86_REG_R10B],
    'r11': [UC_X86_REG_R11, UC_X86_REG_R11D, UC_X86_REG_R11W, UC_X86_REG_R11B],
    'r12': [UC_X86_REG_R12, UC_X86_REG_R12D, UC_X86_REG_R12W, UC_X86_REG_R12B],
    'r13': [UC_X86_REG_R13, UC_X86_REG_R13D, UC_X86_REG_R13W, UC_X86_REG_R13B],
    'r14': [UC_X86_REG_R14, UC_X86_REG_R14D, UC_X86_REG_R14W, UC_X86_REG_R14B],
    'r15': [UC_X86_REG_R15, UC_X86_REG_R15D, UC_X86_REG_R15W, UC_X86_REG_R15B],
}

def registers_alias(reg1: int, reg2: int) -> bool:
    """
    Determines if two registers alias (share physical storage).
    For example, dl is an 8-bit subset of rdx.
    """
    # Find which family each register belongs to
    reg1_family = None
    reg2_family = None
    for family, regs in X86_REG_FAMILIES.items():
        if reg1 in regs:
            reg1_family = family
        if reg2 in regs:
            reg2_family = family
        if reg1_family and reg2_family:
            break
    
    # If both registers are from the same family, they alias
    return reg1_family is not None and reg1_family == reg2_family

def get_register_aliases(reg_id: int) -> Set[int]:
    """
    Get all register aliases (including the register itself) for a given register ID.
    Returns a set of register IDs that alias with the input register.
    """
    # Find the family that contains this register
    for family, regs in X86_REG_FAMILIES.items():
        if reg_id in regs:
            return set(regs)
    
    # If register is not found in any family, return just the register itself
    return {reg_id}

def compare_runs(function, inputs):
    """
    Can be used to show determinism of the emulator.
    """
    result1 = function(*inputs)
    result2 = function(*inputs)
    
    if result1 != result2:
        print(f"Non-deterministic result: {result1} vs {result2}")
    else:
        print(f"Consistent result: {result1} for inputs {inputs}")

def verify_memory_layout(emulator):
    """Verify memory regions don't overlap"""
    regions = []
    
    # Add all mapped regions
    for region in emulator.uc.mem_regions():
        start, end, perms = region
        regions.append((start, end, "mapped"))
    
    # Sort by start address
    regions.sort(key=lambda x: x[0])
    
    # Check for overlaps
    for i in range(len(regions) - 1):
        if regions[i][1] > regions[i+1][0]:
            print(f"WARNING: Memory overlap detected!")
            print(f"  Region 1: 0x{regions[i][0]:x} - 0x{regions[i][1]:x}")
            print(f"  Region 2: 0x{regions[i+1][0]:x} - 0x{regions[i+1][1]:x}")