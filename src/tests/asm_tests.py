from emulator import MuWMEmulator
from loader import AsmLoader
from gates.asm import *
from unicorn.x86_const import *

def emulate_asm_assign(in1, debug=False):
    code = get_asm_exception_assign(in1)
    loader = AsmLoader(code)
    emulator = MuWMEmulator(name='assign', loader=loader, debug=debug)

    # Set input and output addresses of assign gate
    input_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R14, input_address)
    output_address = emulator.data_start_addr + emulator.cache.line_size  # makes sure output goes in different cache set than input
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def emulate_asm_or(in1, in2, debug=False):
    code = get_asm_exception_or(in1, in2)
    loader = AsmLoader(code)
    emulator = MuWMEmulator(name='or', loader=loader, debug=debug)

    emulator.logger.log(f"Starting emulation of OR({in1}, {in2})...")

    # Set input and output addresses of OR gate
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

def emulate_asm_and(in1, in2, debug=False):
    code = get_asm_exception_and(in1, in2)
    loader = AsmLoader(code)
    emulator = MuWMEmulator(name='and', loader=loader, debug=debug)

    emulator.logger.log(f"Starting emulation of AND({in1}, {in2})...")

    # Set input and output addresses of AND gate
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    output_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    emulator.logger.log(f"Output value: {emulator.cache.is_cached(output_address)}")

    return emulator.cache.is_cached(output_address)

# Test Out[0] = (In1[0] ∧ In2[0]) ∨ In3[0]
def emulate_asm_and_or(in1, in2, in3, debug=False):
    code = get_asm_exception_and_or(in1, in2, in3)
    loader = AsmLoader(code)
    emulator = MuWMEmulator(name='and_or', loader=loader, debug=debug)

    emulator.logger.log(f"Starting emulation of AND-OR({in1}, {in2}, {in3})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)
    
    input3_address = emulator.data_start_addr + 2 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R12, input3_address)
    
    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    result = emulator.cache.is_cached(output_address)
    emulator.logger.log(f"Output value: {result}")

    return result

def emulate_asm_not(in1, debug=False):
    code = get_asm_exception_not(in1)
    loader = AsmLoader(code)
    emulator = MuWMEmulator(name='not', loader=loader, debug=debug)

    emulator.logger.log(f"Starting emulation of NOT({in1})...")

    # Set input and output addresses
    input1_address = emulator.data_start_addr
    emulator.uc.reg_write(UC_X86_REG_R13, input1_address)
    
    input2_address = emulator.data_start_addr + emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R14, input2_address)

    output_address = emulator.data_start_addr + 3 * emulator.cache.line_size
    emulator.uc.reg_write(UC_X86_REG_R15, output_address)

    emulator.emulate()

    result = emulator.cache.is_cached(output_address)
    emulator.logger.log(f"Output value: {result}")

    return result