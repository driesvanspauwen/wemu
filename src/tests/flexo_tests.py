import struct
from typing import Tuple, Dict
from cache import LRUCache
from emulator import MuWMEmulator
from loader import ELFLoader
from unicorn import UC_HOOK_CODE, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE
from unicorn.x86_const import *
import time
import struct
from random import randint
from tests.ref.ref import *

# -------------------------------------------------------------------
# Generic helpers
# -------------------------------------------------------------------

OUT_ADDR_BOOL = 0x1000_0000
PAGE_SIZE       = 0x1000
IN1_ADDR_ARB    = 0x2000_0000
IN2_ADDR_ARB    = 0x2000_1000
OUT_ADDR_ARB    = 0x2000_2000
ERR_ADDR_ARB    = 0x2000_3000

def _ensure_memory(emulator: MuWMEmulator, addr: int, size: int = PAGE_SIZE, init_zero: bool = True):
    """
    Ensure that `addr` is mapped in the emulator's address space.
    Optionally initialize it to zero if `init_zero` is True.
    """
    try:
        emulator.uc.mem_read(addr, 1)
    except:
        emulator.logger.log(f"Mapping memory at {addr:#x}")
        emulator.uc.mem_map(addr, size, UC_PROT_ALL)
    if init_zero:
        emulator.uc.mem_write(addr, b'\x00' * size)

def _hook_rand_once(emulator: MuWMEmulator, rand_addr: int):
    """
    Install a hook that intercepts a single call to rand@plt at `rand_addr`
    and forces RAX to a fixed value, then skips the call instruction.
    """
    def _hook(uc, address, size, user_data):
        if address == rand_addr:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False

    emulator.uc.hook_add(UC_HOOK_CODE, _hook, None, rand_addr, rand_addr + 1)

def _emulate_boolean_gate(
    name: str,
    elf_path: str,
    start_addr: int,
    end_addr: int,
    rand_addr: int,
    regs_setup: Dict[int, int],
    debug: bool = False
) -> int:
    """
    Generic emulator function for boolean gates (AND, OR, NOT, NAND, XOR, XOR3, XOR4, MUX).
    - name: name to label the emulator instance
    - elf_path: path to the gate's ELF file
    - start_addr, end_addr: code boundaries for emulation
    - rand_addr: address of the rand@plt call to hook
    - regs_setup: mapping from unicorn register constants to their values
    Returns the single-byte result read from OUT_ADDR_BOOL.
    """
    # Create loader and emulator
    loader = ELFLoader(elf_path)
    emulator = MuWMEmulator(name=name, loader=loader, debug=debug)
    emulator.code_start_address = start_addr
    emulator.code_exit_addr = end_addr

    # Ensure output memory is mapped and zeroed
    _ensure_memory(emulator, OUT_ADDR_BOOL)

    # Hook rand@plt to be deterministic
    _hook_rand_once(emulator, rand_addr)

    # Write inputs/register values
    for reg, val in regs_setup.items():
        emulator.uc.reg_write(reg, val)

    # Run emulation
    emulator.emulate()

    # Read back a single byte at the output address
    result_byte = emulator.uc.mem_read(OUT_ADDR_BOOL, 1)[0]
    return int(result_byte)


def emulate_flexo_and(in1: int, in2: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-and",
        elf_path="gates/flexo/gates/gate_and.elf",
        start_addr=0x11e0,
        end_addr=0x13fb,
        rand_addr=0x11f9,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_or(in1: int, in2: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-or",
        elf_path="gates/flexo/gates/gate_or.elf",
        start_addr=0x1400,
        end_addr=0x161b,
        rand_addr=0x1419,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_not(in1: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-not",
        elf_path="gates/flexo/gates/gate_not.elf",
        start_addr=0x1620,
        end_addr=0x17d5,
        rand_addr=0x1632,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_nand(in1: int, in2: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-nand",
        elf_path="gates/flexo/gates/gate_nand.elf",
        start_addr=0x17e0,
        end_addr=0x19fb,
        rand_addr=0x17f9,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_xor(in1: int, in2: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-xor",
        elf_path="gates/flexo/gates/gate_xor.elf",
        start_addr=0x1a00,
        end_addr=0x1c1b,
        rand_addr=0x1a19,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_xor3(in1: int, in2: int, in3: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-xor3",
        elf_path="gates/flexo/gates/gate_xor3.elf",
        start_addr=0x1ed0,
        end_addr=0x2172,
        rand_addr=0x1ef2,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: in3 & 0x1,
            UC_X86_REG_RCX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_xor4(in1: int, in2: int, in3: int, in4: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-xor4",
        elf_path="gates/flexo/gates/gate_xor4.elf",
        start_addr=0x2180,
        end_addr=0x24b3,
        rand_addr=0x21ab,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: in3 & 0x1,
            UC_X86_REG_RCX: in4 & 0x1,
            UC_X86_REG_R8:  OUT_ADDR_BOOL,
        },
        debug=debug
    )


def emulate_flexo_mux(in1: int, in2: int, sel: int, debug: bool = False) -> int:
    return _emulate_boolean_gate(
        name="flexo-mux",
        elf_path="gates/flexo/gates/gate_mux.elf",
        start_addr=0x1c20,
        end_addr=0x1ec2,
        rand_addr=0x1c42,
        regs_setup={
            UC_X86_REG_RDI: in1 & 0x1,
            UC_X86_REG_RSI: in2 & 0x1,
            UC_X86_REG_RDX: sel & 0x1,
            UC_X86_REG_RCX: OUT_ADDR_BOOL,
        },
        debug=debug
    )


def _emulate_adder(
    name: str,
    elf_path: str,
    start_addr: int,
    end_addr: int,
    rand_addr: int,
    a: int,
    b: int,
    byte_width: int,
    debug: bool = False
) -> Tuple[int, int]:
    """
    Generic emulator for n-bit adders produced by the weird-machine.
    - name: emulator name
    - elf_path: path to the adder ELF
    - start_addr, end_addr: code boundaries for emulation
    - rand_addr: address of the rand@plt call to hook
    - a, b: integer operands
    - byte_width: how many bytes to write/read for the result
    Returns a tuple (sum, error_flag), where `sum` is the integer result (low `byte_width` bytes),
    and `error_flag` is a single byte read from the error-output region.
    """
    # Addresses for code and data (shared for all adders)
    loader = ELFLoader(elf_path)
    emulator = MuWMEmulator(name=name, loader=loader, debug=debug)
    emulator.code_start_address = start_addr
    emulator.code_exit_addr = end_addr

    # Ensure memory regions for inputs, outputs, and error flags
    for addr in (IN1_ADDR_ARB, IN2_ADDR_ARB, OUT_ADDR_ARB, ERR_ADDR_ARB):
        _ensure_memory(emulator, addr, size=PAGE_SIZE, init_zero=False)

    # Prepare input buffers: only low `byte_width` bytes carry the value
    in1_bytes = (a & ((1 << (8 * byte_width)) - 1)).to_bytes(byte_width, 'little') + b'\x00' * (8 - byte_width)
    in2_bytes = (b & ((1 << (8 * byte_width)) - 1)).to_bytes(byte_width, 'little') + b'\x00' * (8 - byte_width)
    emulator.uc.mem_write(IN1_ADDR_ARB,     in1_bytes)
    emulator.uc.mem_write(IN2_ADDR_ARB,     in2_bytes)
    emulator.uc.mem_write(OUT_ADDR_ARB,     b'\x00' * 8)
    emulator.uc.mem_write(ERR_ADDR_ARB,     b'\x00' * 8)

    # Hook rand@plt for determinism
    _hook_rand_once(emulator, rand_addr)

    # Set up registers (RDI, RSI, RDX, RCX) to point to memory buffers
    emulator.uc.reg_write(UC_X86_REG_RDI, IN1_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RSI, IN2_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERR_ADDR_ARB)

    # Run emulation
    emulator.emulate()

    # Read result (low `byte_width` bytes) and error flag (1 byte)
    result = int.from_bytes(emulator.uc.mem_read(OUT_ADDR_ARB, byte_width), 'little')
    error_flag = emulator.uc.mem_read(ERR_ADDR_ARB, 1)[0]
    return result, error_flag


def emulate_flexo_adder8(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    return _emulate_adder(
        name="flexo-adder8",
        elf_path="gates/flexo/arithmetic/adder.elf",
        start_addr=0x1270,
        end_addr=0x362e,
        rand_addr=0x12a0,
        a=a,
        b=b,
        byte_width=1,
        debug=debug
    )


def emulate_flexo_adder16(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    return _emulate_adder(
        name="flexo-adder16",
        elf_path="gates/flexo/arithmetic/adder.elf",
        start_addr=0x3630,
        end_addr=0x94da,
        rand_addr=0x3660,
        a=a,
        b=b,
        byte_width=2,
        debug=debug
    )


def emulate_flexo_adder32(a: int, b: int, debug: bool = False) -> Tuple[int, int]:
    # The 32-bit adder uses a slightly different memory mapping (unmapping then mapping)
    ADDER_START_ADDR = 0x94e0
    ADDER_END_ADDR   = 0x16bd1
    RAND_CALL_ADDR   = 0x9510

    loader = ELFLoader("gates/flexo/arithmetic/adder.elf")
    emulator = MuWMEmulator(name="flexo-adder32", loader=loader, debug=debug)
    emulator.code_start_address = ADDER_START_ADDR
    emulator.code_exit_addr = ADDER_END_ADDR

    # For 32-bit, explicitly unmap then remap to set correct protections
    for addr in (IN1_ADDR_ARB, IN2_ADDR_ARB, OUT_ADDR_ARB, ERR_ADDR_ARB):
        try:
            emulator.uc.mem_unmap(addr, PAGE_SIZE)
        except:
            pass
        emulator.uc.mem_map(addr, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    # Write inputs (4-byte values, low 4 bytes)
    in1 = (a & 0xFFFFFFFF).to_bytes(4, 'little') + b'\x00' * 4
    in2 = (b & 0xFFFFFFFF).to_bytes(4, 'little') + b'\x00' * 4
    emulator.uc.mem_write(IN1_ADDR_ARB, in1)
    emulator.uc.mem_write(IN2_ADDR_ARB, in2)
    emulator.uc.mem_write(OUT_ADDR_ARB,  b'\x00' * 8)
    emulator.uc.mem_write(ERR_ADDR_ARB,  b'\x00' * 8)

    # Hook rand
    _hook_rand_once(emulator, RAND_CALL_ADDR)

    # Set up registers
    emulator.uc.reg_write(UC_X86_REG_RDI, IN1_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RSI, IN2_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUT_ADDR_ARB)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERR_ADDR_ARB)

    emulator.emulate()

    result = int.from_bytes(emulator.uc.mem_read(OUT_ADDR_ARB, 4), 'little')
    error_flag = emulator.uc.mem_read(ERR_ADDR_ARB, 1)[0]
    return result, error_flag


# -------------------------------------------------------------------
# Crypto emulations
# -------------------------------------------------------------------

def emulate_flexo_sha1_round(state_in, w_in, debug=False):
    INPUT_ADDR       = 0x200000
    OUTPUT_ADDR      = 0x202000
    ERROR_OUTPUT_ADDR= 0x203000
    PAGE_SIZE_LOCAL  = 0x1000

    WEIRD_SHA1_ADDR  = 0x1550
    RAND_CALL_ADDR   = 0x157f
    SHA1_RET_ADDR    = 0x28e73

    loader   = ELFLoader("gates/flexo/sha1/sha1_round.elf")
    emulator = MuWMEmulator(name='flexo-sha1', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_SHA1_ADDR
    emulator.code_exit_addr      = SHA1_RET_ADDR

    # Map memory for inputs/outputs
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE_LOCAL)

    # Write input state (5 × uint32) at INPUT_ADDR
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<5I", *state_in))

    # Set up registers: rdi=input, rsi=w, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, w_in)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)

    # Hook rand@plt
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_SHA1_ADDR, SHA1_RET_ADDR)

    emulator.emulate()

    # Read 5 × uint32 from OUTPUT_ADDR and ERROR_OUTPUT_ADDR
    result = list(struct.unpack("<5I", emulator.uc.mem_read(OUTPUT_ADDR, 20)))
    err_out= list(struct.unpack("<5I", emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 20)))

    return result, err_out


def emulate_flexo_aes_round(input_block, key_block, debug=False):
    INPUT_ADDR        = 0x200000
    KEY_ADDR          = 0x201000
    OUTPUT_ADDR       = 0x202000
    ERROR_OUTPUT_ADDR = 0x203000
    PAGE_SIZE_LOCAL   = 0x1000

    WEIRD_AES_ADDR    = 0x1c30
    RAND_CALL_ADDR    = 0x1c60
    AES_RET_ADDR      = 0xb4f44

    loader   = ELFLoader("gates/flexo/aes/aes_round-16.elf")
    emulator = MuWMEmulator(name='flexo-aes', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_AES_ADDR
    emulator.code_exit_addr      = AES_RET_ADDR

    emulator.uc.mem_map(INPUT_ADDR,        PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(KEY_ADDR,          PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(OUTPUT_ADDR,       PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE_LOCAL)

    emulator.uc.mem_write(INPUT_ADDR,  bytes(input_block))
    emulator.uc.mem_write(KEY_ADDR,    bytes(key_block))

    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, KEY_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)

    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_AES_ADDR, AES_RET_ADDR)

    emulator.emulate()

    result = list(emulator.uc.mem_read(OUTPUT_ADDR, 16))
    err_out= list(emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 16))
    return result, err_out


def emulate_flexo_simon32(input_block, key_block, debug=False):
    INPUT_ADDR        = 0x200000
    KEY_ADDR          = 0x201000
    OUTPUT_ADDR       = 0x202000
    ERROR_OUTPUT_ADDR = 0x203000
    PAGE_SIZE_LOCAL   = 0x1000

    WEIRD_SIMON_ADDR  = 0x1440
    RAND_CALL_ADDR    = 0x1470
    SIMON_RET_ADDR    = 0x116246

    loader   = ELFLoader("gates/flexo/simon/simon32-14.elf")
    emulator = MuWMEmulator(name='flexo-simon32', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_SIMON_ADDR
    emulator.code_exit_addr      = SIMON_RET_ADDR

    emulator.uc.mem_map(INPUT_ADDR,        PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(KEY_ADDR,          PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(OUTPUT_ADDR,       PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE_LOCAL)

    emulator.uc.mem_write(INPUT_ADDR,  bytes(input_block))
    emulator.uc.mem_write(KEY_ADDR,    bytes(key_block))

    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, KEY_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)

    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_SIMON_ADDR, SIMON_RET_ADDR)

    emulator.emulate()

    result = list(emulator.uc.mem_read(OUTPUT_ADDR, 4))
    err_out= list(emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 4))
    return result, err_out

def emulate_flexo_alu(x_data, y_data, control_data, debug=False):
    """Emulate the Flexo ALU - you'll need to implement this based on your emulator setup"""
    
    INPUT_X_ADDR = 0x200000
    INPUT_Y_ADDR = 0x201000
    INPUT_CONTROL_ADDR = 0x202000
    OUTPUT_ADDR = 0x203000
    ERROR_OUTPUT_ADDR = 0x204000
    PAGE_SIZE_LOCAL = 0x1000
    WEIRD_ALU_ADDR = 0x12d0    # From your objdump output
    ALU_RET_ADDR = 0x3a28      # From your objdump output
    
    loader = ELFLoader("gates/flexo/alu/ALU-2.elf")  # Update path
    emulator = MuWMEmulator(name='flexo-alu', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_ALU_ADDR
    emulator.code_exit_addr = ALU_RET_ADDR
    
    # Map memory for inputs/outputs
    emulator.uc.mem_map(INPUT_X_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(INPUT_Y_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(INPUT_CONTROL_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(OUTPUT_ADDR, PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR, PAGE_SIZE_LOCAL)
    
    # Write input data (1 byte each)
    emulator.uc.mem_write(INPUT_X_ADDR, bytes([x_data]))
    emulator.uc.mem_write(INPUT_Y_ADDR, bytes([y_data]))
    emulator.uc.mem_write(INPUT_CONTROL_ADDR, bytes([control_data]))
    
    # Set up registers: rdi=x, rsi=y, rdx=control, rcx=out, r8=error_out
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_X_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, INPUT_Y_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, INPUT_CONTROL_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_R8, ERROR_OUTPUT_ADDR)
    
    # Hook rand@plt call (from your objdump, there's a rand call at 1307)
    RAND_CALL_ADDR = 0x1307
    emulator.rsb.add_exception_addr(RAND_CALL_ADDR)
    
    def hook_rand_call(uc, address, size, user_data):
        if address == RAND_CALL_ADDR:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        return False
    
    emulator.uc.hook_add(UC_HOOK_CODE, hook_rand_call, None, WEIRD_ALU_ADDR, ALU_RET_ADDR)
    
    emulator.emulate()
    
    # Read 1 byte from OUTPUT_ADDR and ERROR_OUTPUT_ADDR
    result = emulator.uc.mem_read(OUTPUT_ADDR, 1)[0]
    err_out = emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 1)[0]
    
    return result, err_out

def emulate_flexo_sha1_2blocks(block1, block2, debug=False):
    INPUT_ADDR   = 0x200000
    STATES_ADDR  = 0x201000
    PAGE_SIZE_LOCAL = 0x1000

    SHA1_BLOCK_ADDR      = 0xa2820
    SHA1_BLOCK_RET_ADDR  = 0xa2cdf

    loader   = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-2blocks', loader=loader, debug=debug)

    # Allocate memory for both blocks + state
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE_LOCAL * 3)

    # Initialize SHA-1 state (standard initial values)
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))

    # Hooks for round debugging and handling PLT calls (rand, memset, memcpy)
    emulator.round_count = [0]

    def hook_round_debug(uc, address, size, user_data):
        if address in [0x1560, 0x28e90, 0x50820, 0x7a560]:
            emulator.persist_pending_loads()
            emulator.cache.reset()
            emulator.in_speculation = False
            emulator.speculation_depth = 0
            emulator.speculation_limit = 0
            emulator.timer.cycles = 0
            try:
                rdi = uc.reg_read(UC_X86_REG_RDI)
                rsi = uc.reg_read(UC_X86_REG_RSI)
                rdx = uc.reg_read(UC_X86_REG_RDX)
                rcx = uc.reg_read(UC_X86_REG_RCX)
                input_state = list(struct.unpack("<5I", uc.mem_read(rdi, 20)))
                emulator.logger.log(f"Round {emulator.round_count[0]} input: {[hex(x) for x in input_state]}")
            except:
                pass
            emulator.round_count[0] += 1
        return False

    def hook_after_sha1_block(uc, address, size, user_data):
        if SHA1_BLOCK_RET_ADDR - 8 <= address <= SHA1_BLOCK_RET_ADDR:
            state = list(struct.unpack("<5I", uc.mem_read(STATES_ADDR, 20)))
            print(f"SHA1_BLOCK COMPLETE - State: {[hex(x) for x in state]}")
        return False

    def hook_dyn_calls(uc, address, size, user_data):
        # rand calls inside weird SHA-1
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        # memset@plt
        if address == 0xa284f:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            data = bytes([rsi & 0xFF] * int(rdx))
            uc.mem_write(rdi, data)
            emulator.skip_curr_insn()
            return True
        # memcpy@plt
        if address == 0xa2869:
            rdi = int(uc.reg_read(UC_X86_REG_RDI))
            rsi = int(uc.reg_read(UC_X86_REG_RSI))
            rdx = int(uc.reg_read(UC_X86_REG_RDX))
            try:
                chunk = bytes(uc.mem_read(rsi, rdx))
                uc.mem_write(rdi, chunk)
                if rdx >= 16:
                    words = struct.unpack("<4I", chunk[:16])
                    print(f"First 4 words copied: {[hex(w) for w in words]}")
            except Exception as e:
                print(f"ERROR in memcpy: {e}")
            emulator.skip_curr_insn()
            return True
        return False

    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls, None, 0x1560, 0xa3530)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_round_debug, None, 0x1560, 0xa3530)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_after_sha1_block, None, SHA1_BLOCK_RET_ADDR - 8, SHA1_BLOCK_RET_ADDR + 1)

    # Process first 512-bit block
    print("=== PROCESSING FIRST BLOCK ===")
    print(f"Initial SHA-1 state: {[hex(x) for x in initial_state]}")
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block1))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr      = SHA1_BLOCK_RET_ADDR
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)  # do_ref = false
    emulator.emulate()

    intermediate_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    print(f"Intermediate state: {[hex(x) for x in intermediate_state]}")

    # Process second 512-bit block
    print("\n=== PROCESSING SECOND BLOCK ===")
    emulator.round_count[0] = 0
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block2))
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)
    emulator.uc.reg_write(UC_X86_REG_RIP, SHA1_BLOCK_ADDR)
    emulator.in_speculation    = False
    emulator.speculation_depth = 0
    emulator.checkpoints       = []
    emulator.store_logs        = []
    emulator.emulate()

    final_state = list(struct.unpack("<5I", emulator.uc.mem_read(STATES_ADDR, 20)))
    print(f"Final state: {[hex(x) for x in final_state]}")

    return final_state

def emulate_flexo_aes_block(input_data, key_data, debug=False):
    INPUT_ADDR          = 0x300000
    KEY_ADDR            = 0x301000
    OUTPUT_ADDR         = 0x302000
    ERROR_OUTPUT_ADDR   = 0x303000
    PAGE_SIZE_LOCAL     = 0x1000

    WEIRD_AES_BLOCK_ADDR = 0x261ec0
    AES_BLOCK_RET_ADDR   = 0x262d39
    
    loader = ELFLoader("gates/flexo/aes/aes_block-10.elf")  # Update path
    emulator = MuWMEmulator(name='flexo-aes-block', loader=loader, debug=debug)
    emulator.code_start_address = WEIRD_AES_BLOCK_ADDR
    emulator.code_exit_addr = AES_BLOCK_RET_ADDR
    
    # Map memory for inputs/outputs
    emulator.uc.mem_map(INPUT_ADDR,         PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(KEY_ADDR,           PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(OUTPUT_ADDR,        PAGE_SIZE_LOCAL)
    emulator.uc.mem_map(ERROR_OUTPUT_ADDR,  PAGE_SIZE_LOCAL)
    
    # Write input data (16 bytes each)
    emulator.uc.mem_write(INPUT_ADDR, bytes(input_data))
    emulator.uc.mem_write(KEY_ADDR,   bytes(key_data))
    
    # Set up registers: rdi=input, rsi=key, rdx=output, rcx=error_output
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RSI, KEY_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)
    emulator.uc.reg_write(UC_X86_REG_RCX, ERROR_OUTPUT_ADDR)
    
    # # Debug hook
    # round_counter = [0]  # Use list to allow modification in nested function

    # AES_ROUND_ADDRESSES = [
    #     0xb4f40,   # __weird__aes_first_round
    #     0x1c20,   # __weird__aes_round
    #     0x170390, # __weird__aes_last_round
    # ]
    
    # KEY_SCHEDULE_ADDRESSES = [
    #     0x22d6f0  # __weird__round_key
    # ]

    # def aes_debug_hook(uc, address, size, user_data):
    #     """Simple fixed hook - read from register addresses, not hardcoded ones"""
        
    #     if address in AES_ROUND_ADDRESSES:
    #         round_counter[0] += 1
    #         print(f"=== AES Round {round_counter[0]} at address 0x{address:x} ===")
            
    #         try:
    #             # Read the actual addresses from registers (function parameters)
    #             rdi = uc.reg_read(UC_X86_REG_RDI)  # input parameter
    #             rsi = uc.reg_read(UC_X86_REG_RSI)  # key parameter
                
    #             # Read state from where RDI points (not INPUT_ADDR)
    #             current_state = list(uc.mem_read(rdi, 16))
    #             print(f"Round {round_counter[0]} input state: {[f'0x{x:02x}' for x in current_state]}")
                
    #             # Read key from where RSI points (not KEY_ADDR) 
    #             round_key = list(uc.mem_read(rsi, 16))
    #             print(f"Round {round_counter[0]} key: {[f'0x{x:02x}' for x in round_key]}")
                
    #         except Exception as e:
    #             print(f"Could not read memory at round {round_counter[0]}: {e}")
        
    #     elif address in KEY_SCHEDULE_ADDRESSES:
    #         print(f"=== Key Schedule Operation at address 0x{address:x} ===")
            
    #         try:
    #             rdi = uc.reg_read(UC_X86_REG_RDI)  # prev_key
    #             rsi = uc.reg_read(UC_X86_REG_RSI)  # next_key
                
    #             prev_key = list(uc.mem_read(rdi, 16))
    #             print(f"Previous key: {[f'0x{x:02x}' for x in prev_key]}")
                
    #         except Exception as e:
    #             print(f"Could not read key schedule memory: {e}")
        
    #     return False

    # Add any necessary hooks
    def hook_dyn_calls(uc, address, size, user_data):
        # rand calls
        if address in [0x1c50, 0xb4f77, 0x1703c8, 0x22d721]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        # memset@plt
        if address == 0x261eee:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            data = bytes([rsi & 0xFF] * int(rdx))
            uc.mem_write(rdi, data)
            emulator.skip_curr_insn()
            return True
        return False
    
    # emulator.uc.hook_add(UC_HOOK_CODE, aes_debug_hook)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_dyn_calls)
    
    emulator.emulate()
    
    # Read 16 bytes from OUTPUT_ADDR and ERROR_OUTPUT_ADDR
    result = list(emulator.uc.mem_read(OUTPUT_ADDR, 16))
    err_out = list(emulator.uc.mem_read(ERROR_OUTPUT_ADDR, 16))
    
    return result, err_out