from emulator import MuWMEmulator
from loader import ELFLoader
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RDI

# -------------------------------------------------------------------
# Generic helper for DRY emulation of GitM‐based gates
# -------------------------------------------------------------------

def _emulate_gitm_gate(
    name: str,
    elf_path: str,
    start_addr: int,
    end_addr: int,
    in_addrs: tuple,
    in_bits: tuple,
    out_addrs: tuple,
    debug: bool = False
) -> tuple:
    """
    Generic emulator for GitM‐based gates.
    - name: label for the emulator instance
    - elf_path: path to the ELF binary
    - start_addr, end_addr: code boundaries for emulate()
    - in_addrs: tuple of memory addresses used to prime the cache for each input
    - in_bits: tuple of integer bits (0 or 1) for each input
    - out_addrs: tuple of memory addresses from which to read cached output bits
    Returns a tuple of booleans indicating whether each out_addr was cached.
    """
    loader = ELFLoader(elf_path)
    emulator = MuWMEmulator(name=name, loader=loader, debug=debug)
    emulator.code_start_address = start_addr
    emulator.code_exit_addr = end_addr

    # Prime the cache for any input bits that are 1
    for addr, bit in zip(in_addrs, in_bits):
        if bit:
            emulator.cache.read(addr, emulator.uc)

    # Combine all input bits into a single integer parameter, LSB = in_bits[0], etc.
    param = 0
    for idx, bit in enumerate(in_bits):
        param |= (bit & 1) << idx

    # Write the combined parameter into RDI (64‐bit register)
    emulator.uc.reg_write(UC_X86_REG_RDI, param)

    emulator.logger.log(f"Starting emulation of {name} with bits={in_bits} ...")
    emulator.emulate()

    # Check cache status for each output address
    results = tuple(emulator.cache.is_cached(addr) for addr in out_addrs)
    return results

# -------------------------------------------------------------------
# Specific gate wrappers using the generic helper
# -------------------------------------------------------------------

def emulate_gitm_assign(input_val: int, debug: bool = False) -> bool:
    IN_ADDR   = 0x81c0   # reg1
    OUT1_ADDR = 0x79c0   # reg2
    OUT2_ADDR = 0x71c0   # reg3
    START     = 0x1490
    END       = 0x160f

    # Only one input bit, prime cache at IN_ADDR if input_val == 1
    results = _emulate_gitm_gate(
        name="gitm_assign",
        elf_path="gates/gitm/main_assign.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN_ADDR,),
        in_bits=(input_val & 1,),
        out_addrs=(OUT1_ADDR, OUT2_ADDR),
        debug=debug
    )
    result1, result2 = results
    # Both outputs should match the input: 
    # result1 (bool) must be True if input_val==1, False if input_val==0.
    # Similarly for result2. The original returned result1 and (result2 == input_val),
    # so we preserve that semantics.
    return result1 and (result2 == bool(input_val))


def emulate_gitm_and(in1: int, in2: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    START    = 0x1490
    END      = 0x161d

    result, = _emulate_gitm_gate(
        name="gitm_and",
        elf_path="gates/gitm/main_and.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR, IN2_ADDR),
        in_bits=(in1 & 1, in2 & 1),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result


def emulate_gitm_or(in1: int, in2: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    START    = 0x1490
    END      = 0x1620

    result, = _emulate_gitm_gate(
        name="gitm_or",
        elf_path="gates/gitm/main_or.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR, IN2_ADDR),
        in_bits=(in1 & 1, in2 & 1),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result


def emulate_gitm_not(input_val: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    OUT_ADDR = 0x71c0
    START    = 0x1490
    END      = 0x1628

    # NOT gate uses the same input for reg1 (and reg2, but we only need one for cache priming)
    result, = _emulate_gitm_gate(
        name="gitm_not",
        elf_path="gates/gitm/main_not.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR,),
        in_bits=(input_val & 1,),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result


def emulate_gitm_nand(in1: int, in2: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    START    = 0x1490
    END      = 0x2a6e

    result, = _emulate_gitm_gate(
        name="gitm_nand",
        elf_path="gates/gitm/main_nand.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR, IN2_ADDR),
        in_bits=(in1 & 1, in2 & 1),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result


def emulate_gitm_mux(in1: int, in2: int, in3: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    IN3_ADDR = 0x71c0
    OUT_ADDR = 0x69c0
    START    = 0x1ea0
    END      = 0x356d

    result, = _emulate_gitm_gate(
        name="gitm_mux",
        elf_path="gates/gitm/main_mux.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR, IN2_ADDR, IN3_ADDR),
        in_bits=(in1 & 1, in2 & 1, in3 & 1),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result


def emulate_gitm_xor(in1: int, in2: int, debug: bool = False) -> bool:
    IN1_ADDR = 0x81c0
    IN2_ADDR = 0x79c0
    OUT_ADDR = 0x71c0
    START    = 0x1490
    END      = 0x2e54

    result, = _emulate_gitm_gate(
        name="gitm_xor",
        elf_path="gates/gitm/main_xor.elf",
        start_addr=START,
        end_addr=END,
        in_addrs=(IN1_ADDR, IN2_ADDR),
        in_bits=(in1 & 1, in2 & 1),
        out_addrs=(OUT_ADDR,),
        debug=debug
    )
    return result
