from tests.flexo_tests import *
from tests.gitm_tests import *
import time
import struct
from random import randint

def time_gate_bulk(
    gate_fn, 
    gate_name: str,
    tot_trials: int = 1000000,
    input_bits: int = 2,
    expected_fn=None
) -> None:
    """
    Generic function to time gate operations over many iterations.
    
    Args:
        gate_fn: The gate function to test
        gate_name: Name for display purposes
        tot_trials: Number of iterations to run
        input_bits: Number of input bits to extract from seed
        expected_fn: Function to compute expected result (for validation)
    """
    def gate_fn_with_error_codes(seed: int) -> int:
        """
        Gate function that returns error codes like the hardware:
        0 = correct result
        2 = detected error (we assume this never happens in emulation)
        other = undetected error
        """
        # Extract inputs from seed
        inputs = [(seed >> i) & 1 for i in range(input_bits)]
        
        # Get emulated result
        result = gate_fn(*inputs, debug=False)
        
        # Validate if expected function provided
        if expected_fn:
            expected = expected_fn(*inputs)
            if result == expected:
                return 0  # Correct
            else:
                return 1  # Undetected error
        else:
            return 0  # Assume correct if no validation
    
    tot_correct_counts = 0
    tot_detected_counts = 0
    tot_error_counts = 0
    
    # Start timing
    start_time = time.perf_counter_ns()
    
    for seed in range(tot_trials):
        result = gate_fn_with_error_codes(seed)
        
        # Use exact same logic as hardware
        if result == 0:
            tot_correct_counts += 1
        elif result & 2:  # Check if bit 1 is set
            tot_detected_counts += 1
        else:
            tot_error_counts += 1
    
    # End timing
    end_time = time.perf_counter_ns()
    tot_ns = end_time - start_time
    tot_s = tot_ns / 1_000_000_000
    
    print(f"=== {gate_name} gate (emulated) ===")
    print(f"Accuracy: {(tot_correct_counts / tot_trials * 100):.5f}%, ", end="")
    print(f"Error detected: {(tot_detected_counts / tot_trials * 100):.5f}%, ", end="")
    print(f"Undetected error: {(tot_error_counts / tot_trials * 100):.5f}%")
    
    avg_s = tot_s / tot_trials
    print(f"Time usage per run: {avg_s:.9f} s")
    print(f"Total seconds: {tot_s:.6f} s")
    print(f"over {tot_trials} iterations.")

# Specific timing functions using the generic helpers
def time_flexo_and(tot_trials: int = 1000000) -> None:
    time_gate_bulk(
        gate_fn=emulate_flexo_and,
        gate_name="AND",
        tot_trials=tot_trials,
        input_bits=2,
        expected_fn=lambda in1, in2: in1 and in2
    )

def time_gitm_and(tot_trials: int = 1000000) -> None:
    time_gate_bulk(
        gate_fn=emulate_gitm_and,
        gate_name="GITM AND",
        tot_trials=tot_trials,
        input_bits=2,
        expected_fn=lambda in1, in2: in1 and in2
    )

def time_gitm_mux(tot_trials: int = 1000000) -> None:
    time_gate_bulk(
        gate_fn=emulate_gitm_mux,
        gate_name="GITM MUX",
        tot_trials=tot_trials,
        input_bits=3,
        expected_fn=lambda sel, in1, in2: in1 if sel == 0 else in2
    )

def time_flexo_sha1_round_average(num_iterations: int = 100) -> None:
    print(f"\n=== SHA1 Round Average Timing ({num_iterations} iterations) ===")
    
    total_time = 0.0
    
    for i in range(num_iterations):
        # Generate random inputs for each iteration
        state = [randint(0, 0xFFFFFFFF) for _ in range(5)]
        w = randint(0, 0xFFFFFFFF)
        
        # Time the emulation
        start_time = time.perf_counter_ns()
        output, err_out = emulate_flexo_sha1_round(state, w, debug=False)
        end_time = time.perf_counter_ns()
        
        tot_ns = end_time - start_time
        tot_s = tot_ns / 1_000_000_000
        total_time += tot_s
        
        # Optionally print progress every 10 iterations
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{num_iterations} iterations...")
    
    # Calculate and display results
    avg_time = total_time / num_iterations
    
    print(f"\n=== SHA1 Round Average Results ===")
    print(f"Total iterations: {num_iterations}")
    print(f"Total execution time: {total_time:.6f} s")
    print(f"Average execution time per round: {avg_time:.9f} s")
    print(f"Average time per round (nanoseconds): {avg_time * 1_000_000_000:.2f} ns")

def time_flexo_simon32_average(num_iterations: int = 100) -> None:
    print(f"\n=== SIMON32 Average Timing ({num_iterations} iterations) ===")
    
    total_time = 0.0
    
    for i in range(num_iterations):
        # Generate random inputs for each iteration
        input_block = [randint(0, 255) for _ in range(4)]   # 4-byte (32-bit) block
        key_block = [randint(0, 255) for _ in range(8)]     # 8-byte (64-bit) key
        
        # Time the emulation
        start_time = time.perf_counter_ns()
        output, err_out = emulate_flexo_simon32(input_block, key_block, debug=False)
        end_time = time.perf_counter_ns()
        
        tot_ns = end_time - start_time
        tot_s = tot_ns / 1_000_000_000
        total_time += tot_s
        
        # Optionally print progress every 10 iterations
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{num_iterations} iterations...")
    
    # Calculate and display results
    avg_time = total_time / num_iterations
    
    print(f"\n=== SIMON32 Average Results ===")
    print(f"Total iterations: {num_iterations}")
    print(f"Total execution time: {total_time:.6f} s")
    print(f"Average execution time per block: {avg_time:.9f} s")
    print(f"Average time per block (nanoseconds): {avg_time * 1_000_000_000:.2f} ns")

def time_flexo_alu_average(num_iterations: int = 100) -> None:
    print(f"\n=== ALU Average Timing ({num_iterations} iterations) ===")
    
    total_time = 0.0
    
    for i in range(num_iterations):
        # Generate random inputs for each iteration
        x_data = randint(0, 15)       # 4 bits
        y_data = randint(0, 15)       # 4 bits
        control_data = randint(0, 63) # 6 bits
        
        # Time the emulation
        start_time = time.perf_counter_ns()
        output, err_out = emulate_flexo_alu(x_data, y_data, control_data, debug=False)
        end_time = time.perf_counter_ns()
        
        tot_ns = end_time - start_time
        tot_s = tot_ns / 1_000_000_000
        total_time += tot_s
        
        # Optionally print progress every 10 iterations
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{num_iterations} iterations...")
    
    # Calculate and display results
    avg_time = total_time / num_iterations
    
    print(f"\n=== ALU Average Results ===")
    print(f"Total iterations: {num_iterations}")
    print(f"Total execution time: {total_time:.6f} s")
    print(f"Average execution time per operation: {avg_time:.9f} s")
    print(f"Average time per operation (nanoseconds): {avg_time * 1_000_000_000:.2f} ns")

def emulate_flexo_sha1_2blocks_timing(input_data, debug=False):
    """Emulate SHA1 2-blocks by calling sha1_block twice"""

    # START TIMING HERE
    start_time = time.perf_counter_ns()
    
    INPUT_ADDR   = 0x200000
    STATES_ADDR  = 0x201000
    PAGE_SIZE_LOCAL = 0x1000

    SHA1_BLOCK_ADDR      = 0xa2820
    SHA1_BLOCK_RET_ADDR  = 0xa2cdf  # Return address from objdump

    loader   = ELFLoader("gates/flexo/sha1/sha1_2blocks-6.elf")
    emulator = MuWMEmulator(name='flexo-sha1-2blocks', loader=loader, debug=True)

    # Allocate memory for input blocks and state
    emulator.uc.mem_map(INPUT_ADDR, PAGE_SIZE_LOCAL * 3)

    # Initialize SHA-1 state (standard initial values)
    initial_state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    emulator.uc.mem_write(STATES_ADDR, struct.pack("<5I", *initial_state))

    def hook_round_ret(uc, address, size, user_data):
        nonlocal start_time  # Allow access to start_time from outer scope
        round_addresses = [0x1560, 0x28e90, 0x50820, 0x7a560]
        if address in round_addresses:
            state = list(struct.unpack("<5I", uc.mem_read(STATES_ADDR, 20)))
            
            # Determine round type based on address
            round_type = round_addresses.index(address) + 1
            
            if debug:
                print(f"Round {emulator.round_counter} (sha1_round{round_type}): {[hex(x) for x in state]}")
            
            # Increment counter for next round
            emulator.round_counter += 1

            if emulator.round_counter == [81]:
                emulator.round_counter = 1  # Reset after 80 rounds

            # Reset state at start of round 67
            if emulator.round_counter == 67:
                # END TIMING HERE
                end_time = time.perf_counter_ns()
                emulator.execution_time_ns = end_time - start_time
                uc.stop()

        return False

    # Hook for PLT calls (rand, memset, memcpy) - needed for library function emulation
    for address in [0x7a594]:
        emulator.rsb.add_exception_addr(address)

    def hook_plt_calls(uc, address, size, user_data):
        # rand calls inside weird SHA-1 - return deterministic value
        if address in [0x158f, 0x28ebf, 0x5084f, 0x7a58f]:
            uc.reg_write(UC_X86_REG_RAX, 0x12345678)
            emulator.skip_curr_insn()
            return True
        # memset@plt at 0xa284f
        elif address == 0xa284f:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            data = bytes([rsi & 0xFF] * int(rdx))
            uc.mem_write(rdi, data)
            emulator.skip_curr_insn()
            return True
        # memcpy@plt at 0xa2869
        elif address == 0xa2869:
            rdi = int(uc.reg_read(UC_X86_REG_RDI))
            rsi = int(uc.reg_read(UC_X86_REG_RSI))
            rdx = int(uc.reg_read(UC_X86_REG_RDX))
            try:
                data = bytes(uc.mem_read(rsi, rdx))
                uc.mem_write(rdi, data)
                if debug and rdx >= 16:
                    words = struct.unpack("<4I", data[:16])
                    print(f"memcpy: copied {rdx} bytes, first 4 words: {[hex(w) for w in words]}")
            except Exception as e:
                if debug:
                    print(f"memcpy error: {e}")
            emulator.skip_curr_insn()
            return True
        return False

    # Add hooks
    emulator.uc.hook_add(UC_HOOK_CODE, hook_plt_calls)
    emulator.uc.hook_add(UC_HOOK_CODE, hook_round_ret)

    # Split input into two 16-word blocks
    block1 = input_data[:16]
    block2 = input_data[16:32]

    # Process first block
    if debug:
        print("=== PROCESSING FIRST BLOCK ===")
        print(f"Block 1: {[hex(x) for x in block1]}")
        print(f"Initial state: {[hex(x) for x in initial_state]}")
    
    emulator.uc.mem_write(INPUT_ADDR, struct.pack("<16I", *block1))
    emulator.code_start_address = SHA1_BLOCK_ADDR
    emulator.code_exit_addr = SHA1_BLOCK_RET_ADDR
    emulator.uc.reg_write(UC_X86_REG_RDI, INPUT_ADDR)    # block pointer
    emulator.uc.reg_write(UC_X86_REG_RSI, STATES_ADDR)   # states pointer
    emulator.uc.reg_write(UC_X86_REG_RDX, 0)             # do_ref = false
    
    emulator.emulate()
    print(f"Emulation finished at round {emulator.round_counter}.")
    
    # RETURN TIMING INFORMATION HERE TO CALLER
    execution_time_ns = getattr(emulator, 'execution_time_ns', 0)
    execution_time_s = execution_time_ns / 1_000_000_000
    return execution_time_s, emulator.round_counter

def time_flexo_sha1_2blocks(tot_trials: int = 100) -> None:
    """
    Times SHA1 2-blocks emulation over multiple iterations and outputs average execution time.
    This function emulates the first 66 rounds of SHA1 processing.
    
    Args:
        tot_trials: Number of times to execute the emulation (default 100)
    """
    print(f"\n=== SHA1 2-Blocks Timing ({tot_trials} trials) ===")
    
    total_time = 0.0
    successful_runs = 0
    
    for i in range(tot_trials):
        # Generate random 32-word input (2 blocks of 16 words each)
        input_data = [randint(0, 0xFFFFFFFF) for _ in range(32)]
        
        try:
            # Time the emulation
            execution_time_s, round_counter = emulate_flexo_sha1_2blocks_timing(input_data, debug=False)
            total_time += execution_time_s
            successful_runs += 1
            
        except Exception as e:
            print(f"Trial {i + 1} failed: {e}")
            continue
        
        # Optionally print progress every 10 iterations
        if (i + 1) % 10 == 0:
            print(f"Completed {i + 1}/{tot_trials} trials...")
    
    # Calculate and display results
    if successful_runs > 0:
        avg_time = total_time / successful_runs
        avg_time_ns = avg_time * 1_000_000_000
        
        print(f"\n=== SHA1 2-Blocks Timing Results ===")
        print(f"Total trials: {tot_trials}")
        print(f"Successful runs: {successful_runs}/{tot_trials} ({(successful_runs/tot_trials)*100:.2f}%)")
        print(f"Total execution time: {total_time:.6f} s")
        print(f"Average execution time (first 66 rounds): {avg_time:.9f} s")
        print(f"Average time (nanoseconds): {avg_time_ns:.2f} ns")
        print(f"Rounds processed per trial: 66")
    else:
        print("No successful runs completed!")

if __name__ == "__main__":
    # Bulk timing tests
    # print("=== Bulk Timing Tests ===")
    # time_flexo_and(tot_trials=1000)
    # print()
    # time_gitm_and(tot_trials=1000)
    # print()
    # time_gitm_mux(tot_trials=1000)
    # print()
    
    # # SHA1 round timing tests
    # print("=== SHA1 Round Timing Tests ===")
    # time_flexo_sha1_round_average(num_iterations=1)
    
    # # SIMON32 timing tests
    # print("=== SIMON32 Timing Tests ===")
    # time_flexo_simon32_average(num_iterations=1)
    
    # ALU timing tests
    print("=== ALU Timing Tests ===")
    time_flexo_alu_average(num_iterations=100)
    
    # SHA1 2-blocks timing test (first 66 rounds)
    time_flexo_sha1_2blocks(tot_trials=1)
