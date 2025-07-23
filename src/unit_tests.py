import sys
import itertools
import random
from loader import *
from gates.asm import *
from unicorn.x86_const import *

# Import tests
from tests.asm_tests import *
from tests.flexo_tests import *
from tests.gitm_tests import *

# Import reference implementations
from tests.ref.ref import *
from tests.ref.sha1_round.ref import ref_sha1_round
from tests.ref.aes_round.ref import ref_aes_round
from tests.ref.simon32.ref import ref_simon32
from tests.ref.aes_block.ref import ref_aes_block
from tests.ref.alu.ref import ref_alu

##########################################
# ASM tests
##########################################

def test_asm_assign() -> bool:
    verifier = lambda a: a
    return run_gate_test('ASSIGN', emulate_asm_assign, verifier, 1)

def test_asm_and() -> bool:
    verifier = lambda a, b: a and b
    return run_gate_test('AND', emulate_asm_and, verifier, 2)

def test_asm_or() -> bool:
    verifier = lambda a, b: a or b
    return run_gate_test('OR', emulate_asm_or, verifier, 2)

def test_asm_not() -> bool:
    verifier = lambda a: not a
    return run_gate_test('NOT', emulate_asm_not, verifier, 1)

def test_asm_and_or() -> bool:
    verifier = lambda a, b, c: (a and b) or c
    return run_gate_test('AND-OR', emulate_asm_and_or, verifier, 3)

##########################################
# GITM tests
##########################################

def test_gitm_assign() -> bool:
    verifier = lambda a: a
    return run_gate_test('ASSIGN', emulate_gitm_assign, verifier, 1)

def test_gitm_and() -> bool:
    verifier = lambda a, b: a and b
    return run_gate_test('AND', emulate_gitm_and, verifier, 2)

def test_gitm_or() -> bool:
    verifier = lambda a, b: a or b
    return run_gate_test('OR', emulate_gitm_or, verifier, 2)

def test_gitm_not() -> bool:
    verifier = lambda a: not a
    return run_gate_test('NOT', emulate_gitm_not, verifier, 1)

def test_gitm_nand() -> bool:
    verifier = lambda a, b: not (a and b)
    return run_gate_test('NAND', emulate_gitm_nand, verifier, 2)

def test_gitm_mux() -> bool:
    verifier = lambda a, b, sel: a if sel == 0 else b
    return run_gate_test('MUX', emulate_gitm_mux, verifier, 3)

def test_gitm_xor() -> bool:
    verifier = lambda a, b: a ^ b
    return run_gate_test('XOR', emulate_gitm_xor, verifier, 2)

##########################################
# Flexo tests
##########################################

def test_flexo_and() -> bool:
    verifier = lambda a, b: a and b
    return run_gate_test('FLEXO-AND', emulate_flexo_and, verifier, 2)

def test_flexo_or() -> bool:
    verifier = lambda a, b: a or b
    return run_gate_test('FLEXO-OR', emulate_flexo_or, verifier, 2)

def test_flexo_not() -> bool:
    verifier = lambda a: not a
    return run_gate_test('FLEXO-NOT', emulate_flexo_not, verifier, 1)

def test_flexo_nand() -> bool:
    verifier = lambda a, b: not (a and b)
    return run_gate_test('FLEXO-NAND', emulate_flexo_nand, verifier, 2)

def test_flexo_xor() -> bool:
    verifier = lambda a, b: a ^ b
    return run_gate_test('FLEXO-XOR', emulate_flexo_xor, verifier, 2)

def test_flexo_xor3() -> bool:
    verifier = lambda a, b, c: a ^ b ^ c
    return run_gate_test('FLEXO-XOR3', emulate_flexo_xor3, verifier, 3)

def test_flexo_xor4() -> bool:
    verifier = lambda a, b, c, d: a ^ b ^ c ^ d
    return run_gate_test('FLEXO-XOR4', emulate_flexo_xor4, verifier, 4)

def test_flexo_mux() -> bool:
    verifier = lambda a, b, sel: a if sel == 0 else b
    return run_gate_test('FLEXO-MUX', emulate_flexo_mux, verifier, 3)

def test_flexo_adder8() -> bool:
    verifier = lambda a, b: (a + b) & 0xFF
    return run_adder_flexo_test('FLEXO-ADDER8', emulate_flexo_adder8, verifier, bits=8)

def test_flexo_adder16() -> bool:
    verifier = lambda a, b: (a + b) & 0xFFFF
    return run_adder_flexo_test('FLEXO-ADDER16', emulate_flexo_adder16, verifier, bits=16)

def test_flexo_adder32() -> bool:
    verifier = lambda a, b: (a + b) & 0xFFFFFFFF
    return run_adder_flexo_test('FLEXO-ADDER32', emulate_flexo_adder32, verifier, bits=32)

def test_flexo_sha1_round():
   all_passed = True

   # Generate random test inputs
   state = [randint(0, 0xFFFFFFFF) for _ in range(5)]
   w = randint(0, 0xFFFFFFFF)
   try:
       out, err = emulate_flexo_sha1_round(state, w)
       ref = ref_sha1_round(state, w, round_num=0)  # Note: C code uses 1-based, we use 0-based
       match = all(out[i] == ref[i] for i in range(5))
       if match:
           print(f"Test passed for SHA1_ROUND(state={[hex(x) for x in state]}, w={hex(w)})")
       else:
           print(f"Test failed for SHA1_ROUND(state={[hex(x) for x in state]}, w={hex(w)}):")
           print(f"\tExpected: {[hex(x) for x in ref]}")
           print(f"\tResult: {[hex(x) for x in out]}")
           all_passed = False
           
   except Exception as e:
       print(f"Test error for SHA1_ROUND(state={[hex(x) for x in state]}, w={hex(w)}): {e}")
       all_passed = False
   
   return all_passed

def test_flexo_aes_round():
    all_passed = True
    
    # Generate random test inputs
    input_block = [randint(0, 255) for _ in range(16)]
    key_block = [randint(0, 255) for _ in range(16)]
    
    try:
        out, err = emulate_flexo_aes_round(input_block, key_block)
        ref = ref_aes_round(input_block, key_block)
        
        match = all(out[i] == ref[i] for i in range(16))
        
        if match:
            print(f"Test passed for AES_ROUND(input={[hex(x) for x in input_block[:4]]}..., key={[hex(x) for x in key_block[:4]]}...)")
        else:
            print(f"Test failed for AES_ROUND(input={[hex(x) for x in input_block[:4]]}..., key={[hex(x) for x in key_block[:4]]}...):")
            print(f"\tExpected: {[hex(x) for x in ref[:4]]}...")
            print(f"\tResult:   {[hex(x) for x in out[:4]]}...")
            all_passed = False
    except Exception as e:
        print(f"Test error for AES_ROUND(input={[hex(x) for x in input_block[:4]]}..., key={[hex(x) for x in key_block[:4]]}...): {e}")
        all_passed = False
    
    return all_passed

def test_flexo_simon32():
    all_passed = True
    
    # Generate random test inputs
    input_block = [randint(0, 255) for _ in range(4)]   # 4-byte (32-bit) block
    key_block = [randint(0, 255) for _ in range(8)]     # 8-byte (64-bit) key
    
    try:
        out, err = emulate_flexo_simon32(input_block, key_block)
        ref = ref_simon32(input_block, key_block)
        
        match = all(out[i] == ref[i] for i in range(4))
        
        if match:
            print(f"Test passed for SIMON32(input={[hex(x) for x in input_block]}, key={[hex(x) for x in key_block[:4]]}...)")
        else:
            print(f"Test failed for SIMON32(input={[hex(x) for x in input_block]}, key={[hex(x) for x in key_block[:4]]}...):")
            print(f"\tExpected: {[hex(x) for x in ref]}")
            print(f"\tResult:   {[hex(x) for x in out]}")
            all_passed = False
    except Exception as e:
        print(f"Test error for SIMON32(input={[hex(x) for x in input_block]}, key={[hex(x) for x in key_block[:4]]}...): {e}")
        all_passed = False
    
    return all_passed

def test_flexo_alu():
    all_passed = True
    
    # Generate random test inputs
    x_data = randint(0, 15)      # 4 bits
    y_data = randint(0, 15)      # 4 bits
    control_data = randint(0, 63) # 6 bits
    
    try:
        out, err = emulate_flexo_alu(x_data, y_data, control_data)
        ref = ref_alu(x_data, y_data, control_data)
        
        # Compare only the 6 bits that matter
        out_masked = out & 0x3F
        ref_masked = ref & 0x3F
        
        match = (out_masked == ref_masked)
        if match:
            print(f"Test passed for ALU(x={hex(x_data)}, y={hex(y_data)}, control={hex(control_data)})")
        else:
            print(f"Test failed for ALU(x={hex(x_data)}, y={hex(y_data)}, control={hex(control_data)}):")
            print(f"\tExpected: {hex(ref_masked)}")
            print(f"\tResult: {hex(out_masked)}")
            all_passed = False
            
    except Exception as e:
        print(f"Test error for ALU(x={hex(x_data)}, y={hex(y_data)}, control={hex(control_data)}): {e}")
        all_passed = False
        
    return all_passed

# def test_flexo_alu_exhaustive():
#     """Test all possible ALU input combinations - commented out by default due to long runtime"""
#     all_passed = True
#     failed_count = 0
#     total_combinations = 16 * 16 * 64  # 16,384 total combinations
#     tested_count = 0
    
#     for x in range(16):        # 4-bit x
#         for y in range(16):    # 4-bit y
#             for control in range(64):  # 6-bit control
#                 tested_count += 1
#                 try:
#                     out, err = emulate_flexo_alu(x, y, control)
#                     ref = ref_alu(x, y, control)
                    
#                     out_masked = out & 0x3F
#                     ref_masked = ref & 0x3F
                    
#                     if out_masked != ref_masked:
#                         if failed_count < 10:  # Only print first 10 failures
#                             print(f"FAIL: ALU(x={x}, y={y}, control={control}): expected {ref_masked}, got {out_masked}")
#                         failed_count += 1
#                         all_passed = False
                        
#                 except Exception as e:
#                     if failed_count < 10:
#                         print(f"ERROR: ALU(x={x}, y={y}, control={control}): {e}")
#                     failed_count += 1
#                     all_passed = False
                
#                 print(f"\rProgress: {tested_count}/{total_combinations} combinations tested ({tested_count/total_combinations*100:.1f}%)", end='', flush=True)
    
#     print()
    
#     if failed_count > 10:
#         print(f"... and {failed_count - 10} more failures")
    
#     print(f"Exhaustive ALU test: {total_combinations - failed_count}/{total_combinations} passed")
#     return all_passed

# def test_flexo_sha1_2blocks():
#     """Currently not working"""
#      # Use the same random seed as your working 1-block test for consistency
#     random.seed(12345)

#     block1 = [random.randint(0, 0xFFFFFFFF) for _  in range(16)]
#     block2 = [random.randint(0, 0xFFFFFFFF) for _ in range(16)]

#     print(f"Testing SHA1_2BLOCKS with:\n\tBlock 1: {[hex(x) for x in block1]}\n\tBlock 2: {[hex(x) for x in block2]}")

#     result = emulate_flexo_sha1_2blocks(block1, block2, debug=True)
#     reference = ref_sha1_2blocks(block1, block2)
    
#     print(f"\nFinal comparison:")
#     print(f"\tEmulator: {[hex(x) for x in result]}")
#     print(f"\tReference: {[hex(x) for x in reference]}")
#     print(f"\tMatch: {all(result[i] == reference[i] for i in range(5))}")
#     return all(result[i] == reference[i] for i in range(5))

# def test_flexo_aes_block():
#     """Currently not working"""
#     all_passed = True
#     random.seed(12345)
#     # Generate random test inputs (16 bytes each for input and key)
#     input_data = [random.randint(0, 255) for _ in range(16)]
#     key_data = [random.randint(0, 255) for _ in range(16)]
#     try:
#         out, err = emulate_flexo_aes_block(input_data, key_data)
#         ref = ref_aes_block(input_data, key_data)
#         match = all(out[i] == ref[i] for i in range(16))
#         if match:
#             print(f"Test passed for AES_BLOCK(input={[hex(x) for x in input_data]}, key={[hex(x) for x in key_data]})")
#         else:
#             print(f"Test failed for AES_BLOCK(input={[hex(x) for x in input_data]}, key={[hex(x) for x in key_data]}):")
#             print(f"\tExpected: {[hex(x) for x in ref]}")
#             print(f"\tResult: {[hex(x) for x in out]}")
#             all_passed = False
#     except Exception as e:
#         print(f"Test error for AES_BLOCK(input={[hex(x) for x in input_data]}, key={[hex(x) for x in key_data]}): {e}")
#         all_passed = False
#     return all_passed


##########################################
# HELPER FUNCTIONS
##########################################

def run_gate_test(gate_name, emulate_function, verifier, num_inputs, debug=False) -> bool:
    """
    Generic test runner for gates with max 4 input bits.
    
    Args:
        gate_name: name of the gate for (logging)
        emulate_function: function to emulate the gate
        verifier: function that computes expected output
        num_inputs: number of inputs for the gate (max 4)
        debug: whether to enable debug logging
    """
    all_passed = True
    
    # Generate all possible input combinations
    for inputs in itertools.product([0, 1], repeat=num_inputs):
        try:
            # Run the gate with the inputs
            if num_inputs == 1:
                result = emulate_function(inputs[0], debug=debug)
            elif num_inputs == 2:
                result = emulate_function(inputs[0], inputs[1], debug=debug)
            elif num_inputs == 3:
                result = emulate_function(inputs[0], inputs[1], inputs[2], debug=debug)
            elif num_inputs == 4:
                result = emulate_function(inputs[0], inputs[1], inputs[2], inputs[3], debug=debug)
            else:
                raise ValueError(f"Unsupported number of inputs: {num_inputs}")
            
            # Compute expected result using verifier
            expected = verifier(*inputs)
            
            if result == expected:
                print(f"Test passed for {gate_name}{inputs}")
            else:
                print(f"Test failed for {gate_name}{inputs}:")
                print(f"\tExpected: {expected}")
                print(f"\tResult: {result}")
                all_passed = False
                
        except Exception as e:
            print(f"Test error for {gate_name}{inputs}: {e}")
            all_passed = False
    
    return all_passed

def run_adder_flexo_test(adder_name, emulate_function, verifier, bits, runs=4,debug=False) -> bool:
    """
    Generic randomized tester for an N-bit Flexo adder. Performs 4 tests with random inputs.
    """

    all_passed = True
    max_val = (1 << bits) - 1

    for _ in range(runs):
        a = randint(0, max_val)
        b = randint(0, max_val)
        # a = 1735138883
        # b = 3407895005
        # compare_runs(a, b)
        result, _ = emulate_function(a, b, debug=debug)
        expected = verifier(a, b)

        if result != expected:
            print(f"Test failed for {adder_name}({a}, {b}):")
            print(f"\tExpected: {expected}")
            print(f"\tResult:   {result}")
            all_passed = False
        else:
            print(f"Test passed for {adder_name}({a}, {b})")

    return all_passed

##########################################
# CLI
##########################################

def run_all_tests():
    """
    Run all test functions in this module (functions that start with 'test_').
    """
    test_functions = [name for name in globals() 
                     if name.startswith('test_') and callable(globals()[name])]
    
    print(f"Running {len(test_functions)} tests:")
    for test_func_name in test_functions:
        print(f"\n--- Running {test_func_name} ---")
        globals()[test_func_name]()
    
    print("\nAll tests have been run!")

def run_tests_by_prefix(prefix):
    """
    Run all test functions that start with the specified prefix.
    """
    test_functions = [name for name in globals() 
                     if name.startswith(f'test_{prefix}') and callable(globals()[name])]
    
    if not test_functions:
        print(f"No tests found with prefix 'test_{prefix}'")
        return
    
    print(f"Running {len(test_functions)} {prefix.upper()} tests:")
    for test_func_name in test_functions:
        print(f"\n--- Running {test_func_name} ---")
        globals()[test_func_name]()
    
    print(f"\nAll {prefix.upper()} tests have been run!")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unit_tests.py <test_name>")
        print("       python unit_tests.py all (to run all tests)")
        print("       python unit_tests.py asm (to run all ASM tests)")
        print("       python unit_tests.py gitm (to run all GITM (Ghost is the Machine) tests)")
        print("       python unit_tests.py flexo (to run all Flexo tests)")
        print("Available tests:")
        # List all functions that start with 'test_'
        # tests = [name for name in globals() if name.startswith('test_')]
        # for test in tests:
        #     print(f"  - {test}")
        sys.exit(1)

    test_name = sys.argv[1]
    if test_name.lower() == 'all':
        run_all_tests()
    elif test_name.lower() in ['asm', 'gitm', 'flexo']:
        run_tests_by_prefix(test_name.lower())
    elif test_name in globals() and test_name.startswith('test_'):
        globals()[test_name]()  # Run the requested test
        print("Finished unit tests")
    else:
        print(f"Error: Test '{test_name}' not found")
        sys.exit(1)