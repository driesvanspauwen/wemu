import subprocess
import os

def compile_asm(asm_code, output_dir, output_bin="assign_gate.bin", output_obj="assign_gate.o", debug=False):
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Update file paths to use output directory
    asm_file = os.path.join(output_dir, "assign_gate.asm")
    output_obj = os.path.join(output_dir, output_obj)
    output_bin = os.path.join(output_dir, output_bin)
    objdump_output_file = os.path.join(output_dir, "objdump.txt")
    
    # Save the assembly to a file
    with open(asm_file, 'w') as f:
        f.write(asm_code)
        if debug:
            print(f"Saved assembly to {asm_file}")
    
    try:
        # Assemble using NASM
        subprocess.run(['nasm', '-f', 'elf64', asm_file, '-o', output_obj], check=True)
        if debug:
            print(f"Compiled object file to {output_obj}")

        # Extract binary code
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', output_obj, output_bin], check=True)
        if debug:
            print(f"Extracted binary to {output_bin}")
        
        # Generate objdump output
        subprocess.run(['objdump', '-M', 'intel', '-d', output_obj], stdout=open(objdump_output_file, 'w'), check=True)
        if debug:
            print(f"Objdump saved to {objdump_output_file}")

        with open(output_bin, 'rb') as f:
            machine_code = f.read()
        
        return machine_code
    
    except subprocess.CalledProcessError as e:
        print(f"Compilation error: {e}")
        return None