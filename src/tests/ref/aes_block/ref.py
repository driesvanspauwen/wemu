import ctypes
import os
import subprocess
import atexit

# Global variables to track the library and file for cleanup
_aes_block_lib = None
_so_file_path = None

def _cleanup_aes_block_lib():
    """Clean up the compiled library file"""
    global _so_file_path
    if _so_file_path and os.path.exists(_so_file_path):
        try:
            os.unlink(_so_file_path)
        except OSError:
            pass

def get_aes_block_lib():
    """Get the compiled AES block library (compile if needed)"""
    global _aes_block_lib, _so_file_path
    
    if _aes_block_lib is not None:
        return _aes_block_lib
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    so_file = os.path.join(current_dir, "aes_block.so")
    c_file = os.path.join(current_dir, "aes_block.c")
    
    _so_file_path = so_file
    
    # Check if C file exists
    if not os.path.exists(c_file):
        raise FileNotFoundError(f"C wrapper file {c_file} not found")
    
    if os.path.exists(so_file):
        os.unlink(so_file)
        
    subprocess.run([
        'gcc', '-shared', '-fPIC', '-O2',
        '-o', so_file, c_file
    ], check=True, capture_output=True, text=True)
    
    # Load the library
    lib = ctypes.CDLL(so_file)
    
    # Set up function signature
    lib.ref_aes_block_c.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # input (const byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # key (const byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # output (byte*)
    ]
    lib.ref_aes_block_c.restype = None
    
    # Cache the library
    _aes_block_lib = lib
    
    # Register cleanup function to run at exit
    atexit.register(_cleanup_aes_block_lib)
    
    return lib

def ref_aes_block(input_data, key_data):
    """Reference implementation using the actual C code"""
    lib = get_aes_block_lib()
    
    # Convert inputs to ctypes arrays - use c_ubyte for byte*
    input_arr = (ctypes.c_ubyte * 16)(*input_data)
    key_arr = (ctypes.c_ubyte * 16)(*key_data)
    output_arr = (ctypes.c_ubyte * 16)()
    
    # Call C function
    lib.ref_aes_block_c(input_arr, key_arr, output_arr)
    
    # Convert back to Python list
    return list(output_arr)