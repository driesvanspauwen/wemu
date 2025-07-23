import ctypes
import os
import subprocess
import atexit

# Global variables to track the library and file for cleanup
_sha1_lib = None
_so_file_path = None

def _cleanup_sha1_lib():
    """Clean up the compiled library file"""
    global _so_file_path
    if _so_file_path and os.path.exists(_so_file_path):
        try:
            os.unlink(_so_file_path)
        except OSError:
            pass

def get_sha1_lib():
    """Get the compiled SHA-1 library (compile if needed)"""
    global _sha1_lib, _so_file_path
    
    if _sha1_lib is not None:
        return _sha1_lib
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    so_file = os.path.join(current_dir, "sha1_round.so")
    c_file = os.path.join(current_dir, "sha1_round.c")
    
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
    lib.ref_sha1_round_c.argtypes = [
        ctypes.POINTER(ctypes.c_uint),  # inputs (unsigned*)
        ctypes.c_uint,                  # w (unsigned)
        ctypes.POINTER(ctypes.c_uint),  # outputs (unsigned*)
        ctypes.c_uint                   # round (unsigned)
    ]
    lib.ref_sha1_round_c.restype = None
    
    # Cache the library
    _sha1_lib = lib
    
    # Register cleanup function to run at exit
    atexit.register(_cleanup_sha1_lib)
    
    return lib

def ref_sha1_round(inputs, w, round_num=0):
    """Reference implementation using the actual C code"""
    lib = get_sha1_lib()
    
    # Convert inputs to ctypes arrays - use c_uint to match 'unsigned'
    inputs_arr = (ctypes.c_uint * 5)(*inputs)
    outputs_arr = (ctypes.c_uint * 5)()
    
    # Call C function
    lib.ref_sha1_round_c(inputs_arr, w, outputs_arr, round_num)
    
    # Convert back to Python list
    return list(outputs_arr)