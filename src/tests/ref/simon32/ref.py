import ctypes
import os
import subprocess
import atexit

# Global variables to track the library and file for cleanup
_simon_lib = None
_so_file_path = None

def _cleanup_simon_lib():
    """Clean up the compiled library file"""
    global _so_file_path
    if _so_file_path and os.path.exists(_so_file_path):
        try:
            os.unlink(_so_file_path)
        except OSError:
            pass

def get_simon_lib():
    """Get the compiled Simon32 library (compile if needed)"""
    global _simon_lib, _so_file_path
    
    if _simon_lib is not None:
        return _simon_lib
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    so_file = os.path.join(current_dir, "simon32.so")
    c_file = os.path.join(current_dir, "simon32.c")
    
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
    lib.ref_simon_encrypt_c.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # input (byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # key (byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # output (byte*)
    ]
    lib.ref_simon_encrypt_c.restype = None
    
    # Cache the library
    _simon_lib = lib
    
    # Register cleanup function to run at exit
    atexit.register(_cleanup_simon_lib)
    
    return lib

def ref_simon32(input_data, key_data):
    """Reference implementation using the actual C code"""
    lib = get_simon_lib()
    
    # Convert inputs to ctypes arrays - use c_ubyte for byte*
    input_arr = (ctypes.c_ubyte * 4)(*input_data)
    key_arr = (ctypes.c_ubyte * 8)(*key_data)
    output_arr = (ctypes.c_ubyte * 4)()
    
    # Call C function
    lib.ref_simon_encrypt_c(input_arr, key_arr, output_arr)
    
    # Convert back to Python list
    return list(output_arr)