import ctypes
import os
import subprocess
import atexit

# Global variables to track the library and file for cleanup
_alu_lib = None
_so_file_path = None

def _cleanup_alu_lib():
    """Clean up the compiled library file"""
    global _so_file_path
    if _so_file_path and os.path.exists(_so_file_path):
        try:
            os.unlink(_so_file_path)
        except OSError:
            pass

def get_alu_lib():
    """Get the compiled ALU library (compile if needed)"""
    global _alu_lib, _so_file_path
    
    if _alu_lib is not None:
        return _alu_lib
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    so_file = os.path.join(current_dir, "alu.so")
    c_file = os.path.join(current_dir, "alu.c")
    
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
    lib.ref_alu_c.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),  # x (byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # y (byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # control (byte*)
        ctypes.POINTER(ctypes.c_ubyte),  # out (byte*)
    ]
    lib.ref_alu_c.restype = None
    
    # Cache the library
    _alu_lib = lib
    
    # Register cleanup function to run at exit
    atexit.register(_cleanup_alu_lib)
    
    return lib

def ref_alu(x_data, y_data, control_data):
    """Reference implementation using the actual C code"""
    lib = get_alu_lib()
    
    # Convert inputs to ctypes arrays - use c_ubyte for byte*
    x_arr = (ctypes.c_ubyte * 1)(x_data)
    y_arr = (ctypes.c_ubyte * 1)(y_data)
    control_arr = (ctypes.c_ubyte * 1)(control_data)
    out_arr = (ctypes.c_ubyte * 1)()
    
    # Call C function
    lib.ref_alu_c(x_arr, y_arr, control_arr, out_arr)
    
    # Return the single output byte
    return out_arr[0]