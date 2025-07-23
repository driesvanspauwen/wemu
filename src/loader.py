from unicorn import *
from unicorn.x86_const import *
from compiler import compile_asm
from typing import Protocol, runtime_checkable
from elftools.elf.elffile import ELFFile
from logger import Logger

@runtime_checkable
class EmulatorInterface(Protocol):
    """
    Protocol defining the interface for an emulator.
    Provides type checking without creating a circular dependency.
    """
    uc: Uc
    output_dir: str

    # Helper addresses
    code_start_address: int
    code_exit_addr: int
    fault_handler_addr: int
    data_start_addr: int

    # logger
    logger: Logger

class Loader():
    def load(self, emulator: EmulatorInterface):
        """Abstract method to load code into the emulator"""
        pass

class AsmLoader(Loader):
    CODE_BASE = 0x1000
    DATA_BASE = 0x2000
    STACK_BASE = 0x3000
    REGION_SIZE = 0x1000

    def __init__(self, asm_code: str):
        self.asm_code = asm_code

    def load(self, emulator: EmulatorInterface):
        """Load assembly code into the emulator"""
        output_dir = emulator.output_dir
        self.machine_code = compile_asm(self.asm_code, output_dir=output_dir)
        self._map_memory(emulator)
    
    def _map_memory(self, emulator: EmulatorInterface):
        """Map memory for the emulator"""
        # memory mappings
        emulator.uc.mem_map(self.CODE_BASE, self.REGION_SIZE, UC_PROT_ALL)
        emulator.uc.mem_map(self.DATA_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        emulator.uc.mem_map(self.STACK_BASE, self.REGION_SIZE, UC_PROT_READ | UC_PROT_WRITE)

        emulator.uc.mem_write(self.CODE_BASE, self.machine_code)
        
        emulator.uc.reg_write(UC_X86_REG_RSP, self.STACK_BASE + self.REGION_SIZE - 8)  # Stack pointer

        # helper addresses
        emulator.code_start_address = self.CODE_BASE
        emulator.code_exit_addr = self.CODE_BASE + len(self.machine_code)
        emulator.fault_handler_addr = emulator.code_exit_addr  # No fault handler in asm snippet
        emulator.data_start_addr = self.DATA_BASE

class ELFLoader(Loader):
    STACK_ADDR = 0x70000000
    STACK_SIZE = 0x10000000

    def __init__(self, elf_path: str, stack_addr: int = STACK_ADDR, stack_size: int = STACK_SIZE):
        self.elf_path = elf_path
        self.stack_addr = stack_addr
        self.stack_size = stack_size
    
    def load(self, emulator: EmulatorInterface):
        """Load ELF file into the emulator"""
        self.f = open(self.elf_path, "rb")
        self.elf = ELFFile(self.f)
        
        self.map_segments(emulator)
        self.map_stack(emulator)
    
    def map_segments(self, emulator: EmulatorInterface):
        emulator.logger.log("Mapping segments:")
        for segment in self.elf.iter_segments():
            if segment.header.p_type == 'PT_LOAD':  # Only consider loadable segments
                # Calculate memory size (page-aligned)
                mem_start = segment.header.p_vaddr & ~0xFFF  # Page align
                mem_end = (segment.header.p_vaddr + segment.header.p_memsz + 0xFFF) & ~0xFFF
                mem_size = mem_end - mem_start

                # Determine segment permissions
                perm = 0
                if segment.header.p_flags & 0x1:  # PF_X - Execute
                    perm |= UC_PROT_EXEC
                if segment.header.p_flags & 0x2:  # PF_W - Write
                    perm |= UC_PROT_WRITE
                if segment.header.p_flags & 0x4:  # PF_R - Read
                    perm |= UC_PROT_READ
                    
                # Make sure we have at least read permission
                if perm == 0:
                    perm = UC_PROT_READ
                    
                # Map memory region used by segment
                emulator.logger.log(f"Mapping segment at 0x{mem_start:x} - 0x{mem_end-1:x}, size: 0x{mem_size:x}")
                
                try:
                    emulator.uc.mem_map(mem_start, mem_size, perm)
                    
                    # Map segment data
                    data = segment.data()
                    emulator.uc.mem_write(segment.header.p_vaddr, data)
                    emulator.logger.log(f"\tData written: 0x{len(data):x} bytes at 0x{segment.header.p_vaddr:x}")
                    
                    # Zero out uninitialized data
                    if segment.header.p_memsz > segment.header.p_filesz:
                        padding_size = segment.header.p_memsz - segment.header.p_filesz
                        padding_addr = segment.header.p_vaddr + segment.header.p_filesz
                        emulator.uc.mem_write(padding_addr, b'\x00' * padding_size)
                        emulator.logger.log(f"\tZeroed: 0x{padding_size:x} bytes at 0x{padding_addr:x}")
                except UcError as e:
                    emulator.logger.log(f"\tError mapping segment: {e}")
    
    def map_stack(self, emulator: EmulatorInterface):
        emulator.logger.log(f"Mapping stack with base 0x{self.stack_addr:x} and size 0x{self.stack_size:x}")
        emulator.uc.mem_map(self.stack_addr, self.stack_size, UC_PROT_READ | UC_PROT_WRITE)
        emulator.uc.reg_write(UC_X86_REG_RSP, self.stack_addr + self.stack_size - 0x100)

        