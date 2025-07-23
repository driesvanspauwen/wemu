from unicorn import *
from unicorn.x86_const import *
from typing import Protocol, runtime_checkable
from logger import Logger

@runtime_checkable
class EmulatorInterface(Protocol):
    """
    Protocol defining the interface for an emulator.
    Provides type checking without creating a circular dependency.
    """
    uc: Uc
    logger: Logger

class Timer():
    def __init__(self):
        self.reset()
    
    def rdtscp(self, emulator: EmulatorInterface):
        if self.active:
            emulator.logger.log(f"\tRDTSC cycles: {self.cycles}")
            emulator.uc.reg_write(UC_X86_REG_RAX, self.cycles & 0xFFFFFFFF)
            emulator.uc.reg_write(UC_X86_REG_RDX, (self.cycles >> 32) & 0xFFFFFFFF)
            self.reset()
        else:
            emulator.logger.log(f"\tRDTSC cycles: {self.cycles}")
            emulator.uc.reg_write(UC_X86_REG_RAX, 0)
            emulator.uc.reg_write(UC_X86_REG_RDX, 0)
            self.active = True
    
    def increase_cycles(self, cycles):
        if self.active:
            self.cycles += cycles

    def reset(self):
        self.active = False
        self.cycles = 0