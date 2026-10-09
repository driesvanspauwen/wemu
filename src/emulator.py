from unicorn import *
from unicorn.x86_const import *
from helper import *
from typing import List, Tuple, Dict, ByteString
from logger import Logger
from cache import *
from rsb import RSB
from read_timer import Timer
from ugir_trace import Trace
from loader import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn
from capstone.x86 import *
import os
import traceback

Checkpoint = Tuple[object, int, int]  # context, next_insn_addr, flags

class MuWMEmulator():
    # initialize capstone
    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    cs.detail = True

    # cache
    CACHE_MISS_CYCLES = 300   # Typical CPU cycles for memory
    REGULAR_INSTR_CYCLES = 1  # Regular instruction timing
    MAX_SPEC_WINDOW = 250

    def __init__(self, name: str, loader: Loader, cache: Cache = None,
                 debug: bool = True, trace: Trace = None):
        # initialize unicorn
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pending_fault_id: int = 0

        # cache
        if cache is None:
            self.cache = InfiniteCache()
        else:
            self.cache = cache

        # rsb
        self.rsb = RSB()

        self.round_count: List[int] = None  # used for sha1_block emulation

        # speculation control
        self.in_speculation: bool = False
        self.speculation_depth: int = 0
        self.speculation_limit: int = 0
        self.previous_context = None

        # OoOE
        self.pending_registers: Set[int] = set()
        self.pending_memory_loads: Set[int] = set()
        self.pending_cache_misses: Set[int] = set()

        # Timing (for rdtscp support)
        self.timer = Timer()
        # Logical order clock: not a CPU latency or speculative-depth estimate.
        self.trace = trace
        self.trace_cycle = 0
        self._trace_cache_lines = set()
        self._trace_seeded = False
        if trace is not None:
            if trace.events:
                raise ValueError("trace must be empty when attached to an emulator")
            if trace.line_size != self.cache.line_size:
                raise ValueError("trace line size differs from cache model")
            if not hasattr(self.cache, "resident_lines"):
                raise ValueError("traced cache requires resident_lines()")

        # instructions
        self.curr_insn: CsInsn
        self.curr_insn_address: int = 0
        self.next_insn_addr: int = 0

        # checkpointing
        self.checkpoints: List[Checkpoint] = []
        self.store_logs: List[List[Tuple[int, ByteString]]] = []  # each entry is a list of (address, prev_value) tuples, one entry per checkpoint

        # logging & compilation
        self.name = name
        self.output_dir = os.path.join("output", name)
        self.logger = Logger(os.path.join(self.output_dir, 'emulation_log.txt'), debug)
        
        # Helper addresses
        self.code_start_address: int
        self.code_exit_addr: int
        # self.fault_handler_addr: int
        self.data_start_addr: int

        # load code & map memory
        self.loader = loader
        self.loader.load(self)

        # hooks
        self.uc.hook_add(UC_HOOK_MEM_READ, self.mem_read_hook, self)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.mem_write_hook, self)
        self.uc.hook_add(UC_HOOK_CODE, self.instruction_hook, self)

    def _trace(self, kind: str, address: int = None, instruction: int = None,
               details: dict = None):
        if self.trace is not None:
            self.trace.add(kind, cycle=self.trace_cycle,
                           phase="transient" if self.in_speculation else "architectural",
                           address=address, instruction=instruction, details=details)

    def _trace_cache_state(self, changed_address: int = None):
        if self.trace is None:
            return
        if changed_address is not None and isinstance(self.cache, InfiniteCache):
            line = (changed_address // self.cache.line_size) * self.cache.line_size
            resident = line in self.cache.cache
            recorded = line in self._trace_cache_lines
            if resident and not recorded:
                self._trace("cache_fill", address=line)
                self._trace_cache_lines.add(line)
            elif recorded and not resident:
                self._trace("cache_evict", address=line)
                self._trace_cache_lines.remove(line)
            return
        current = self.cache.resident_lines()
        for address in sorted(self._trace_cache_lines - current):
            self._trace("cache_evict", address=address)
        for address in sorted(current - self._trace_cache_lines):
            self._trace("cache_fill", address=address)
        self._trace_cache_lines = current

    def checkpoint(self, emulator: Uc, next_insn_addr: int):
        flags = emulator.reg_read(UC_X86_REG_EFLAGS)
        context = emulator.context_save()
        self.store_logs.append([])
        self.log(f"\tCheckpoint at 0x{next_insn_addr:x}")
        self.checkpoints.append((context, next_insn_addr, flags))

    def speculate_fault(self, errno: int) -> int:
        # speculates only division by zero errors currently
        if not errno == 21:
            self.log(f"Unhandled fault: {errno}")
            return 0
        
        # normally, the fault handler would be called after rollback, which continues execution 256 bytes after the faulty instruction
        # modelling this fault handler is difficult, so we manually hardcode the effect of the fault handler
        insn_addr_after_fault = self.curr_insn.address + 256
        self.checkpoint(self.uc, insn_addr_after_fault)
        self._trace("spec_begin", instruction=self.curr_insn.address,
                    details={"trigger": "divide_error"})
        
        self.in_speculation = True
        self.speculation_limit = self.MAX_SPEC_WINDOW
        
        regs_read, _ = self.curr_insn.regs_access()
        if self.check_register_dep(regs_read, self.pending_cache_misses):
            self.speculation_limit += self.CACHE_MISS_CYCLES

        # real processors cant rewrite these registers because they cant reorder instructions that might depend on this data
        self.uc.reg_write(UC_X86_REG_RAX, 0)
        self.uc.reg_write(UC_X86_REG_RDX, 0)

        return self.next_insn_addr

    def speculate_rsb_misprediction(self, actual_ret_addr: int, predicted_ret_addr: int):
        self.checkpoint(self.uc, actual_ret_addr)
        self._trace("spec_begin", instruction=self.curr_insn.address,
                    details={"trigger": "rsb", "predicted": predicted_ret_addr,
                             "actual": actual_ret_addr})
        self.uc.reg_write(UC_X86_REG_RIP, predicted_ret_addr)

        self.in_speculation = True
        self.speculation_limit = self.MAX_SPEC_WINDOW

    def handle_fault(self, errno: int) -> int:
        next_addr = self.speculate_fault(errno)
        if next_addr:
            return next_addr
    
    def skip_curr_insn(self) -> None:
        """Skips current instruction by directly jumping to the next one"""
        address = self.curr_insn.address
        size = self.curr_insn.size
        self.uc.reg_write(UC_X86_REG_RIP, address + size)

    def instruction_hook(self, uc: Uc, address: int, size: int, user_data):
        # when unicorn encounters unsupported instructions (e.g. rdtscp), it might set the size to garbage
        # workaround by setting it to the x86 instruction size limit
        if size > 15: size = 15
        
        try:
            insn_bytes = uc.mem_read(address, size)
        except UcError as e:
            self.log(f"\tError reading instruction bytes at 0x{address:x}: {e}")
            return
        
        for insn in self.cs.disasm(insn_bytes, address, 1): # disassemble only one instruction
            self.timer.increase_cycles(self.REGULAR_INSTR_CYCLES)
            self.trace_cycle += 1

            self.curr_insn = insn
            self.curr_insn_address = address
            self.next_insn_addr = address + size
            self._trace("instruction", instruction=address,
                        details={"mnemonic": insn.mnemonic, "size": insn.size})
            self.log(f"Executing 0x{address:x}: {insn.mnemonic} {insn.op_str}")

            if address == self.code_exit_addr:
                if self.in_speculation:
                    self.uc.emu_stop()
                else:
                    self.finish_emulation()
                return

            if insn.mnemonic == "call":
                return_addr = address + insn.size
                self.log(f"\tCall instruction detected, adding to RSB: 0x{return_addr:x}")

                if self.rsb.add_ret_addr(return_addr):
                    self._trace("rsb_push", instruction=address,
                                details={"target": return_addr})
            
            if insn.mnemonic == "ret":
                predicted_ret_addr = self.rsb.pop_ret_addr()
                self._trace("rsb_pop", instruction=address,
                            details={"target": predicted_ret_addr})
                self.log(f"\tReturn instruction detected, popping from RSB: 0x{predicted_ret_addr:x}")

                rsp = uc.reg_read(UC_X86_REG_RSP)
                actual_ret_addr = int.from_bytes(uc.mem_read(rsp, 8), byteorder='little')

                misprediction = predicted_ret_addr != actual_ret_addr and predicted_ret_addr != 0
                if misprediction:
                    self.log(f"\tRSB misprediction detected: RSB predicted 0x{predicted_ret_addr:x}, actual 0x{actual_ret_addr:x}, RSP located at 0x{rsp:x}")
                    uc.reg_write(UC_X86_REG_RSP, rsp+8) # pop return address from stack for after rollback
                    self.speculate_rsb_misprediction(actual_ret_addr, predicted_ret_addr)

                    return

                return
            
            # Check if instruction is rdtscp
            if insn.mnemonic == "rdtscp":
                self.persist_pending_loads()  # rdtscp waits until all previous loads are globally visisble (Intel manual v2)
                self._trace("readout", instruction=address,
                            details={"kind": "rdtscp"})
                self.timer.rdtscp(self)
                self.skip_curr_insn()
                return
            
            # Check if instruction is clflush
            if insn.mnemonic == "clflush":
                for i, op in enumerate(insn.operands):
                    if op.type == CS_OP_MEM:
                        # Get base register value if it exists
                        base_value = 0
                        if op.mem.base != 0:
                            if op.mem.base == X86_REG_RIP:  # Special handling for RIP-relative addressing
                                # For RIP-relative addressing, we need the address of the next instruction
                                # which is current RIP + instruction size
                                base_value = uc.reg_read(op.mem.base) + insn.size
                            else:
                                base_value = uc.reg_read(op.mem.base)
                        
                        # Get index register value and scale if they exist
                        index_value = 0
                        if op.mem.index != 0:
                            index_value = uc.reg_read(op.mem.index)
                            index_value *= op.mem.scale
                        
                        # Calculate the full address
                        flush_addr = base_value + index_value + op.mem.disp
                        
                        # Flush this address from the cache
                        self.log(f"\tFlushing address 0x{flush_addr:x} from cache")
                        self.cache.flush_address(flush_addr)
                        self._trace("cache_flush", address=flush_addr,
                                    instruction=address)
                        self._trace_cache_state(flush_addr)
                        break
                
                self.skip_curr_insn()
                return

            # Check if instruction is mfence
            if insn.mnemonic == "mfence":
                self.log(f"\tMFENCE encountered, serializing all memory operations")
                self.persist_pending_loads()  # Complete all prior memory ops
                self.pending_registers.clear()  # Clear pending registers
                self.pending_cache_misses.clear()  # Clear pending cache misses
                self.skip_curr_insn()
                return

            # Check if we should execute this instruction based on dependencies
            if not self.can_resolve_deps(insn):
                self.log(f"\tSkipping instruction (resolving dependencies will exceed speculation limit)")
                self.skip_curr_insn()
                return

        self.previous_context = self.uc.context_save()
        
        if self.in_speculation:
            self.speculation_depth += self.REGULAR_INSTR_CYCLES
            self.log(f"\tSpeculation depth: {self.speculation_depth}")

            # and on expired speculation window
            if self.speculation_depth > self.speculation_limit:
                self.log(f"\tSpeculation window exceeded (depth: {self.speculation_depth}, limit: {self.speculation_limit})")
                self.uc.emu_stop()

    def mem_read_hook(self, uc: Uc, access, address: int, size: int, value, user_data):
        _, regs_written = self.curr_insn.regs_access()
        cache_hit = self.cache.is_cached(address)

        # cache miss: add address and registers to pending
        if not cache_hit:
            self.timer.increase_cycles(self.CACHE_MISS_CYCLES)
            self.trace_cycle += 1
            self._trace("memory_read", address=address,
                        instruction=self.curr_insn_address,
                        details={"size": size, "cache_hit": False})
            for reg in regs_written:
                self.pending_cache_misses.add(reg)
                if self.in_speculation:
                    if self.CACHE_MISS_CYCLES > (self.speculation_limit - self.speculation_depth):
                        self.pending_memory_loads.add(address)
                        self.pending_registers.add(reg)

                        self.log(f"\tSkipping instruction (execution will exceed speculation limit)")
                        self.skip_curr_insn()
                    else:
                        self.speculation_depth += self.CACHE_MISS_CYCLES
                        self.log(f"\tReading cache address 0x{address:x}")
                        self.cache.read(address, uc)
                        self._trace_cache_state(address)
                else:
                    self.cache.read(address, uc)
                    self._trace_cache_state(address)
            self.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE MISS")
        
        # cache hit: remove address and registers from pending
        else:
            self.timer.increase_cycles(self.REGULAR_INSTR_CYCLES)
            self.trace_cycle += 1
            self._trace("memory_read", address=address,
                        instruction=self.curr_insn_address,
                        details={"size": size, "cache_hit": True})
            self.cache.read(address, uc)
            self._trace_cache_state(address)
            # self.pending_memory_loads.discard(address)
            # for reg in regs_written:
            #     self.remove_pending_register(reg)

            self.log(f"\tMemory read: address=0x{address:x}, size={size}, CACHE HIT")
        
        self._pretty_print_pending_state(indent=1)

    def mem_write_hook(self, uc: Uc, access, address: int, size: int, value, user_data):
        self.cache.write(address, value)
        self._trace("memory_write", address=address,
                    instruction=self.curr_insn_address,
                    details={"size": size, "value": value})
        self._trace_cache_state(address)
        if self.in_speculation:
            # store the original value in case we need to rollback
            original_value = uc.mem_read(address, size)
            self.store_logs[-1].append((address, original_value))
        self.log(f"\tMemory write: address=0x{address:x}, size={size}, value=0x{value:x}")

    def rollback(self):
        self.log(f"RSP before rollback: 0x{self.uc.reg_read(UC_X86_REG_RSP):x}")
        state, next_insn_addr, flags = self.checkpoints.pop()
        
        self.persist_pending_loads()
        self._trace("spec_end", instruction=self.curr_insn_address,
                    details={"rollback": True})

        # reset speculative state
        self.in_speculation = False
        self.speculation_depth = 0
        self.speculation_limit = 0
        
        # restore registers
        self.uc.context_restore(state)

        # rollback memory changes
        mem_changes = self.store_logs.pop()
        while mem_changes:
            addr, val = mem_changes.pop()
            self.uc.mem_write(addr, bytes(val))
        
        # restore flags
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags)

        self.log(f"\tRollback complete")

        return next_insn_addr
    
    def persist_pending_loads(self):
        """
        Persist pending memory loads to the cache.
        """
        self.log("Persisting pending memory loads...")
        self._pretty_print_pending_state(indent=1)
        for address in self.pending_memory_loads:
            self.cache.write(address, self.uc.mem_read(address, self.cache.line_size))
            self._trace("pending_load_fill", address=address,
                        instruction=self.curr_insn_address)
            self._trace_cache_state(address)
        self.pending_memory_loads.clear()
        self.pending_registers.clear()
        self.pending_cache_misses.clear()

    def reset_round_state(self):
        """Reset the existing Flexo round state through trace-aware transitions."""
        self.persist_pending_loads()
        self.cache.reset()
        self._trace_cache_state()
        if self.in_speculation:
            self._trace("spec_end", details={"rollback": False,
                                             "trigger": "round_reset"})
        self.in_speculation = False
        self.speculation_depth = 0
        self.speculation_limit = 0
        self.timer.cycles = 0

    def can_resolve_deps(self, insn: CsInsn):
        """
        Determines if an instruction can resolve its dependencies within the speculative limit.
        """
        if not self.in_speculation:
            # only perform OOO execution in speculation
            return True

        regs_read, regs_written = insn.regs_access()

        dep = self.check_register_dep(regs_read, self.pending_registers)
        self.log(f"\tRAW Dependency: {dep}")

        # no dependencies
        if not dep:
            for reg in regs_written:
                self.remove_pending_register(reg)

            return True

        # update resolve times for affected registers
        for reg in regs_written:
            self.pending_registers.add(reg)

        # print(f"\tMax cycle wait: {max_cycle_wait}, speculation limit: {self.speculation_limit}")
        # return max_cycle_wait <= self.speculation_limit
        return False
    
    def check_register_dep(self, regs_read: Set[int], regs_pending: Set[int]) -> bool:
        """
        
        """
        self.log(f"\tRegs read: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_read]}")
        self.log(f"\tRegs pending: {[f'{self.cs.reg_name(reg_id)}' for reg_id in regs_pending]}")
        
        for reg_read in regs_read:
            for reg_pending in regs_pending:
                if reg_read == reg_pending or registers_alias(reg_read, reg_pending):
                    return True
                    
        return False
    
    def remove_pending_register(self, reg_id: int):
        """
        Remove a register and all its aliases from pending_registers.
        """
        from helper import get_register_aliases
        
        # Get all aliases for this register
        aliases = get_register_aliases(reg_id)
        
        # Remove the register and all its aliases from pending_registers
        for alias in aliases:
            if alias in self.pending_registers:
                self.log(f"\tRemoving pending register {self.cs.reg_name(alias)}")
                self.pending_registers.discard(alias)

    
    def emulate(self):
        if self.trace is not None and not self._trace_seeded:
            self._trace_cache_state()
            for target in self.rsb.stack:
                self._trace("rsb_push", details={"target": target})
            self._trace_seeded = True
        start_address = self.code_start_address
        while True:
            self.pending_fault_id = 0

            if start_address is None:
                self.finish_emulation()
                return

            try:
                self.log(f"(Re)starting emulation with start address 0x{start_address:x}, exit address 0x{self.code_exit_addr:x}")
                self.log(f"Execution mode: {'speculative (limit: ' + str(self.speculation_limit) + ')' if self.in_speculation else 'normal'}")
                self.uc.emu_start(start_address, -1)

                if self.curr_insn_address == self.code_exit_addr and not self.in_speculation:
                    return
                
            except UcError as e:
                self.log(f"\tError interpreting instruction at 0x{self.curr_insn.address:x}: {e}")
                self.pending_fault_id = int(e.errno)
            
            except Exception as e:
                error_msg = f"Unhandled exception (stopping emulation): {e}"
                stack_trace = traceback.format_exc()
                self.log(f"{error_msg}\n{stack_trace}")
                print(f"{error_msg}\n{stack_trace}")
                self.finish_emulation()
                return

            if self.pending_fault_id:
                # workaround for a Unicorn bug: after catching an exception
                # we need to restore some pre-exception context. otherwise,
                # the emulator becomes corrupted
                self.uc.context_restore(self.previous_context)
                # another workaround, specifically for flags
                self.uc.reg_write(UC_X86_REG_EFLAGS, self.uc.reg_read(UC_X86_REG_EFLAGS))
            
                start_address = self.handle_fault(self.pending_fault_id)

                self.pending_fault_id = 0
                if start_address and start_address != self.code_exit_addr:
                    self.log(f"\tSetting start address at 0x{start_address:x}")
                    continue
            
            # used to resume emulation after rollback
            if self.in_speculation:
                start_address = self.rollback()
                continue
    
    def finish_emulation(self):
        self.persist_pending_loads()
        self.log("Emulation finished")
        self.uc.emu_stop()

    def _pretty_print_pending_state(self, indent=0):
        """
        Pretty prints the current state of pending memory loads and registers.
        """
        indent_str = "\t" * indent
        self.log(f"{indent_str}Pending memory loads: {[f'0x{address:x}' for address in self.pending_memory_loads]}")
        
        # Update to show both register names and cycle counts
        reg_entries = [self.cs.reg_name(reg_id) for reg_id in self.pending_registers]
        self.log(f"{indent_str}Pending registers: {reg_entries}")
    
    def log(self, message: str):
        """
        Log a message using the logger. You can use this method to constraint logging to specific regions of the code.
        """
        self.logger.log(message)
