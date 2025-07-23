from typing import List, Set, Tuple

class RSB:
    def __init__(self, exception_addrs: Set[int] = None):
        self.stack: List[int] = []

        # Set of addresses that the RSB never stores
        self.exception_addrs: Set[int] = exception_addrs or set()
    
    def add_exception_addr(self, addr: int):
        self.exception_addrs.add(addr)
    
    def remove_exception_addr(self, addr: int):
        if addr in self.exception_addrs:
            self.exception_addrs.remove(addr)
    
    def add_ret_addr(self, predicted_addr: int):
        """
            predicted_addr: The predicted return address (call_addr + call_size)
        """
        if predicted_addr not in self.exception_addrs:
            self.stack.append(predicted_addr)
    
    def pop_ret_addr(self) -> int:
        if self.stack:
            return self.stack.pop()
        else:
            print("WARNING: RSB underflow, returning 0")
            return 0
    
    def is_empty(self) -> bool:
        return len(self.stack) == 0