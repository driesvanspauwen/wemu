import os
import datetime

class Logger:
    def __init__(self, log_file, debug: bool = True, log_time: bool = False, max_size_bytes=10 * 1024 * 1024):
        self.debug = debug
        self.log_time = log_time
        self.base_log_file = log_file
        self.max_size = max_size_bytes
        
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(self.base_log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.log_file = self._get_latest_log_file()
        self._initialized_files = set()
    
    def _get_log_indexed_name(self, index: int) -> str:
        base, ext = os.path.splitext(self.base_log_file)
        if index == 0:
            return self.base_log_file  # First file uses original name
        return f"{base}_{index}{ext}"
    
    def _get_latest_log_file(self) -> str:
        index = 0
        while True:
            candidate = self._get_log_indexed_name(index)
            if not os.path.exists(candidate) or os.path.getsize(candidate) < self.max_size:
                return candidate
            index += 1
    
    def log(self, message):
        if not self.debug:
            return
        
        if self.log_time:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            message = f"[{timestamp}] {message}"
        
        # Check if we need to rotate to a new log file
        if os.path.exists(self.log_file) and os.path.getsize(self.log_file) >= self.max_size:
            self.log_file = self._get_latest_log_file()
        
        # Use 'w' mode for the first write to this specific file, then 'a' for subsequent writes
        file_already_initialized = self.log_file in self._initialized_files
        mode = 'a' if file_already_initialized else 'w'
        
        with open(self.log_file, mode) as f:
            f.write(message + '\n')
        
        # Mark this file as initialized
        if not file_already_initialized:
            self._initialized_files.add(self.log_file)