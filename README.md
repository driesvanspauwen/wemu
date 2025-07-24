# WeMu: Effective and Scalable Emulation of Microarchitectural Weird Machines

This repository contains the artifact for the paper "WeMu: Effective and Scalable Emulation of Microarchitectural Weird Machines" submitted to uASC 2026 (<paper_url>).

WeMu is the first emulation framework designed specifically for analyzing Microarchitectural Weird Machines (µWMs), enabling observation and reverse engineering of hidden microarchitectural computations.

## Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone and build (one-time setup)
git clone <paper_artifact_repo.git>
cd wemu
docker build -t wemu .

# Run the container
docker run -it wemu

# Inside the container, everything is ready:
python unit_tests.py all
```

### Option 2: Local Installation
Requirements:
- Python 3.9 or higher
- GCC
- Linux/Unix environment (recommended)
- NASM and binutils (optional, for assembly tests only)

Setup:
1. Clone the repository.
2. Install the requirements from [`requirements.txt`](./requirements.txt).
3. Navigate to [`src`](./src) where you have access to the tests.

### Running Tests
This repository includes a unit testing framework for validating WeMu's computational output when emulating the 24 µWMs from previous work.
The unit testing framework can be controlled through a CLI as follows:
```bash
# Run all 24 µWM implementations from evaluation
python unit_tests.py all

# Run specific categories
python unit_tests.py flexo    # RSB-based µWMs
python unit_tests.py gitm     # Exception-based µWMs
python unit_tests.py asm      # Assembly test cases

# Run individual tests
python unit_tests.py test_gitm_and
python unit_tests.py test_flexo_simon32
```

### Expected Output
Successful test runs should show output like:
```
$ python unit_tests.py test_gitm_and
--- Running test_gitm_and ---
Test passed for AND(0, 0)
Test passed for AND(0, 1)
Test passed for AND(1, 0)
Test passed for AND(1, 1)
```

### Enabling Execution Traces
By default, running the tests will _not_ produce execution traces for debugging and analysis, these can be enabled by passing `debug=True` to the `run_<muwm_name>_test` or `emulate_<framework_name>_<muwm_name>_test` functions. Note that if a unit test iterates over multiple input combinations, the debug logs will be overwritten for every iteration, so only those from the last input combination will remain visible.

# Repository Structure

## Microarchitectural modeling
These components contribute to modeling microarchitectural effects:
- [`Cache`](./src/cache.py) Contains a model of a finite-size LRU cache and an infinite cache. Our evaluation uses the latter, because the former introduces cache conflicts between microarchitectural weird registers causing several emulation errors.
- [`RSB`](./src/rsb.py) A simple RSB implementation.
- [`Timer`](./src/read_timer.py) An abstraction of the time-stamp counter.
- [`MuWMEmulator`](./src/emulator.py) The backbone of WeMu that runs the emulations. Models transient and out-of-order execution effects and updates the state of other microarchitectural models correctly.

## Helper components
These are helper components used when emulating binaries:
- [`Compiler`](./src/compiler.py) Compiles assembly snippets to binaries that can be interpreted by Unicorn.
- [`Loader`](./src/loader.py) Contains `AsmLoader` for loading assembly snippets and `ElfLoader` for loading full ELF binaries. They offer automatic (but customizable) memory setup in Unicorn. WeMu requires one of these for loading its inputs. 
- [`Logger`](./src/logger.py) Can be used to build execution traces and outputs them to designated logs.

## Unit Testing Framework
- [`unit_tests.py`](./src/unit_tests.py) Main test runner.
- [`tests/flexo_tests.py`](./src/tests/flexo_tests.py) RSB-based µWM tests (17 µWMs) [2]
- [`tests/gitm_tests.py`](./src/tests/gitm_tests.py) Exception-based µWM tests (7 implementations) [1]
- [`tests/asm_tests.py`](./src/tests/asm_tests.py) Our self-built assembly µWM implementations, heavily based on the GITM tests.
- [`tests/ref`](./src/tests/ref/) Directory containing reference implementations for µWM validation (C source code copied directly from original code artifacts)

# Custom µWM Analysis
To analyze your own µWM, you can choose between emulating your µWM directly from an assembly implementation or emulating an actual binary. We discuss when to use each method and provide our recommended steps to extend the unit testing framework to enable your analysis.

## Assembly Emulation
This option is suitable when quickly testing specific small, isolated µWM features. We recommend the following steps to set it up:

1. Add your µWM assembly implementation in [`gates/asm.py`](./src/gates/asm.py).
2. Create a function `emulate_asm_<muwm_name>` in [`tests/asm_tests.py`](./src/tests/asm_tests.py). This function takes logical inputs that would be passed to the µWM normally and sets up the registers accordingly. Use the [`AsmLoader`](./src/loader.py) to automate memory setup and adapt its constants if necessary (e.g., if the memory regions are too small and memory contents overlap)
3. Create a function `test_asm_<muwm_name>` in [`unit_tests.py`](./src/unit_tests.py), which calls the `emulate_asm_<muwm_name>` function with the desired inputs (for instance, you can set this function up to enumerate all possible inputs, or iterate over a constant number of randomized inputs), and verifies this against a reference implementation.

## Binary Emulation
Binary emulation is suitable when analyzing µWM ELF binaries. We recommend emulating only the region of interest (which contains the actual µWM implementation code) and setting up memory manually to match what is expected by the µWM. An object dump can help with this setup. We recommend the following steps to set it up. Note that we follow our existing approach of grouping together µWMs from different frameworks -- in our case, those refer to Flexo (RSB-based [2]) and GITM (exception-based [1]). Feel free to omit the framework name if not applicable:

1. Add your µWM binary implementation in [`gates/<framework_name>`](./src/gates). 
2. Create a function `emulate_<framework_name>_<muwm_name>` in [`tests/<framework_name>_tests.py`](./src/tests/asm_tests.py). This function takes logical inputs that would be passed to the µWM normally and sets up memory accordingly. Use the [`ELFLoader`](./src/loader.py) to automate memory setup and adapt its constants if necessary (e.g., if the memory regions are too small and memory contents overlap). Since Unicorn does not emulate dynamic library calls or system calls, you might have to add Unicorn hooks to simulate the effect of such calls.
3. Create a function `test_<framework_name>_<muwm_name>` in [`unit_tests.py`](./src/unit_tests.py), which calls the `emulate_<framework_name>_<muwm_name>` function with the desired inputs (for instance, you can set this function up to enumerate all possible inputs, or iterate over a constant number of randomized inputs), and verifies this against a reference implementation.

## Adapting Execution Trace Logging
The [`MuWMEmulator`](./src/emulator.py) produces execution traces for debugging or analysis purposes when its constructor argument `debug` is set. You can customize the logging in three different ways:
1. Add debug hooks in the `emulate_<framework_name>_<muwm_name>` function which produce logs via `emulator.logger.log(message)`
2. Add logging information directly in the [`MuWMEmulator`](./src/emulator.py) implementation via `self.log(message)`
3. Limit the logging to specific regions in the binary by changing the `MuWMEmulator.log(message)` implementation, e.g.:
    ```python
    def log(self, message: str):
        if 0x1000 <= self.curr_insn_address < 0x2000:
            self.logger.log(message)
    ```

# References

[1] Wang, P. L., Brown, F., & Wahby, R. S. (2023, May). The ghost is the machine: Weird machines in transient execution. In *2023 IEEE Security and Privacy Workshops (SPW)* (pp. 264-272). IEEE.

[2] Wang, P. L., Paccagnella, R., Wahby, R. S., & Brown, F. (2024). Bending microarchitectural weird machines towards practicality. In *33rd USENIX Security Symposium (USENIX Security 24)* (pp. 1099-1116).

# License
This project is licensed under the MIT License. See the [`LICENSE`](./LICENSE) file for full details.
