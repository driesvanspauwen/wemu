# WeMu: Effective and Scalable Emulation of Microarchitectural Weird Machines

This repository contains the artifact for the paper [WeMu: Effective and Scalable Emulation of Microarchitectural Weird Machines](https://uasc.cc/proceedings26/uasc26-vanspauwen.pdf) submitted to uASC 2026.

WeMu is the first emulation framework designed specifically for analyzing Microarchitectural Weird Machines (µWMs), enabling observation and reverse engineering of hidden microarchitectural computations.

## Quick Start

### Option 1: Docker (Recommended)
```bash
# Clone and build (one-time setup)
git clone https://github.com/driesvanspauwen/wemu.git
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

## UGIR substrate extension

The extension adds a versioned microarchitectural trace to `MuWMEmulator` and
a capability registry covering UGIR's five demonstrated compute classes and
eight observed-only classes. Pass `trace=Trace()` when constructing an
emulator, then save `trace.to_json()` to inspect or replay state changes.
Tracing is optional; the original gate runners keep their existing API.

```python
from emulator import MuWMEmulator
from ugir_trace import Trace

trace = Trace()
emulator = MuWMEmulator(name="example", loader=loader, trace=trace, debug=False)
# Set the usual code start, exit, and input state, then call emulator.emulate().
open("trace.json", "w", encoding="utf-8").write(trace.to_json())
```

```bash
cd src
python ugir_cli.py capabilities
python ugir_cli.py replay trace.json
python ugir_cli.py replay trace.json --at 42
python ugir_cli.py verify-evidence --ugir-root /path/to/ugir
python ugir_cli.py ingest-tlb native-capture.txt --threshold 39 --seed 5001 --trials-per-row 2000 --output tlb-trace.json
python -m unittest discover -s tests -p 'test_ugir_*.py'
```

The cache and exception/RSB mechanisms remain the instruction-executed
baseline described in the [WeMu paper](https://vanbulck.net/files/uasc26-wemu.pdf).
`replay --at` shows the state after one trace event, including speculative
stores, RSB contents, cache lines, and the abstract predictor/translation
registers. The full trace can be inspected without requiring a completed
speculation window at the selected event.
BTB, TLB, and memory-dependence transitions in `ugir_trace.py` are deliberately
abstract replay models. They expose hypotheses for testing; they do not
emulate those UGIR gates from binaries or establish CPU-specific fidelity.
Observed-only classes have no gate-emulation capability. The capability CLI
reports each mechanism's status explicitly.

`verify-evidence` checks six cases across five distinct primary UGIR source
files, including one rejected control, against SHA-256 and recorded native
counts. Cache and transient-window roles share one AMD record; they are not
independent silicon runs. Three positive JSON records are aggregate oracle
outputs, so they do not preserve per-attempt order or timing. The TLB
histogram also lacks attempt order; its sham has different address geometry.
The TLB report therefore marks `sham_source_recount_verified: true` and
`controls_verified: false`; the latter does not invalidate the recorded counts.
Most referenced UGIR `data/` records are gitignored in that separate checkout;
provide the exact local source files or the verifier fails. Its result reports
`model_fidelity: not_assessed` even when a source oracle status is admitted.
Its `source_verified` field means the pinned bytes and selected measurements
were checked; `schema_validation: not_assessed` means this command did not run
the version-specific UGIR reader.
The CPU string in the manifest is an annotation. JSON cases verify source
model and machine IDs; the TLB batch verifies logical CPU index 4, not the
human CPU model. Trace `cycle` values are logical-order ticks, not silicon
timings or speculative depth.
Native reproduction requires the source's supported x86-64 Linux CPU and
the UGIR runner; the portable tests verify stored evidence only.
An [AMD live validation report](docs/ugir-amd-live-validation-2026-10-09.md)
retains four raw cache-AND records from two source versions and two seeds;
the version-specific reader and admission policy are recorded there.

`ingest-tlb` accepts four-row AND output from the optional
[`native/ugir_tlb_ordered_capture.c`](native/ugir_tlb_ordered_capture.c)
timer wrapper linked to an existing UGIR TLB gate object. It checks that each
ordered rail latency reconstructs the source's H/J histograms and AND counts,
then exports one architectural readout event per trial. The capture header
records the wrapper's threshold, seed, row count, and gate label; ingestion
requires them to match the requested threshold, seed, and count. The trace preserves
attempt order and a SHA-256 computed from the native output at ingestion.
`replay` does not reopen that source or verify its hash. CPU/core and binary
identity must be retained separately. The trace does not expose hidden TLB
state or predict the gate. A wrapper can perturb timings; compare an
instrumented run with the original under the same CPU protocol before using
it as silicon evidence. The [Raptor Lake capture report](docs/ugir-rpl-tlb-capture-2026-10-09.md)
records the current native-run limitation.

Design and acceptance details are in [docs/ugir-extension-design.md](docs/ugir-extension-design.md)
and [docs/ugir-extension-plan.md](docs/ugir-extension-plan.md).

# References

[1] Wang, P. L., Brown, F., & Wahby, R. S. (2023, May). The ghost is the machine: Weird machines in transient execution. In *2023 IEEE Security and Privacy Workshops (SPW)* (pp. 264-272). IEEE.

[2] Wang, P. L., Paccagnella, R., Wahby, R. S., & Brown, F. (2024). Bending microarchitectural weird machines towards practicality. In *33rd USENIX Security Symposium (USENIX Security 24)* (pp. 1099-1116).

# License
This project is licensed under the MIT License. See the [`LICENSE`](./LICENSE) file for full details.

# Citation
If you use or extend this work, please cite it as:
```
@inproceedings{vanspauwen2026wemu,
  title     = {WeMu: Effective and Scalable Emulation of Microarchitectural Weird Machines},
  author    = {Vanspauwen, Dries and Daniel, Lesly-Ann and Van Bulck, Jo},
  booktitle = {2nd Microarchitecture Security Conference ({uASC})},
  month     = Feb,
  year      = 2026
}
```
