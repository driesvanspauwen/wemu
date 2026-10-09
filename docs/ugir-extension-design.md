# UGIR substrate extension for WeMu

## Goal and evidence boundary

Extend the paper's instruction-level cache/exception/RSB emulator with a
single trace and model interface for the substrate classes inventoried by
UGIR. Keep three results distinct: deterministic model behavior, comparison
with native silicon records, and an oracle admission claim. A simulated gate
truth table is never a native reliability or transient-admission result.

The paper's WeMu uses an infinite cache-presence model and tests exception
and RSB machines. Its evaluation does not validate BTB, TLB, or dependence
predictor behavior. This extension preserves that baseline and makes new
models opt-in and explicitly scoped.

## Taxonomy and capability levels

UGIR identifies five demonstrated compute classes: cache; transient and
out-of-order window; branch predictor; TLB and page walk; and load/store,
fill, and dependence buffers. It also identifies eight observed-only classes:
prefetcher, execution ports, DRAM row buffer, interconnect/coherence, memory
controller, power/frequency, GPU/accelerator/FPGA, and micro-op cache/frontend.

Each class must appear in a machine-readable registry with a capability:
`instruction` (effect arises from executing guest instructions), `trigger`
(opens a window for a gate on another substrate), `abstract` (deterministic
event-state model), `observation` (trace only), or `unsupported`. Gate
emulation is a separate explicit set; the current set contains only the
paper's cache-line gates. An RSB transient trigger is not a branch-predictor
weird register. An abstract model does not assert that real silicon uses its
transition rules.

## Architecture

1. `MicroEvent` captures guest instruction, address, phase, logical-order tick,
   and a typed event kind. Event sequence numbers and a versioned JSON export
   make traces independently replayable. The CLI can inspect the modeled state
   immediately after any event, including an open speculation window.
2. Current Unicorn hooks emit cache and RSB events at instruction and
   speculation boundaries. Predictor, translation, and buffer events are
   explicit abstract replay inputs; no native Unicorn monitor emits them yet.
3. Pure state models consume explicit events. This permits unit tests and
   native trace ingestion without Unicorn, and separates a transition model
   from a physical claim.
 4. `EvidenceCase` binds each silicon example to a local raw file hash, source
    path, CPU profile, class, expected observation, and verdict. Verification
    rejects missing or mismatched sources; it never turns a model match into
    an oracle admission.
5. An optional four-row TLB-AND timer wrapper preserves ordered rail latencies
   from the gate's readout. Ingestion checks its self-reported threshold and
   seed, then recomputes H/J histograms and AND counts before producing trace
   events. The trace hash is computed from the native bytes at ingestion;
   replay alone cannot verify that source. CPU and binary identity require
   separate provenance. These events are architectural observations; they do
   not expose page-walk or replacement transitions.

The `cycle` field in trace JSON is a monotonic logical-order tick. It is not
speculative depth, issue latency, or wall-clock CPU cycles. Cache line and
page sizes are serialized with each trace, and resident cache state at the
start of emulation is emitted before the first guest instruction.

## Acceptance gates

- All 13 classes are named; observed-only classes never report an emulated
  gate. Cache/RSB behavior remains covered by the original gate suite.
- Every modeled transition has a positive and a counterexample test. A
  transient rollback restores architectural state while preserving the
  modeled microarchitectural side effect.
- Exception AND/OR/NOT, RSB NAND, and representative UGIR silicon examples
  have explicit expected outcomes, including rejected and unmeasured rows.
- A replay with an unsupported event or malformed sequence fails closed.
  `verify-evidence` rejects wrong pinned source hashes and ambiguous source
  records; `ingest-tlb` computes a hash from its input. Replay alone does not
  reopen the original silicon source.
- Native tests run only on a compatible x86-64 Linux host; other hosts can
  verify stored raw evidence and run deterministic tests. Reports identify
  which mode ran and list skipped native checks.

The current evidence manifest intentionally maps cache and transient-window
roles to the same AMD exception-cache record. These are two roles of one
construction, not independent silicon runs. The TLB sham is a killed-window
control with different address geometry from the real case; reports retain
that distinction. Raw aggregate and histogram sources lack per-attempt order.
The new ordered TLB capture protocol retains that order when its optional
wrapper can run, but requires an A/A check against the uninstrumented gate.

## Deferred research questions

BTB aliasing, TLB replacement/page-walk behavior, MDP training, and substrate
interference require CPU-specific calibration. The initial abstract models
should generate falsifiable trace predictions; silicon comparisons decide
whether each transition rule can be promoted to a calibrated profile.
