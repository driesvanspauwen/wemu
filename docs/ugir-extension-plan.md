# UGIR extension implementation plan

**Goal:** Add a traceable, falsifiable substrate extension to WeMu without
confusing model output with native oracle admission.

**Spec:** [ugir-extension-design.md](ugir-extension-design.md).

## Task 1 — Freeze the baseline

- Record upstream commit, dependency versions, host, and the result of the
  existing `gitm`, `flexo`, and assembly gate suites. Count failures in output;
  `unit_tests.py` can exit zero after a per-gate error.
- Preserve existing exception/RSB semantics and known SHA/AES failures.

## Task 2 — Versioned trace and capability registry

- Add pure-Python types for `MicroEvent`, `Trace`, `Capability`, and 13 UGIR
  substrate classes. Include per-mechanism status and rationale.
- Test complete taxonomy, invalid kinds/sequence/cycles, round-trip JSON,
  and fail-closed handling for unsupported compute requests.
- Add a CLI that prints capabilities and validates/replays a trace.

## Task 3 — Execution hooks and state replay

- Instrument instruction, read, write, flush, RSB, speculation, pending-load,
  and rollback points in `src/emulator.py`; keep tracing optional.
- Add deterministic models for branch-target state, page-translation state,
  and load/store dependence state. Mark these `abstract` until silicon fidelity
  tests support a narrower calibrated profile.
- Test transitions and transient rollback invariants separately; then run
  gate-level integration tests against GITM and Flexo binaries.

## Task 4 — Silicon evidence contract

- Add an evidence manifest with one admitted or rejected representative per
  demonstrated compute class, including CPU, raw source, SHA-256, and expected
  observation. Never copy a verdict from an ignored local file without a hash.
- Add a verifier that rejects missing/hash-mismatched evidence and reports
  functional, mechanism, and native reliability results in separate fields.
- Run it over local UGIR records; persist only checked, portable minimal
  fixtures if permitted by their provenance and size.

## Task 5 — Independent verification

- Ask verifier agents to challenge taxonomy completeness, paper fidelity,
  trace/state invariants, and silicon evidence binding after implementation.
- Run unit, integration, and source-gate suites; report exact pass/fail/skip
  counts and host limitations. Fix findings and rerun affected gates.

## Checkpoint: trace and evidence foundation

- Tasks 2–5 are implemented for the stated abstract and cache scope. The
  extension suite has 64 passing tests; existing GITM and Flexo suites produced
  28 and 66 pass lines with no failure lines. The assembly suite needs `nasm`,
  which was unavailable on the macOS host.
- Fresh AMD native cache-AND runs and their negative controls are preserved in
  [the validation report](ugir-amd-live-validation-2026-10-09.md). They test
  source and silicon evidence handling, not WeMu prediction accuracy.
- Verifier agents challenged the replay and evidence invariants. Their
  actionable findings were reproduced as failing tests and fixed. The report
  records provenance limits for the older non-Git AMD source.
- Ordered TLB readout ingestion is implemented and tested against an independent
  native stub. A live Raptor Lake A/A comparison could not start because
  `/dev/tlb_device` is absent; see
  [the capture report](ugir-rpl-tlb-capture-2026-10-09.md). No TLB fidelity or
  oracle claim follows from the stub test.
- The pinned AMD Zen 3 one-shot BTB bundle imports 4,000 ordered readouts per
  seed. Four archived runs recount against their SHA-linked manifest and report;
  see [the BTB readout report](ugir-amd-btb-readout-validation-2026-10-09.md).
  This is preliminary source evidence with no recorded threshold, not a
  reusable BTB register or WeMu-to-silicon fidelity result.

## Next acceptance gates for full UGIR compute coverage

1. Define per-gate native event taps that preserve attempt order, including
   predictor updates/predictions, translation outcomes, and store-dependence
   decisions. Aggregate JSON and latency histograms cannot reconstruct these
   sequences. Keep source CPU, process, seed, and code-layout identity.
2. For each demonstrated compute class, implement a CPU-scoped instruction
   backend or a calibrated transition profile. Feed native traces into the
   versioned event schema, then compare held-out gate outputs and intermediate
   observations against WeMu replay. Promote `abstract` to gate emulation only
   when the same profile passes the held-out matrix and negative controls.
3. Use controlled interventions to distinguish competing hidden-state models:
   vary one training address, page mapping, or store/load alias at a time;
   require the predicted change in both readout and event history. Retain
   failed interventions as counterexamples rather than retuning them away.
4. Run the resulting matrix on supported AMD and Raptor Lake CPUs with CPU
   locks and versioned raw artifacts. Broadwell live runs remain deferred while
   its other experiments are active. Require an independent verifier pass on
   every capability promotion.
