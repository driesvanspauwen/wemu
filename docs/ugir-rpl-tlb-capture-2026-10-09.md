# Raptor Lake TLB ordered capture attempt, 2026-10-09 UTC

## Protocol

The optional `native/ugir_tlb_ordered_capture.c` wrapper links with UGIR's
four-row Flexo-TLB AND gate object in place of its histogram-only `rpl_instr.c`.
It records the two `timer_raw()` returns for each trial, then emits a
configuration header, the original H/J histograms, and ordered `UCAP v=1` lines.
`ingest-tlb` checks the reported threshold, seed, count, and gate label, then
requires a contiguous sequence, four-row round-robin order, exact H/J
reconstruction, and equality with the reported AND counts before writing a
trace. The header is emitted by the wrapper; CPU and linked binary identity
remain separate provenance fields.

The source basis was the local UGIR checkout at
`9a2153a09025d91acba69bcaa062df0c1c50a454`, under
`reproductions/ctrl-alt-tlb/rpl_audit_20261007/`. The intended native case
was `P_AND_m17_o64k_s5001` on an Intel Core i7-14700 host, logical CPU 4,
seed 5001, threshold 39. The preexisting gate object SHA-256 was
`f550d088ae35bfee6b3f38c4412445144084021fe167e824e22834cab45a0ec0`.
The current wrapper source SHA-256 was
`d4ca18e879082dd61299e770e63baa7622084698d98c41a0c772ddb8fe9ef4cf`.
It linked successfully against that existing gate object on the host; the
resulting ELF SHA-256 was
`c48aca8bd155f04db154026e36d171e1039ca2ee3d631ba52414a0af3234b205`.

## Native result

The uninstrumented baseline was attempted first under the host's CPU 4 and
Raptor Lake locks, with `UGIR_THR=39`, `UGIR_SEED=5001`, `UGIR_ROWS=4`, and
`UGIR_N=200`. It exited 1 with zero stdout and stderr bytes. A bounded
one-trial syscall diagnostic under the same locks showed:

```text
open("/dev/tlb_device", O_RDWR) = -1 ENOENT
exit(1)
```

The device was absent and no TLB module was loaded. The instrumented gate was
therefore **not run**. No live ordered TLB trace, A/A timing comparison,
model-fidelity score, or new TLB admission result was obtained. The host's
kernel configuration was not changed.

## What passed locally

A separate C stub supplies deterministic `timer_raw()` values to the wrapper.
The emitted H/J and UCAP rows pass ingestion and preserve the four expected
AND readouts. Parser tests reject changed threshold, missing or reordered
trials, histogram and count mismatch, duplicate rows, malformed protocol
version, unknown lines, oversized input, and tampered replay flags. This
verifies the capture format and
parser contract, not the Flexo-TLB experiment on silicon.

Before using a native trace as evidence, restore the UGIR-supported device
and runner environment, then compare the original and instrumented gate under
the same seed, CPU isolation, threshold, and trial count. Retain both raw
outputs and the device/runner provenance. Neither a histogram alone nor this
stub can reconstruct or verify hidden page-walk state.
