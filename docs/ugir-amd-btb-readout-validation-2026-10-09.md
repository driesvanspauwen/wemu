# AMD Zen 3 BTB one-shot readout import, 2026-10-09 UTC

## Source and protocol

The source bundle is `rigger/data/amd_btb_readmit/`. Its pinned manifest
claims the restored UGIR Zen 3 BTB one-shot AND C/assembly harness at commit
`2d91d0a4a32bf51f7d2b9457fb096234358dd83b`; that harness is recoverable
from UGIR Git history and is absent from its current checkout. The importer
checks manifest/report agreement on the commit but cannot prove which source
built the native binary. The manifest identifies an
AMD Ryzen 7 5700X, logical CPU 1, four fresh processes, 1,000 trials per
truth row, and seeds 101, 9001, 9002, and 9003. Seed 101 was calibration;
the other three were held out. This checkpoint imported archived records;
it did not start a new native experiment.

The built-in WeMu pin fixes manifest SHA-256
`604e1464d4e363b138e8777dbff102028466ac198379717df5fb6e81ac6e1af1`
and report SHA-256
`1570fbf48c32d722d8bdb265a6a5debecc08829a1c99675888695a91fcfef118`.
The importer verifies each selected CSV against both records, requires each
round's row order to match the source's seeded shuffle, recomputes AND truth,
correctness and real/sham counts, and checks reported Wilson bounds. It also
requires the stored hit and miss cycle labels to admit at least one common
threshold. Trace events preserve raw cycles, stored hit flags, PMU counts,
and attempt order. Replay rechecks the truth/status relationships and the
threshold-separation invariant.

## Recount

| Run | Row 00 | Row 01 | Row 10 | Row 11 | Worst Wilson lower 95% | Feasible integer threshold | Sham hits |
|---|---:|---:|---:|---:|---:|---:|---:|
| Calibration 101 | 1000/1000 | 1000/1000 | 994/1000 | 999/1000 | 0.986972 | 102–305 | 0 |
| Held 9001 | 1000/1000 | 1000/1000 | 1000/1000 | 998/1000 | 0.992737 | 102–305 | 0 |
| Held 9002 | 1000/1000 | 1000/1000 | 997/1000 | 997/1000 | 0.991217 | 136–305 | 0 |
| Held 9003 | 1000/1000 | 1000/1000 | 995/1000 | 995/1000 | 0.988349 | 102–305 | 0 |

The four imports yielded 16,000 replayable observations and zero committed
mismatches. Portable tests reject changed source bytes, inconsistent report
counts/commit, duplicate or wrongly shuffled attempts, impossible hit/miss
cycle labels, and tampered replay truth fields.

## Interpretation

These are **preliminary one-shot C-harness results, not current UGIR oracle
admission**. The CSV omits the per-process calibration threshold; WeMu can
check that some threshold separates stored hit/miss labels and infer the
corresponding integer interval, but cannot verify the exact chosen value. The
manifest self-attests CPU and binary identity;
the pinned hashes bind archived files, not the live binary or machine
independently. The records lack current per-trial architectural, mechanism,
and retirement/window evidence. They do not establish persistent BTB storage,
hidden predictor transitions, or agreement between WeMu's abstract BTB model
and silicon.
