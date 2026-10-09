# AMD cache-AND live validation, 2026-10-09 UTC

This is a bounded native UGIR comparison supporting the WeMu extension's
evidence workflow. It is not a WeMu-to-silicon fidelity result. No Broadwell
host was contacted or used.

## Execution

- Host: `resbears-MS-7C95`, Linux x86-64, AMD Ryzen 7 5700X. CPU 1 was
  reserved with `/tmp/ugir-cpu1.lock` and each measurement was pinned with
  `taskset -c 1`. The two source trees and build outputs were placed under
  separate `/tmp/wemu-*` directories. No global ASLR or PMU setting changed.
- Command per source and seed: `ugir-oracle measure --gate cache-and
  --variant-id V1 --out <file> --seed <505|606> --trials 1000`. Native runs
  used neither `--mock` nor synthetic weirdness flags.
- The legacy source was a preexisting, non-Git `~/ugir` copy on that host.
  Its host-observed gate source SHA-256 was
  `883b6e7bb2dc9fb3a2ec993b890fc065e57bc815e39d2f57f18a1a870045c282`;
  host-observed binary SHA-256 was
  `5233cd48b5f05251b37c464c681a83a70007829cb18545511925ea923694017b`.
- The current source was copied from a clean `tools/` tree at UGIR commit
  `9a2153a09025d91acba69bcaa062df0c1c50a454`. Its gate source SHA-256 was
  `ebbcd1428a440448463df9e521da07890eb6000b88e51176b061812268fa3c9f`;
  host-observed binary SHA-256 was
  `caaf08c6c8c85fb435462d7055519fc205971ad72f7552c74fc6e04566ce1e08`.
  It was built offline with `CLANG=/usr/bin/clang-17`.

## Raw outcomes

Each row lists successes out of 1,000 attempts in input order 00/01/10/11.
The sham had zero resident observations in all four rows for every run.
Each same-session positive control had 256 samples and a resident rate of
at least 255/256.

| Source | Seed | Successes | Minimum Wilson lower 95% | Admission | Raw SHA-256 |
| --- | ---: | --- | ---: | --- | --- |
| Legacy | 505 | 1000 / 1000 / 1000 / 894 | 0.873390 | rejected | `a3c3bc338d6188fb805d5fb555c794e11dda89c78da3ba11a046cea3d376446e` |
| Legacy | 606 | 1000 / 1000 / 1000 / 896 | 0.875540 | rejected | `baeb3cd22114cd885f9f22584d2247068fa13ef8e33bcf26fde42348a1c4568d` |
| Current | 505 | 1000 / 1000 / 1000 / 1000 | 0.996173 | admitted | `2074788ae5fd8fa4900a60d60e14c8d535961900ec2806091fbb602e244e90eb` |
| Current | 606 | 1000 / 1000 / 1000 / 1000 | 0.996173 | admitted | `def7efdbbfa3f26feff4ca935bba2c25415242edb4d9c4883833be0eb23b7958` |

Raw records: [legacy seed 505](../evidence/live/amd-legacy-cache-and-seed-505.json),
[legacy seed 606](../evidence/live/amd-legacy-cache-and-seed-606.json),
[current seed 505](../evidence/live/amd-current-cache-and-seed-505.json), and
[current seed 606](../evidence/live/amd-current-cache-and-seed-606.json).
The local copies match the SHA-256 values returned by the host.

The legacy records pass the legacy `ugir-reader` and schema. They carry a
historical admission floor of 0.90 and an incorrect `machine_id` value
`testbed-broadwell` despite the AMD model and the observed AMD host. The
current reader rejects these records specifically because its schema requires
the present 0.80 floor. Both current records pass the current UGIR reader and
schema. These are different source and admission protocols; this comparison
does not isolate which code change caused the row-11 difference.

The four raw records are archived here. The legacy non-Git source tree,
compiled binaries, build logs, and legacy reader/schema are not in this
bundle, so the source and binary hashes and legacy-reader pass are recorded
host observations rather than independently reproducible claims from these
files alone. The current source revision and its gate source hash can be
checked against the named UGIR commit. `source_verified` from WeMu's verifier
checks pinned bytes and selected fields; it does not run either UGIR reader.

## Scope

This run establishes that the current native cache-AND construction can be
admitted on this AMD host for two specified seeds under current UGIR policy.
It does not establish repeatability across days, other hosts, or all UGIR
substrates. The WeMu abstract BTB, TLB, and dependence models were not used to
predict these native attempts; their `model_fidelity` remains `not_assessed`.
