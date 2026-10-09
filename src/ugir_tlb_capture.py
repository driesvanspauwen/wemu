"""Convert ordered native TLB-AND rail timings into checked observations.

The capture records readout timings, not hidden TLB transitions. Its source
SHA identifies the bytes checked at ingestion; replay alone does not rehash
the native source.
"""

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Dict, List

from ugir_evidence import _AND, _H, _J, _histogram_bins, _wilson_lower
from ugir_trace import Trace


_TRIAL = re.compile(
    r"^UCAP v=1 seq=(\d+) row=([01],[01]) rail1=(\d+) rail0=(\d+)$")
_CONFIG = re.compile(
    r"^UCAP_CONFIG v=1 gate=AND rows=4 n=(\d+) threshold=(\d+) seed=(\d+)$")
_ROW_ORDER = ("0,0", "1,0", "0,1", "1,1")
MAX_CAPTURE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class TLBCapture:
    trace: Trace
    native_rows: Dict[str, List[int]]
    min_row_wilson_lower_95: float


def parse_tlb_capture(data: bytes, *, threshold: int, seed: int,
                      trials_per_row: int) -> TLBCapture:
    if type(threshold) is not int or not 0 < threshold <= 0x7FFFFFFFFFFFFFFF or (
            type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF) or (
            type(trials_per_row) is not int or not 0 < trials_per_row <= 10000):
        raise ValueError("invalid TLB capture threshold, seed, or trial count")
    if not isinstance(data, bytes) or len(data) > MAX_CAPTURE_BYTES:
        raise ValueError("TLB capture must be bounded bytes")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("TLB capture must be UTF-8") from exc

    hist, joint, reported = {}, {}, {}
    config = None
    trials = []
    for line in lines:
        if line.startswith("UCAP_CONFIG "):
            match = _CONFIG.fullmatch(line)
            if (match is None or config is not None or hist or joint or
                    reported or trials):
                raise ValueError("malformed, duplicate, or late TLB capture configuration")
            count, native_threshold, native_seed = (int(match[i]) for i in (1, 2, 3))
            if (count != trials_per_row or native_threshold != threshold or
                    native_seed != seed):
                raise ValueError("TLB capture configuration differs from requested run")
            config = {"gate": "AND", "rows": 4, "trials_per_row": count,
                      "threshold": native_threshold, "seed": native_seed}
        elif line.startswith("UCAP "):
            match = _TRIAL.fullmatch(line)
            if match is None:
                raise ValueError("malformed or unsupported ordered TLB trial")
            sequence = int(match[1])
            row = match[2]
            rail1, rail0 = int(match[3]), int(match[4])
            if rail1 > 0xFFFFFFFFFFFFFFFF or rail0 > 0xFFFFFFFFFFFFFFFF:
                raise ValueError("TLB rail latency exceeds native uint64 range")
            if sequence != len(trials) or row != _ROW_ORDER[sequence % 4]:
                raise ValueError("TLB trial sequence or row order differs from capture protocol")
            trials.append((row, rail1, rail0))
        elif line.startswith("H row="):
            match = _H.fullmatch(line)
            if match is None or (match[1], match[2]) in hist:
                raise ValueError("malformed or duplicate TLB rail histogram")
            hist[(match[1], match[2])] = _histogram_bins(match[3], joint=False)
        elif line.startswith("J row="):
            match = _J.fullmatch(line)
            if match is None or match[1] in joint:
                raise ValueError("malformed or duplicate TLB joint histogram")
            joint[match[1]] = _histogram_bins(match[2], joint=True)
        elif line.startswith("AND row="):
            match = _AND.fullmatch(line)
            if match is None or match[1] in reported:
                raise ValueError("malformed or duplicate TLB AND row")
            reported[match[1]] = tuple(int(match[i]) for i in range(2, 7))
        elif line.strip():
            raise ValueError("unknown line in ordered TLB capture")

    if config is None or len(trials) != 4 * trials_per_row or len(hist) != 8 or (
            len(joint) != 4 or set(reported) != set(_ROW_ORDER)):
        raise ValueError("ordered TLB capture is incomplete")

    derived_h = defaultdict(Counter)
    derived_j = defaultdict(Counter)
    derived_rows = {row: [0, 0, 0, 0, 0] for row in _ROW_ORDER}
    trace = Trace(metadata={"source_kind": "ugir_tlb_ordered_v1",
                            "source_sha256": sha256(data).hexdigest(),
                            "threshold": threshold,
                            "trials_per_row": trials_per_row,
                            "capture_config": config,
                            "native_observation_only": True})
    for sequence, (row, rail1, rail0) in enumerate(trials):
        raw1, hit0 = rail1 < threshold, rail0 < threshold
        detected = raw1 == hit0
        success = not detected and raw1 == (row == "1,1")
        counts = derived_rows[row]
        counts[0] += 1
        counts[1] += int(success)
        counts[2] += int(detected)
        counts[3] += int(not detected and not success)
        counts[4] += int(raw1)
        derived_h[(row, "1")][min(rail1, 399)] += 1
        derived_h[(row, "0")][min(rail0, 399)] += 1
        derived_j[row][(min(rail1, 199), min(rail0, 199))] += 1
        trace.add("readout", sequence, "architectural",
                  details={"substrate": "tlb_page_walk", "row": row,
                           "trial": sequence // 4, "rail1_latency": rail1,
                           "rail0_latency": rail0, "threshold": threshold,
                           "raw1": raw1, "detected": detected,
                           "success": success})

    for row in _ROW_ORDER:
        if tuple(derived_rows[row]) != reported[row] or (
                dict(derived_j[row]) != joint[row]):
            raise ValueError("ordered TLB trials disagree with reported AND or joint counts")
        for rail in ("0", "1"):
            if dict(derived_h[(row, rail)]) != hist[(row, rail)]:
                raise ValueError("ordered TLB trials disagree with rail histogram")

    native_rows = {row: values[:2] for row, values in derived_rows.items()}
    return TLBCapture(trace, native_rows,
                      min(_wilson_lower(values[1], values[0])
                          for values in derived_rows.values()))
