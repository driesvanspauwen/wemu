"""Import pinned AMD Zen 3 one-shot BTB-AND readouts as observations.

The CSV contains ordered architectural cache readouts and PMU counters. It
does not expose BTB targets, a reusable predictor register, or the calibration
threshold needed to derive hit flags independently from recorded cycles.
"""

import csv
from dataclasses import dataclass
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import re
from typing import Dict, List, Optional

from ugir_evidence import _wilson_lower
from ugir_trace import Replay, Trace


_CSV_FIELDS = (
    "round", "a", "b", "expected", "real_signal_cycles", "real_signal_hit",
    "decoded", "correct", "sham_signal_cycles", "sham_signal_hit",
    "committed_equal", "indirect_misses", "branch_misses", "retired_branches",
    "sham_indirect_misses", "sham_branch_misses", "sham_retired_branches")
_BOOLEAN_FIELDS = frozenset(("a", "b", "expected", "real_signal_hit",
                             "decoded", "correct", "sham_signal_hit",
                             "committed_equal"))
_MAX_CSV_BYTES = 16 * 1024 * 1024
_MAX_METADATA_BYTES = 1024 * 1024
_UINT64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class BTBCapture:
    trace: Trace
    native_rows: Dict[str, List[int]]
    min_row_wilson_lower_95: float
    feasible_threshold_interval: List[Optional[int]]


def _read_limited(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError(f"oversized BTB source: {path.name}")
    return data


def _check_pin(data: bytes, expected: str, label: str) -> str:
    if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError(f"invalid {label} SHA-256 pin")
    actual = sha256(data).hexdigest()
    if actual != expected:
        raise ValueError(f"{label} SHA-256 differs from pin")
    return actual


def _object(data: bytes, label: str) -> dict:
    try:
        def reject_constant(value):
            raise ValueError(f"nonfinite {label} JSON value: {value}")

        def reject_duplicate_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate {label} JSON key: {key}")
                result[key] = value
            return result

        value = json.loads(data.decode("utf-8"), parse_constant=reject_constant,
                           object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _unique_run(document: dict, run_id: str, label: str) -> dict:
    runs = document.get("runs")
    if not isinstance(runs, list):
        raise ValueError(f"{label} has no run list")
    matches = [run for run in runs if isinstance(run, dict) and run.get("id") == run_id]
    if len(matches) != 1:
        raise ValueError(f"{label} must identify exactly one selected run")
    return matches[0]


def _reported_count(value, expected: int) -> bool:
    return type(value) is int and value == expected


def _reported_bound(value, expected: float) -> bool:
    return (type(value) in (int, float) and 0 <= value <= 1 and
            abs(value - expected) <= 1e-12)


def _integer(value: str, label: str) -> int:
    if not re.fullmatch(r"[0-9]+", value or ""):
        raise ValueError(f"invalid BTB {label}")
    parsed = int(value)
    if parsed > _UINT64_MAX:
        raise ValueError(f"BTB {label} exceeds native uint64 range")
    return parsed


def _shuffle_round(state: int):
    """Mirror the pinned gate_cli.c SplitMix64/Fisher-Yates row scheduler."""
    rows = [(0, 0), (0, 1), (1, 0), (1, 1)]
    for size in (4, 3, 2):
        state = (state + 0x9E3779B97F4A7C15) & _UINT64_MAX
        value = state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & _UINT64_MAX
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & _UINT64_MAX
        value ^= value >> 31
        index = value % size
        rows[size - 1], rows[index] = rows[index], rows[size - 1]
    return state, rows


def load_btb_run(bundle: Path, run_id: str, *,
                 expected_manifest_sha256: str,
                 expected_report_sha256: str) -> BTBCapture:
    """Check one Rigger source bundle against independent caller-held pins."""
    bundle = Path(bundle)
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", run_id):
        raise ValueError("invalid BTB run id")
    manifest_data = _read_limited(bundle / "manifest.json", _MAX_METADATA_BYTES)
    report_data = _read_limited(bundle / "report.json", _MAX_METADATA_BYTES)
    manifest_hash = _check_pin(manifest_data, expected_manifest_sha256, "manifest")
    report_hash = _check_pin(report_data, expected_report_sha256, "report")
    manifest, report = _object(manifest_data, "manifest"), _object(report_data, "report")
    if report.get("manifest_sha256") != manifest_hash or (
            report.get("binary_sha256") != manifest.get("binary_sha256")) or (
            report.get("source_commit") != manifest.get("source_commit")) or (
            report.get("oracle_admitted") is not False):
        raise ValueError("BTB report provenance or admission status differs")
    if (not isinstance(manifest.get("cpu"), str) or
            type(manifest.get("logical_cpu")) is not int or
            manifest["logical_cpu"] < 0 or
            not isinstance(manifest.get("source_commit"), str) or
            type(manifest.get("binary_sha256")) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", manifest["binary_sha256"])):
        raise ValueError("BTB manifest machine or binary metadata is invalid")
    source_run = _unique_run(manifest, run_id, "manifest")
    report_run = _unique_run(report, run_id, "report")
    if (type(source_run.get("seed")) is not int or
            not 0 <= source_run["seed"] <= _UINT64_MAX or
            source_run.get("split") not in ("held", "calibration")):
        raise ValueError("BTB run seed or split is invalid")
    name = source_run.get("path")
    if (type(name) is not str or not name.endswith(".csv") or
            Path(name).name != name or "\\" in name or name.startswith(".")):
        raise ValueError("BTB source must be a bundle-local CSV filename")
    if (report_run.get("source_path") != name or
            report_run.get("seed") != source_run.get("seed") or
            report_run.get("split") != source_run.get("split")):
        raise ValueError("BTB run identity differs between manifest and report")
    csv_path = bundle / name
    if csv_path.is_symlink():
        raise ValueError("BTB source symlinks are unsupported")
    csv_data = _read_limited(csv_path, _MAX_CSV_BYTES)
    source_hash = _check_pin(csv_data, source_run.get("sha256"), "BTB CSV")
    if report_run.get("source_sha256") != source_hash:
        raise ValueError("BTB report source SHA-256 differs")
    try:
        reader = csv.DictReader(StringIO(csv_data.decode("utf-8")), strict=True)
        if reader.fieldnames != list(_CSV_FIELDS):
            raise ValueError("unsupported BTB CSV schema")
        raw_rows = list(reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ValueError("invalid BTB CSV") from exc
    if not raw_rows or len(raw_rows) > 40000 or len(raw_rows) % 4:
        raise ValueError("BTB CSV has invalid trial count")

    counts = {bits: {"trials": 0, "correct": 0, "signal_hits": 0,
                     "sham_hits": 0, "committed_mismatches": 0}
              for bits in ("00", "01", "10", "11")}
    seen = set()
    shuffle_state = source_run["seed"]
    expected_order = []
    trace = Trace(metadata={
        "source_kind": "amd_zen3_btb_one_shot_and_csv_v1",
        "source_sha256": source_hash,
        "manifest_sha256": manifest_hash,
        "report_sha256": report_hash,
        "run_id": run_id,
        "seed": source_run.get("seed"),
        "split": source_run.get("split"),
        "cpu_claimed_by_manifest": manifest.get("cpu"),
        "logical_cpu_claimed_by_manifest": manifest.get("logical_cpu"),
        "binary_sha256_claimed_by_manifest": manifest.get("binary_sha256"),
        "source_commit_claimed_by_manifest": manifest.get("source_commit"),
        "calibration_threshold": "not_recorded",
        "oracle_admitted": False,
        "native_observation_only": True,
    })
    for sequence, raw in enumerate(raw_rows):
        if None in raw or any(value is None for value in raw.values()):
            raise ValueError("BTB CSV row width differs from schema")
        row = {key: _integer(raw[key], key) for key in _CSV_FIELDS}
        if any(row[key] not in (0, 1) for key in _BOOLEAN_FIELDS):
            raise ValueError("BTB bit field is not binary")
        if row["round"] != sequence // 4:
            raise ValueError("BTB rounds are not contiguous four-row groups")
        if sequence % 4 == 0:
            shuffle_state, expected_order = _shuffle_round(shuffle_state)
        if (row["a"], row["b"]) != expected_order[sequence % 4]:
            raise ValueError("BTB row order differs from seeded shuffle")
        identity = (row["round"], row["a"], row["b"])
        if identity in seen:
            raise ValueError("duplicate BTB attempt within round")
        seen.add(identity)
        expected = row["a"] & row["b"]
        if (row["expected"] != expected or
                row["real_signal_hit"] != row["decoded"] or
                row["correct"] != int(row["decoded"] == expected)):
            raise ValueError("BTB recorded truth, hit, or correctness differs")
        bits = f'{row["a"]}{row["b"]}'
        subtotal = counts[bits]
        subtotal["trials"] += 1
        subtotal["correct"] += row["correct"]
        subtotal["signal_hits"] += row["real_signal_hit"]
        subtotal["sham_hits"] += row["sham_signal_hit"]
        subtotal["committed_mismatches"] += 1 - row["committed_equal"]
        trace.add("readout", sequence, "architectural", details={
            "substrate": "branch_predictor", "scheme": "amd_btb_one_shot_and",
            **row})
    if len(seen) != len(raw_rows) or any(
            counts[bits]["trials"] != len(raw_rows) // 4 for bits in counts):
        raise ValueError("BTB truth rows are incomplete")
    reported_rows = report_run.get("rows")
    if not isinstance(reported_rows, list) or len(reported_rows) != 4:
        raise ValueError("BTB report has incomplete rows")
    if any(not isinstance(item, dict) or
           type(item.get("bits")) is not str or
           item["bits"] not in counts for item in reported_rows):
        raise ValueError("BTB report truth-row identity is invalid")
    report_by_bits = {item["bits"]: item for item in reported_rows}
    if set(report_by_bits) != set(counts):
        raise ValueError("BTB report truth rows differ")
    for bits, subtotal in counts.items():
        reported = report_by_bits[bits]
        if any(not _reported_count(reported.get(key), value)
               for key, value in subtotal.items()):
            raise ValueError("BTB report row counts differ from CSV")
        lower = _wilson_lower(subtotal["correct"], subtotal["trials"])
        if ("wilson_lower_95" in reported and
                not _reported_bound(reported["wilson_lower_95"], lower)):
            raise ValueError("BTB report Wilson bound differs from CSV")
    minimum = min(_wilson_lower(value["correct"], value["trials"])
                  for value in counts.values())
    if ("worst_row_wilson_lower_95" in report_run and
            not _reported_bound(report_run["worst_row_wilson_lower_95"], minimum)):
        raise ValueError("BTB report worst-row bound differs from CSV")
    controls_pass = all(value["sham_hits"] == 0 and
                        value["committed_mismatches"] == 0
                        for value in counts.values())
    if ("preliminary_count_controls_pass" in report_run and
            report_run["preliminary_count_controls_pass"] is not controls_pass):
        raise ValueError("BTB report control verdict differs from CSV")
    replayed = Replay().run(trace)  # Verify readouts and run-level separation.
    return BTBCapture(trace,
                      {bits: [value["trials"], value["correct"]]
                       for bits, value in counts.items()}, minimum,
                      replayed.btb_feasible_threshold_interval)
