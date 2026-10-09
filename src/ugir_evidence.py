"""Verify pinned UGIR silicon examples without promoting them to WeMu claims."""

from hashlib import sha256
import json
import math
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping

from ugir_trace import class_catalog


class EvidenceError(ValueError):
    pass


def _strict_json(payload: Any) -> Any:
    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise EvidenceError("nonfinite evidence number")
        return result

    def reject_constant(value: str) -> None:
        raise EvidenceError(f"nonfinite evidence constant: {value}")

    return json.loads(payload, parse_float=finite_float,
                      parse_constant=reject_constant)


def load_manifest(path: Path) -> List[Dict[str, Any]]:
    try:
        document = _strict_json(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != 1 or not isinstance(document.get("cases"), list):
            raise EvidenceError("unsupported evidence manifest")
        cases = document["cases"]
        required = {"id", "substrate", "format", "path", "sha256", "expected"}
        if any(not isinstance(case, dict) or not required.issubset(case) or
               not isinstance(case["expected"], dict) for case in cases):
            raise EvidenceError("malformed evidence case")
        computed = {name for name, spec in class_catalog().items()
                    if spec.role == "computed"}
        positive = {case["substrate"] for case in cases
                    if case["format"] != "ugir_rejection"}
        if positive != computed:
            raise EvidenceError("manifest must have positive evidence for every compute class")
        if not any(case.get("format") == "ugir_rejection" for case in cases):
            raise EvidenceError("manifest must retain a rejected control")
        ids = [case["id"] for case in cases]
        if len(set(ids)) != len(ids):
            raise EvidenceError("duplicate evidence case id")
        return cases
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise EvidenceError("malformed evidence manifest") from exc


def _source_path(case: Mapping[str, Any], ugir_root: Path) -> Path:
    root = Path(ugir_root).resolve()
    path = case.get("path")
    if not isinstance(path, str) or not path:
        raise EvidenceError("evidence path must be a nonempty string")
    relative = Path(path)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise EvidenceError("evidence path must stay within UGIR root")
    source = (root / relative).resolve()
    if root not in source.parents:
        raise EvidenceError("evidence path escapes UGIR root")
    return source


def _wilson_lower(successes: int, trials: int) -> float:
    if not isinstance(successes, int) or not isinstance(trials, int) or (
            isinstance(successes, bool) or isinstance(trials, bool)
            or trials <= 0 or not 0 <= successes <= trials):
        raise EvidenceError("invalid native trial counts")
    z = 1.959963984540054
    p = successes / trials
    z2 = z * z
    center = p + z2 / (2 * trials)
    margin = z * (p * (1 - p) / trials + z2 / (4 * trials * trials)) ** 0.5
    return (center - margin) / (1 + z2 / trials)


def _probability(value: Any) -> bool:
    return type(value) in (int, float) and 0 <= value <= 1


def _verify_aggregate(case: Mapping[str, Any], data: bytes) -> Dict[str, Any]:
    try:
        record = _strict_json(data)
        if not isinstance(record, dict):
            raise EvidenceError("UGIR aggregate must be a JSON object")
        expected = case["expected"]
        if record.get("synthetic") is not False or record.get("record_state") != "measured":
            raise EvidenceError("source is not a measured native record")
        if record["W"]["transient"] is not expected["transient"]:
            raise EvidenceError("window transient status differs from manifest")
        status = record["admission"]["overall_status"]
        if status != expected["admission"]:
            raise EvidenceError("source admission status differs from manifest")
        variants = record["variants"]
        if len(variants) != 1:
            raise EvidenceError("expected one unambiguous variant")
        native = variants[0]["R_measured"]["native_readout"]
        variant = variants[0]
        if status == "admitted" and variant["status"] != "pass":
            raise EvidenceError("admitted source has nonpassing variant")
        if variant["model_name"] != case["source_model"] or (
                variant["machine_id"] != case["source_machine_id"]):
            raise EvidenceError("source CPU identity differs from manifest")
        sham = variant["controls"]["negative_sham"]
        positive = variant["controls"]["positive_control"]
        if sham["input_independent"] is not True or sham["failed_as_required"] is not True:
            raise EvidenceError("negative sham does not satisfy control")
        sham_rows = sham["sham_rows"]
        if len(sham_rows) != 4 or {row["bits"] for row in sham_rows} != set(expected["rows"]):
            raise EvidenceError("negative sham rows do not match gate rows")
        for row in sham_rows:
            if type(row["trials"]) is not int or row["trials"] <= 0 or (
                    row["resident_count"] != 0 or
                    not _probability(row["resident_rate"])) or (
                    row["resident_rate"] != row["resident_count"] / row["trials"]):
                raise EvidenceError("negative sham resident counts inconsistent")
        if positive["confirmed_same_session"] is not True or (
                type(positive["samples"]) is not int or positive["samples"] <= 0 or
                not _probability(positive["resident_rate"]) or
                positive["resident_rate"] < 0.99):
            raise EvidenceError("positive control is absent or weak")
        weirdness = variant["weirdness"]
        expected_c = "supported" if expected["transient"] else "not_applicable"
        if status == "admitted" and (weirdness["a"], weirdness["b"], weirdness["c"]) != (
                "supported", "supported", expected_c):
            raise EvidenceError("admitted source has inconsistent weirdness verdict")
        rows = native["rows"]
        outputs = record["truth_table"]["outputs"]
        if len(outputs) != 1:
            raise EvidenceError("expected one Boolean output")
        truth = {row["bits"]: row["expected"][outputs[0]]
                 for row in record["truth_table"]["rows"]}
        if len(truth) != 4 or set(truth) != set(expected["rows"]) or (
                any(type(value) is not bool for value in truth.values())):
            raise EvidenceError("invalid source truth table")
        observed = {row["bits"]: [row["trials"], row["successes"]] for row in rows}
        if len(observed) != len(rows) or observed != expected["rows"]:
            raise EvidenceError("native rows differ from manifest")
        lowers = []
        for row in rows:
            lower = _wilson_lower(row["successes"], row["trials"])
            residents = row["resident_count"]
            if type(residents) is not int or not 0 <= residents <= row["trials"]:
                raise EvidenceError("invalid native resident count")
            correct = residents if truth[row["bits"]] else row["trials"] - residents
            if correct != row["successes"] or (
                    not _probability(row["resident_rate"]) or
                    not _probability(row["success_rate"]) or
                    abs(row["resident_rate"] - residents / row["trials"]) > 1e-12 or
                    abs(row["success_rate"] - correct / row["trials"]) > 1e-12):
                raise EvidenceError("native residency and success counts disagree")
            if not _probability(row["wilson_lower_95"]) or (
                    abs(lower - row["wilson_lower_95"]) > 1e-12):
                raise EvidenceError("native row Wilson bound inconsistent with counts")
            lowers.append(lower)
        recorded_min = variants[0]["R_measured"]["min_row_wilson_lower_95"]
        if not _probability(recorded_min) or abs(min(lowers) - recorded_min) > 1e-12:
            raise EvidenceError("minimum Wilson bound inconsistent with rows")
        if status == "admitted":
            measured = variant["R_measured"]
            floor = record["R"]["admission_floor_phi"]
            if not _probability(floor) or floor == 0 or (
                    min(lowers) < floor or measured["meets_floor"] is not True or
                    measured["meets_reliability_floor"] is not True or
                    native["meets_reliability_floor"] is not True or
                    native["admitted"] is not True):
                raise EvidenceError("admitted source fails measured reliability floor")
        return {"source_oracle_status": status,
                "source_variant_status": variants[0]["status"],
                "transient": record["W"]["transient"],
                "cpu_model_from_source": variant["model_name"],
                "machine_id_from_source": variant["machine_id"],
                "controls_verified": True,
                "native_rows": observed,
                "min_row_wilson_lower_95": min(lowers),
                "weirdness": {key: weirdness[key]
                              for key in ("a", "b", "c")}}
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("malformed UGIR aggregate record") from exc


def _verify_rejection(case: Mapping[str, Any], data: bytes) -> Dict[str, Any]:
    try:
        record = _strict_json(data)
        if not isinstance(record, dict):
            raise EvidenceError("UGIR rejection must be a JSON object")
        expected = case["expected"]
        if record.get("synthetic") is not False or record.get("record_state") != "measured":
            raise EvidenceError("rejected control is not a measured record")
        if record["W"]["transient"] is not expected["transient"]:
            raise EvidenceError("rejected control window differs from manifest")
        if record["admission"]["overall_status"] != expected["admission"]:
            raise EvidenceError("rejected control admission differs from manifest")
        variants = record["variants"]
        if len(variants) != 1:
            raise EvidenceError("rejected control must have one variant")
        variant = variants[0]
        if variant["model_name"] != case["source_model"] or (
                variant["machine_id"] != case["source_machine_id"]):
            raise EvidenceError("rejected control CPU identity differs from manifest")
        if variant["status"] != expected["variant_status"] or (
                variant["weirdness"]["c"] != expected["weirdness_c"] or
                expected["reason"] not in variant["reasons"]):
            raise EvidenceError("rejected control reason differs from manifest")
        return {"source_oracle_status": record["admission"]["overall_status"],
                "source_variant_status": variant["status"],
                "transient": record["W"]["transient"],
                "cpu_model_from_source": variant["model_name"],
                "machine_id_from_source": variant["machine_id"],
                "native_rows": None,
                "weirdness": {key: variant["weirdness"][key]
                              for key in ("a", "b", "c")},
                "rejection_reason": expected["reason"]}
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("malformed UGIR rejected control") from exc


_H = re.compile(r"^H row=([01],[01]) rail=([01]) (.+)$")
_J = re.compile(r"^J row=([01],[01]) (.+)$")
_AND = re.compile(
    r"^AND row=([01],[01]) n=(\d+) ok=(\d+) detected=(\d+) "
    r"undetected=(\d+) raw1=(\d+)$")


def _histogram_bins(payload: str, joint: bool) -> Dict[Any, int]:
    bins = {}
    for token in payload.split():
        key, sep, count = token.rpartition(":")
        if not sep or not count.isdigit() or (
                not re.fullmatch(r"\d+,\d+" if joint else r"\d+", key)):
            raise EvidenceError("malformed TLB histogram bin")
        index = tuple(map(int, key.split(","))) if joint else int(key)
        if index in bins:
            raise EvidenceError("duplicate TLB histogram bin")
        bins[index] = int(count)
    return bins


def _verify_tlb_histogram(case: Mapping[str, Any], data: bytes,
                          expected_key: str = "rows") -> Dict[str, Any]:
    hist = {}
    joint = {}
    rows = {}
    try:
        for line in data.decode("utf-8").splitlines():
            if match := _H.fullmatch(line):
                key = (match[1], match[2])
                if key in hist:
                    raise EvidenceError("duplicate TLB rail histogram")
                hist[key] = _histogram_bins(match[3], joint=False)
            elif match := _J.fullmatch(line):
                if match[1] in joint:
                    raise EvidenceError("duplicate TLB joint histogram")
                joint[match[1]] = _histogram_bins(match[2], joint=True)
            elif match := _AND.fullmatch(line):
                if match[1] in rows:
                    raise EvidenceError("duplicate TLB AND row")
                rows[match[1]] = [int(match[2]), int(match[3]), int(match[4]),
                                  int(match[5]), int(match[6])]
            elif line.strip():
                raise EvidenceError("unknown TLB histogram line")
        expected = case["expected"][expected_key]
        if {row: values[:2] for row, values in rows.items()} != expected or (
                len(hist) != 8 or len(joint) != 4):
            raise EvidenceError("TLB histogram rows differ from manifest")
        threshold = case["expected"]["threshold"]
        if not isinstance(threshold, int) or threshold <= 0:
            raise EvidenceError("invalid TLB threshold")
        for row, (trials, successes, detected, undetected, raw1) in rows.items():
            if successes + detected + undetected != trials or raw1 > trials:
                raise EvidenceError("TLB AND row counts inconsistent")
            if sum(hist[(row, "0")].values()) != trials or (
                    sum(hist[(row, "1")].values()) != trials):
                raise EvidenceError("TLB rail histogram count mismatch")
            if sum(joint[row].values()) != trials:
                raise EvidenceError("TLB joint histogram count mismatch")
            for rail in (0, 1):
                marginal = {}
                for latency_pair, count in joint[row].items():
                    latency = latency_pair[0] if rail == 1 else latency_pair[1]
                    marginal[latency] = marginal.get(latency, 0) + count
                if marginal != hist[(row, str(rail))]:
                    raise EvidenceError("TLB joint and rail marginals disagree")
            decoded_raw1 = sum(count for (rail1, _), count in joint[row].items()
                                if rail1 < threshold)
            if decoded_raw1 != raw1:
                raise EvidenceError("TLB raw1 disagrees with joint histogram")
            truth = row == "1,1"
            decoded_detected = sum(count for (rail1, rail0), count in joint[row].items()
                                   if (rail1 < threshold) == (rail0 < threshold))
            decoded_successes = sum(count for (rail1, rail0), count in joint[row].items()
                                    if (rail1 < threshold) != (rail0 < threshold)
                                    and (rail1 < threshold) == truth)
            if decoded_detected != detected or decoded_successes != successes or (
                    trials - decoded_detected - decoded_successes != undetected):
                raise EvidenceError("TLB decoded joint outcomes disagree with AND row")
            _wilson_lower(successes, trials)
        return {"source_oracle_status": "not_present",
                "native_rows": {row: values[:2] for row, values in rows.items()},
                "raw1_by_row": {row: values[4] for row, values in rows.items()},
                "min_row_wilson_lower_95": min(
                    _wilson_lower(values[1], values[0]) for values in rows.values())}
    except (UnicodeDecodeError, KeyError, TypeError) as exc:
        raise EvidenceError("malformed TLB histogram") from exc


def _read_pinned(case: Mapping[str, Any], ugir_root: Path,
                 path_key: str, hash_key: str) -> bytes:
    source = _source_path({"path": case.get(path_key)}, ugir_root)
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"missing evidence source: {case.get(path_key)}") from exc
    expected_hash = case.get(hash_key)
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise EvidenceError("invalid evidence SHA-256")
    if sha256(data).hexdigest() != expected_hash:
        raise EvidenceError(f"evidence SHA-256 mismatch: {case.get('id')}")
    return data


def _verify_tlb_batch(case: Mapping[str, Any], data: bytes) -> Dict[str, Any]:
    expected = case["expected"]
    lines = data.decode("utf-8").splitlines()
    for path_key, elf_key in (("path", "real_elf"), ("sham_path", "sham_elf")):
        stem = Path(case[path_key]).stem
        matching = [line for line in lines if line.startswith(stem + " ")]
        if len(matching) != 1:
            raise EvidenceError("TLB batch log lacks unique case line")
        match = re.fullmatch(
            re.escape(stem) + r" elf=(\S+) cpu=(\d+) n=(\d+) thr=(\d+) "
            r"seed=(\d+) freq=\S+", matching[0])
        if match is None or match[1] != expected[elf_key] or (
                int(match[2]) != expected["native_cpu_index"] or
                int(match[3]) != 2000 or int(match[4]) != expected["threshold"] or
                int(match[5]) != expected["seed"]):
            raise EvidenceError("TLB batch configuration differs from manifest")
    return {"native_cpu_index": expected["native_cpu_index"],
            "threshold": expected["threshold"], "seed": expected["seed"],
            "sham_geometry_matched": expected["sham_geometry_matched"]}


def verify_case(case: Mapping[str, Any], ugir_root: Path) -> Dict[str, Any]:
    data = _read_pinned(case, ugir_root, "path", "sha256")
    expected_hash = case["sha256"]
    if case.get("format") == "ugir_aggregate":
        result = _verify_aggregate(case, data)
    elif case.get("format") == "ugir_rejection":
        result = _verify_rejection(case, data)
    elif case.get("format") == "tlb_histogram":
        result = _verify_tlb_histogram(case, data)
        sham = _read_pinned(case, ugir_root, "sham_path", "sham_sha256")
        sham_result = _verify_tlb_histogram(case, sham, "sham_rows")
        batch = _read_pinned(case, ugir_root, "batch_path", "batch_sha256")
        result.update(_verify_tlb_batch(case, batch))
        result["sham_native_rows"] = sham_result["native_rows"]
        result["sham_source_recount_verified"] = True
        result["controls_verified"] = result["sham_geometry_matched"]
    else:
        raise EvidenceError("unsupported evidence format")
    return {"id": case["id"], "substrate": case["substrate"],
            "cpu_annotation": case["cpu"], "source_sha256": expected_hash,
            "source_verified": True, "schema_validation": "not_assessed",
            "model_fidelity": "not_assessed",
            **result}


def verify_manifest(manifest: Path, ugir_root: Path) -> List[Dict[str, Any]]:
    return [verify_case(case, ugir_root) for case in load_manifest(manifest)]
