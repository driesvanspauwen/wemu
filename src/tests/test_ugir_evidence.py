from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ugir_evidence import (EvidenceError, _verify_tlb_histogram, _wilson_lower,
                           load_manifest, verify_case, verify_manifest)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "evidence" / "ugir-silicon-v1.json"
UGIR_ROOT = Path(os.environ.get("UGIR_ROOT", ROOT.parent / "ugir"))


class EvidenceTests(unittest.TestCase):
    def test_manifest_covers_each_computed_class_and_a_negative_control(self):
        cases = load_manifest(MANIFEST)
        self.assertEqual({case["substrate"] for case in cases}, {
            "cache", "transient_ooo_window", "branch_predictor",
            "tlb_page_walk", "load_store_fill_dependence_buffers"})
        self.assertEqual(len(cases), 6)
        self.assertEqual(sum(case["format"] == "ugir_rejection" for case in cases), 1)

    def test_rejected_control_cannot_be_only_case_for_class(self):
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        document["cases"] = [case for case in document["cases"]
                             if case["id"] != "broadwell-cwt-and"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                load_manifest(path)

    def test_boolean_manifest_version_is_rejected(self):
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        document["version"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(EvidenceError):
                load_manifest(path)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_real_local_silicon_records_match_pinned_hashes_and_counts(self):
        report = verify_manifest(MANIFEST, UGIR_ROOT)
        self.assertEqual(len(report), 6)
        self.assertTrue(all(item["source_verified"] for item in report))
        self.assertTrue(all(item["model_fidelity"] == "not_assessed" for item in report))
        control = next(item for item in report if item["id"].endswith("unresolved-control"))
        self.assertEqual(control["source_oracle_status"], "rejected")
        self.assertEqual(control["weirdness"]["c"], "unresolved")
        tlb = next(item for item in report if item["substrate"] == "tlb_page_walk")
        self.assertTrue(tlb["sham_source_recount_verified"])
        self.assertFalse(tlb["sham_geometry_matched"])
        self.assertFalse(tlb["controls_verified"])

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_hash_mismatch_fails_before_parsing(self):
        case = dict(load_manifest(MANIFEST)[0])
        case["sha256"] = "0" * 64
        with self.assertRaises(EvidenceError):
            verify_case(case, UGIR_ROOT)

    def test_absolute_or_parent_path_is_rejected(self):
        case = dict(load_manifest(MANIFEST)[0])
        for path in ("/tmp/input.json", "../other/input.json"):
            case["path"] = path
            with self.subTest(path=path), self.assertRaises(EvidenceError):
                verify_case(case, UGIR_ROOT)

    def test_null_path_and_list_manifest_fail_as_evidence_errors(self):
        case = dict(load_manifest(MANIFEST)[0])
        case["path"] = None
        with self.assertRaises(EvidenceError):
            verify_case(case, UGIR_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "manifest.json"
            invalid.write_text("[]", encoding="utf-8")
            with self.assertRaises(EvidenceError):
                load_manifest(invalid)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_rehashed_but_invalid_sham_cannot_be_verified(self):
        original = dict(load_manifest(MANIFEST)[0])
        source = UGIR_ROOT / original["path"]
        record = json.loads(source.read_text(encoding="utf-8"))
        record["variants"][0]["controls"]["negative_sham"]["input_independent"] = False
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = json.dumps(record).encode("utf-8")
            (root / "record.json").write_bytes(payload)
            original["path"] = "record.json"
            original["sha256"] = sha256(payload).hexdigest()
            with self.assertRaises(EvidenceError):
                verify_case(original, root)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_admitted_aggregate_requires_passing_variant(self):
        case = dict(load_manifest(MANIFEST)[0])
        record = json.loads((UGIR_ROOT / case["path"]).read_text(encoding="utf-8"))
        record["variants"][0]["status"] = "invalid"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = json.dumps(record).encode("utf-8")
            (root / "record.json").write_bytes(payload)
            case["path"] = "record.json"
            case["sha256"] = sha256(payload).hexdigest()
            with self.assertRaises(EvidenceError):
                verify_case(case, root)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_invalid_aggregate_measurements_are_rejected(self):
        original = dict(load_manifest(MANIFEST)[0])
        source = json.loads((UGIR_ROOT / original["path"]).read_text(encoding="utf-8"))
        for mutate in (
                lambda record: record["variants"][0]["R_measured"]["native_readout"]["rows"][0].update(wilson_lower_95=float("nan")),
                lambda record: record["variants"][0]["controls"]["positive_control"].update(resident_rate=float("nan")),
                lambda record: record["variants"][0]["R_measured"]["native_readout"]["rows"][0].update(resident_rate=10 ** 400)):
            record = json.loads(json.dumps(source))
            mutate(record)
            with self.subTest(mutation=str(mutate)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                payload = json.dumps(record).encode("utf-8")
                (root / "record.json").write_bytes(payload)
                case = dict(original, path="record.json", sha256=sha256(payload).hexdigest())
                with self.assertRaises(EvidenceError):
                    verify_case(case, root)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_admitted_status_requires_measured_reliability_floor(self):
        case = dict(load_manifest(MANIFEST)[0])
        record = json.loads((UGIR_ROOT / case["path"]).read_text(encoding="utf-8"))
        row = record["variants"][0]["R_measured"]["native_readout"]["rows"][0]
        row["successes"] = 600
        row["wilson_lower_95"] = _wilson_lower(600, row["trials"])
        case["expected"] = dict(case["expected"])
        case["expected"]["rows"] = dict(case["expected"]["rows"])
        case["expected"]["rows"][row["bits"]] = [row["trials"], 600]
        measured = record["variants"][0]["R_measured"]
        measured["min_row_wilson_lower_95"] = row["wilson_lower_95"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = json.dumps(record).encode("utf-8")
            (root / "record.json").write_bytes(payload)
            case["path"] = "record.json"
            case["sha256"] = sha256(payload).hexdigest()
            with self.assertRaises(EvidenceError):
                verify_case(case, root)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_native_residency_must_agree_with_success_count(self):
        case = dict(load_manifest(MANIFEST)[0])
        record = json.loads((UGIR_ROOT / case["path"]).read_text(encoding="utf-8"))
        row = record["variants"][0]["R_measured"]["native_readout"]["rows"][3]
        row["resident_count"] = 0
        row["resident_rate"] = 0
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = json.dumps(record).encode("utf-8")
            (root / "record.json").write_bytes(payload)
            case["path"] = "record.json"
            case["sha256"] = sha256(payload).hexdigest()
            with self.assertRaises(EvidenceError):
                verify_case(case, root)

    def test_hash_matched_nonobject_record_fails_cleanly(self):
        case = dict(load_manifest(MANIFEST)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "record.json").write_bytes(b"[]")
            case["path"] = "record.json"
            case["sha256"] = sha256(b"[]").hexdigest()
            with self.assertRaises(EvidenceError):
                verify_case(case, root)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_tlb_joint_marginal_and_sham_hash_are_checked(self):
        case = next(c for c in load_manifest(MANIFEST)
                    if c["format"] == "tlb_histogram")
        raw = (UGIR_ROOT / case["path"]).read_bytes()
        mutated = raw.replace(b"30,45:3", b"90,45:3", 1)
        self.assertNotEqual(raw, mutated)
        with self.assertRaises(EvidenceError):
            _verify_tlb_histogram(case, mutated)
        bad_sham = dict(case)
        bad_sham["sham_sha256"] = "0" * 64
        with self.assertRaises(EvidenceError):
            verify_case(bad_sham, UGIR_ROOT)

    @unittest.skipUnless(UGIR_ROOT.exists(), "external UGIR checkout unavailable")
    def test_tlb_joint_decode_must_match_reported_detection(self):
        case = next(c for c in load_manifest(MANIFEST)
                    if c["format"] == "tlb_histogram")
        lines = (UGIR_ROOT / case["path"]).read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if line.startswith("J row=1,1 "):
                line = line.replace("32,37:1", "32,37:0")
                line = line.replace("39,45:1", "39,45:0")
                line = line.replace("32,45:157", "32,45:158") + " 39,37:1"
                lines[index] = line
                break
        else:
            self.fail("missing joint row")
        with self.assertRaises(EvidenceError):
            _verify_tlb_histogram(case, "\n".join(lines).encode("utf-8"))


if __name__ == "__main__":
    unittest.main()
