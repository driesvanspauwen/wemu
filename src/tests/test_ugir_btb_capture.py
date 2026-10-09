"""Pinned AMD BTB one-shot rows are observations, not a predictor model."""

from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ugir_btb_capture import load_btb_run
from ugir_trace import Replay


FIELDS = ("round,a,b,expected,real_signal_cycles,real_signal_hit,decoded,"
          "correct,sham_signal_cycles,sham_signal_hit,committed_equal,"
          "indirect_misses,branch_misses,retired_branches,"
          "sham_indirect_misses,sham_branch_misses,sham_retired_branches")
ORDERS = (((0, 1), (0, 0), (1, 0), (1, 1)),
          ((0, 0), (1, 0), (0, 1), (1, 1)))  # UGIR seed 101, rounds 0 and 1


def write_bundle(directory, *, rows=None, reported_correct=None,
                 report_source_commit="test-source", seed=101):
    if rows is None:
        rows = []
        for round_number, order in enumerate(ORDERS):
            for a, b in order:
                value = a & b
                rows.append([round_number, a, b, value, 68 if value else 306,
                             value, value, 1, 340, 0, 1, 1, 4, 32, 1, 4, 32])
    csv_bytes = (FIELDS + "\n" + "".join(
        ",".join(str(value) for value in row) + "\n" for row in rows)).encode()
    csv_path = directory / "held.csv"
    csv_path.write_bytes(csv_bytes)
    csv_hash = sha256(csv_bytes).hexdigest()
    manifest = {"cpu": "synthetic", "logical_cpu": 1,
                "source_commit": "test-source", "binary_sha256": "a" * 64,
                "runs": [{"id": "held-1", "split": "held", "seed": seed,
                          "path": "held.csv", "sha256": csv_hash}]}
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
    (directory / "manifest.json").write_bytes(manifest_bytes)
    manifest_hash = sha256(manifest_bytes).hexdigest()
    reports = []
    for a, b in ((0, 0), (0, 1), (1, 0), (1, 1)):
        group = [row for row in rows if row[1:3] == [a, b]]
        reports.append({"bits": f"{a}{b}", "trials": len(group),
                        "correct": sum(row[7] for row in group),
                        "signal_hits": sum(row[5] for row in group),
                        "sham_hits": sum(row[9] for row in group),
                        "committed_mismatches": sum(1 - row[10] for row in group)})
    if reported_correct is not None:
        reports[0]["correct"] = reported_correct
    report = {"manifest_sha256": manifest_hash, "binary_sha256": "a" * 64,
              "source_commit": report_source_commit,
              "oracle_admitted": False,
              "runs": [{"id": "held-1", "split": "held", "seed": seed,
                        "source_path": "held.csv", "source_sha256": csv_hash,
                        "rows": reports}]}
    report_bytes = json.dumps(report, sort_keys=True).encode()
    (directory / "report.json").write_bytes(report_bytes)
    return manifest_hash, sha256(report_bytes).hexdigest()


class BTBCaptureTests(unittest.TestCase):
    def test_imports_ordered_readouts_with_explicit_provenance_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, report_hash = write_bundle(bundle)
            capture = load_btb_run(bundle, "held-1",
                                   expected_manifest_sha256=manifest_hash,
                                   expected_report_sha256=report_hash)
        self.assertEqual(len(capture.trace.events), 8)
        self.assertEqual(capture.native_rows["11"], [2, 2])
        self.assertEqual(capture.trace.metadata["calibration_threshold"], "not_recorded")
        self.assertFalse(capture.trace.metadata["oracle_admitted"])
        self.assertEqual(capture.feasible_threshold_interval, [68, 305])
        observations = Replay().run(capture.trace).observations
        self.assertEqual([item["round"] for item in observations],
                         [0, 0, 0, 0, 1, 1, 1, 1])
        self.assertEqual(sum(item["decoded"] for item in observations), 2)

    def test_replay_rejects_tampered_btb_truth_field(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, report_hash = write_bundle(bundle)
            capture = load_btb_run(bundle, "held-1",
                                   expected_manifest_sha256=manifest_hash,
                                   expected_report_sha256=report_hash)
        capture.trace.events[0].details["correct"] = 0
        with self.assertRaisesRegex(ValueError, "BTB readout"):
            Replay().run(capture.trace)
        capture.trace.events[0].details["correct"] = 1
        capture.trace.events[0].details["real_signal_cycles"] = 20
        with self.assertRaisesRegex(ValueError, "BTB readout"):
            Replay().run(capture.trace)

    def test_failed_direct_readout_does_not_change_replay_state(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, report_hash = write_bundle(bundle)
            capture = load_btb_run(bundle, "held-1",
                                   expected_manifest_sha256=manifest_hash,
                                   expected_report_sha256=report_hash)
        replay = Replay()
        replay.apply(capture.trace.events[0])  # miss at 306 cycles
        before = (replay._btb_readout_max_hit,
                  replay._btb_readout_min_miss, len(replay.observations))
        bad = capture.trace.events[3]  # hit on row 11
        bad.details["real_signal_cycles"] = 400
        with self.assertRaisesRegex(ValueError, "threshold"):
            replay.apply(bad)
        self.assertEqual((replay._btb_readout_max_hit,
                          replay._btb_readout_min_miss, len(replay.observations)), before)

    def test_rejects_changed_source_and_report_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, report_hash = write_bundle(bundle)
            with (bundle / "held.csv").open("ab") as stream:
                stream.write(b"\n")
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)
            manifest_hash, report_hash = write_bundle(bundle, reported_correct=0)
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)

    def test_rejects_conflicting_manifest_and_report_source_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, report_hash = write_bundle(
                bundle, report_source_commit="different-source")
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)

    def test_rejects_duplicate_attempt_even_when_files_are_rehashed(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            rows = []
            for round_number, order in enumerate(ORDERS):
                for a, b in order:
                    value = a & b
                    rows.append([round_number, a, b, value, 68 if value else 306,
                                 value, value, 1, 340, 0, 1, 1, 4, 32, 1, 4, 32])
            rows[2][1:3] = [0, 1]
            manifest_hash, report_hash = write_bundle(bundle, rows=rows)
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)

    def test_preserves_negative_control_attempts(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            rows = []
            for round_number, order in enumerate(ORDERS):
                for a, b in order:
                    value = a & b
                    rows.append([round_number, a, b, value, 68 if value else 306,
                                 value, value, 1, 340, 0, 1, 1, 4, 32, 1, 4, 32])
            rows[0][9] = 1
            rows[0][8] = 68
            rows[0][10] = 0
            manifest_hash, report_hash = write_bundle(bundle, rows=rows)
            capture = load_btb_run(bundle, "held-1",
                                   expected_manifest_sha256=manifest_hash,
                                   expected_report_sha256=report_hash)
        first = Replay().run(capture.trace).observations[0]
        self.assertEqual((first["sham_signal_hit"], first["committed_equal"]),
                         (1, 0))

    def test_rejects_impossible_threshold_labels_with_rehashed_files(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            rows = []
            for round_number, order in enumerate(ORDERS):
                for a, b in order:
                    value = a & b
                    rows.append([round_number, a, b, value,
                                 100 if value else 20, value, value, 1,
                                 20, 0, 1, 1, 4, 32, 1, 4, 32])
            manifest_hash, report_hash = write_bundle(bundle, rows=rows)
            with self.assertRaisesRegex(ValueError, "threshold"):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)

    def test_rejects_wrong_seed_shuffle_with_rehashed_files(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            rows = []
            for round_number, order in enumerate(ORDERS):
                for a, b in order:
                    value = a & b
                    rows.append([round_number, a, b, value, 68 if value else 306,
                                 value, value, 1, 340, 0, 1, 1, 4, 32, 1, 4, 32])
            rows[0], rows[1] = rows[1], rows[0]
            manifest_hash, report_hash = write_bundle(bundle, rows=rows)
            with self.assertRaisesRegex(ValueError, "shuffle"):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=report_hash)

    def test_accepts_full_uint64_seed_used_by_source_shuffle(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            rows = []
            orders = (((1, 1), (1, 0), (0, 1), (0, 0)),
                      ((1, 0), (0, 0), (1, 1), (0, 1)))
            for round_number, order in enumerate(orders):
                for a, b in order:
                    value = a & b
                    rows.append([round_number, a, b, value, 68 if value else 306,
                                 value, value, 1, 340, 0, 1, 1, 4, 32, 1, 4, 32])
            manifest_hash, report_hash = write_bundle(bundle, rows=rows,
                                                      seed=0x100000000)
            capture = load_btb_run(bundle, "held-1",
                                   expected_manifest_sha256=manifest_hash,
                                   expected_report_sha256=report_hash)
        self.assertEqual(capture.trace.metadata["seed"], 0x100000000)

    def test_rejects_nonfinite_report_json_even_when_rehashed(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, _ = write_bundle(bundle)
            report_path = bundle / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["held_worst_row_wilson_lower_95"] = float("nan")
            report_bytes = json.dumps(report).encode()
            report_path.write_bytes(report_bytes)
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=sha256(report_bytes).hexdigest())

    def test_rejects_duplicate_report_json_keys_even_when_rehashed(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp)
            manifest_hash, _ = write_bundle(bundle)
            report_path = bundle / "report.json"
            report_bytes = b'{"probe":1,"probe":2,' + report_path.read_bytes()[1:]
            report_path.write_bytes(report_bytes)
            with self.assertRaises(ValueError):
                load_btb_run(bundle, "held-1",
                             expected_manifest_sha256=manifest_hash,
                             expected_report_sha256=sha256(report_bytes).hexdigest())


if __name__ == "__main__":
    unittest.main()
