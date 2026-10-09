"""Pinned on-host AMD examples; these do not assess WeMu model fidelity."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ugir_evidence import verify_case


ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / "evidence" / "live"
CPU = "AMD AMD family 0x19 model 0x21"

RECORDS = (
    ("legacy", 505, "a3c3bc338d6188fb805d5fb555c794e11dda89c78da3ba11a046cea3d376446e", 894),
    ("legacy", 606, "baeb3cd22114cd885f9f22584d2247068fa13ef8e33bcf26fde42348a1c4568d", 896),
    ("current", 505, "2074788ae5fd8fa4900a60d60e14c8d535961900ec2806091fbb602e244e90eb", 1000),
    ("current", 606, "def7efdbbfa3f26feff4ca935bba2c25415242edb4d9c4883833be0eb23b7958", 1000),
)


class LiveAmdEvidenceTests(unittest.TestCase):
    def test_native_records_and_controls_are_pinned(self):
        for source, seed, digest, row11 in RECORDS:
            with self.subTest(source=source, seed=seed):
                name = f"amd-{source}-cache-and-seed-{seed}.json"
                record = json.loads((LIVE / name).read_text(encoding="utf-8"))
                admitted = source == "current"
                expected = {"transient": True,
                            "admission": "admitted" if admitted else "rejected"}
                if admitted:
                    expected["rows"] = {"00": [1000, 1000], "01": [1000, 1000],
                                        "10": [1000, 1000], "11": [1000, row11]}
                else:
                    expected.update(variant_status="fail", weirdness_c="supported",
                                    reason="min_row_below_admission_floor")
                case = {"id": name, "substrate": "cache",
                        "format": "ugir_aggregate" if admitted else "ugir_rejection",
                        "path": name, "sha256": digest, "cpu": "AMD Ryzen 7 5700X",
                        "source_model": CPU,
                        "source_machine_id": ("testbed-amd-family-0x19-model-0x21"
                                              if admitted else "testbed-broadwell"),
                        "expected": expected}
                report = verify_case(case, LIVE)
                self.assertTrue(report["source_verified"])
                self.assertEqual(report["schema_validation"], "not_assessed")
                self.assertEqual(report["model_fidelity"], "not_assessed")
                self.assertEqual(report["source_oracle_status"], expected["admission"])
                self.assertEqual(record["R"]["admission_floor_phi"],
                                 0.8 if admitted else 0.9)
                native = record["variants"][0]["R_measured"]["native_readout"]
                self.assertEqual({row["bits"]: row["successes"] for row in native["rows"]},
                                 {"00": 1000, "01": 1000, "10": 1000, "11": row11})
                control = record["variants"][0]["controls"]
                self.assertTrue(control["negative_sham"]["input_independent"])
                self.assertEqual([row["resident_count"] for row in
                                  control["negative_sham"]["sham_rows"]], [0] * 4)
                self.assertGreaterEqual(control["positive_control"]["resident_rate"],
                                        255 / 256)


if __name__ == "__main__":
    unittest.main()
