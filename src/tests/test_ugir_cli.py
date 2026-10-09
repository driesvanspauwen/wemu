from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ugir_cli import main
from ugir_trace import Trace


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        output = StringIO()
        with redirect_stdout(output):
            status = main(list(args))
        return status, json.loads(output.getvalue())

    def test_capability_output_identifies_abstract_and_observation_scope(self):
        status, result = self.run_cli("capabilities")
        self.assertEqual(status, 0)
        self.assertEqual(result["branch_predictor"]["mechanisms"]["btb"], "abstract")
        self.assertEqual(result["prefetcher"]["role"], "observed_only")

    def test_replay_summary_shows_microstate_and_no_fidelity_claim(self):
        trace = Trace()
        trace.add("spec_begin", 0, "architectural")
        trace.add("cache_fill", 1, "transient", address=0x2041)
        trace.add("spec_end", 2, "transient", details={"rollback": True})
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "trace.json"
            source.write_text(trace.to_json(), encoding="utf-8")
            status, result = self.run_cli("replay", str(source))
        self.assertEqual(status, 0)
        self.assertEqual(result["cache_lines"], [0x2040])
        self.assertEqual(result["model_fidelity"], "not_assessed")
        self.assertEqual(result["event_counts"]["spec_begin"], 1)

    def test_replay_can_inspect_microstate_before_rollback(self):
        trace = Trace()
        trace.add("btb_train", 0, "architectural", address=0x1000,
                  details={"target": 0x2000})
        trace.add("tlb_fill", 1, "architectural", address=0x3000,
                  details={"physical_page": 0x9000})
        trace.add("mdp_train", 2, "architectural", address=0x4000,
                  details={"wait_for_store": True})
        trace.add("store_enqueue", 3, "architectural", address=0x5000,
                  details={"value": 1})
        trace.add("spec_begin", 4, "architectural")
        trace.add("store_enqueue", 5, "transient", address=0x5000,
                  details={"value": 2})
        trace.add("load_probe", 6, "transient", address=0x5000)
        trace.add("spec_end", 7, "transient", details={"rollback": True})
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "trace.json"
            source.write_text(trace.to_json(), encoding="utf-8")
            status, middle = self.run_cli("replay", str(source), "--at", "6")
            final_status, final = self.run_cli("replay", str(source))
        self.assertEqual((status, final_status), (0, 0))
        self.assertEqual(middle["selected_event"]["kind"], "load_probe")
        self.assertEqual(middle["events"], 7)
        self.assertTrue(middle["in_speculation"])
        self.assertEqual(middle["btb"], {"4096": 8192})
        self.assertEqual(middle["tlb"], {"12288": 36864})
        self.assertEqual(middle["mdp"], {"16384": True})
        self.assertEqual(middle["pending_stores"], [{"address": 0x5000, "value": 1}])
        self.assertEqual(middle["transient_stores"], [{"address": 0x5000, "value": 2}])
        self.assertEqual(middle["observations"][-1]["value"], 2)
        self.assertEqual(final["transient_stores"], [])

    def test_replay_rejects_out_of_range_inspection_step(self):
        trace = Trace()
        trace.add("cache_fill", 0, "architectural", address=0x1000)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "trace.json"
            source.write_text(trace.to_json(), encoding="utf-8")
            status, result = self.run_cli("replay", str(source), "--at", "2")
        self.assertEqual(status, 2)
        self.assertIn("event", result["error"])


if __name__ == "__main__":
    unittest.main()
