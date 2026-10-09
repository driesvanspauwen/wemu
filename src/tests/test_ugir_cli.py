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


if __name__ == "__main__":
    unittest.main()
