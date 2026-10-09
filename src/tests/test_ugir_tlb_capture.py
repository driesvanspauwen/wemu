"""Ordered TLB readout capture must preserve trial identity and raw counts."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ugir_tlb_capture import parse_tlb_capture
from ugir_trace import Replay, Trace


SAMPLE = """UCAP_CONFIG v=1 gate=AND rows=4 n=1 threshold=39 seed=5001
H row=0,0 rail=1 50:1
H row=0,0 rail=0 20:1
H row=1,0 rail=1 50:1
H row=1,0 rail=0 20:1
H row=0,1 rail=1 50:1
H row=0,1 rail=0 20:1
H row=1,1 rail=1 20:1
H row=1,1 rail=0 50:1
J row=0,0 50,20:1
J row=1,0 50,20:1
J row=0,1 50,20:1
J row=1,1 20,50:1
AND row=0,0 n=1 ok=1 detected=0 undetected=0 raw1=0
AND row=1,0 n=1 ok=1 detected=0 undetected=0 raw1=0
AND row=0,1 n=1 ok=1 detected=0 undetected=0 raw1=0
AND row=1,1 n=1 ok=1 detected=0 undetected=0 raw1=1
UCAP v=1 seq=0 row=0,0 rail1=50 rail0=20
UCAP v=1 seq=1 row=1,0 rail1=50 rail0=20
UCAP v=1 seq=2 row=0,1 rail1=50 rail0=20
UCAP v=1 seq=3 row=1,1 rail1=20 rail0=50
"""


class OrderedCaptureTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_native_wrapper_emits_reconstructable_trial_log(self):
        wrapper = Path(__file__).resolve().parents[2] / "native" / "ugir_tlb_ordered_capture.c"
        stub = r'''
#include <stdint.h>
#include <stdio.h>
int64_t WR_HIT_THRESHOLD;
static unsigned index_value;
uint64_t timer_raw(void *address) {
    static const uint64_t values[] = {50,20,50,20,50,20,20,50};
    (void)address;
    return values[index_value++];
}
extern uint64_t timer(void *address);
int main(void) {
    for (int i = 0; i < 8; i++) timer(0);
    puts("AND row=0,0 n=1 ok=1 detected=0 undetected=0 raw1=0");
    puts("AND row=1,0 n=1 ok=1 detected=0 undetected=0 raw1=0");
    puts("AND row=0,1 n=1 ok=1 detected=0 undetected=0 raw1=0");
    puts("AND row=1,1 n=1 ok=1 detected=0 undetected=0 raw1=1");
    return WR_HIT_THRESHOLD == 39 ? 0 : 1;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "stub.c"
            binary = Path(directory) / "capture"
            source.write_text(stub, encoding="utf-8")
            build = subprocess.run(["cc", "-std=c11", "-O2", str(wrapper),
                                    str(source), "-o", str(binary)],
                                   capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 env={**os.environ, "UGIR_ROWS": "4", "UGIR_N": "1",
                                      "UGIR_THR": "39", "UGIR_SEED": "5001"})
            self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
            self.assertEqual(parse_tlb_capture(run.stdout, threshold=39, seed=5001,
                                               trials_per_row=1).native_rows["1,1"],
                             [1, 1])

    def test_trial_log_reconstructs_histograms_and_replays_observations(self):
        result = parse_tlb_capture(SAMPLE.encode(), threshold=39, seed=5001,
                                   trials_per_row=1)
        trace = Trace.from_json(result.trace.to_json())
        self.assertEqual(len(trace.events), 4)
        self.assertEqual(trace.metadata["source_sha256"],
                         hashlib.sha256(SAMPLE.encode()).hexdigest())
        self.assertEqual(result.native_rows,
                         {"0,0": [1, 1], "1,0": [1, 1],
                          "0,1": [1, 1], "1,1": [1, 1]})
        observations = Replay().run(trace).observations
        self.assertEqual([item["row"] for item in observations],
                         ["0,0", "1,0", "0,1", "1,1"])
        self.assertEqual([item["raw1"] for item in observations],
                         [False, False, False, True])
        self.assertTrue(all(item["success"] for item in observations))

    def test_joint_histogram_must_match_ordered_trials(self):
        corrupted = SAMPLE.replace("J row=1,1 20,50:1",
                                   "J row=1,1 20,20:1")
        with self.assertRaises(ValueError):
            parse_tlb_capture(corrupted.encode(), threshold=39, seed=5001,
                              trials_per_row=1)

    def test_sequence_and_row_order_are_required(self):
        for corrupted in (
                SAMPLE.replace("seq=2 row=0,1", "seq=4 row=0,1"),
                SAMPLE.replace("seq=2 row=0,1", "seq=2 row=1,0"),
                SAMPLE.replace("UCAP v=1 seq=3 row=1,1 rail1=20 rail0=50\n", "")):
            with self.subTest(corrupted=corrupted[-120:]), self.assertRaises(ValueError):
                parse_tlb_capture(corrupted.encode(), threshold=39, seed=5001,
                                  trials_per_row=1)

    def test_threshold_change_exposes_decode_mismatch(self):
        for threshold in (10, 40):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                parse_tlb_capture(SAMPLE.encode(), threshold=threshold, seed=5001,
                                  trials_per_row=1)

    def test_replay_rejects_tampered_native_readout(self):
        trace = parse_tlb_capture(SAMPLE.encode(), threshold=39, seed=5001,
                                  trials_per_row=1).trace
        trace.events[0].details["raw1"] = True
        with self.assertRaisesRegex(ValueError, "differs from latencies"):
            Replay().run(trace)

    def test_rejects_duplicate_or_malformed_capture_rows(self):
        for corrupted in (
                SAMPLE + "H row=0,0 rail=1 50:1\n",
                SAMPLE.replace("UCAP v=1 seq=0", "UCAP v=2 seq=0"),
                SAMPLE + "FATAL timer failed\n",
                SAMPLE + " UCAP v=1 seq=99 row=0,0 rail1=50 rail0=20\n",
                SAMPLE.replace("seed=5001", "seed=1234"),
                SAMPLE.replace("H row=0,0 rail=1 50:1",
                               "H row=0,0 rail=1 399:1")
                      .replace("J row=0,0 50,20:1",
                               "J row=0,0 199,20:1")
                      .replace("UCAP v=1 seq=0 row=0,0 rail1=50",
                               "UCAP v=1 seq=0 row=0,0 rail1=18446744073709551616"),
                SAMPLE.replace("AND row=1,1 n=1 ok=1",
                               "AND row=1,1 n=1 ok=0")):
            with self.subTest(corrupted=corrupted[-100:]), self.assertRaises(ValueError):
                parse_tlb_capture(corrupted.encode(), threshold=39, seed=5001,
                                  trials_per_row=1)


if __name__ == "__main__":
    unittest.main()
