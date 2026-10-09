import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ugir_trace import (
    Capability,
    Event,
    Replay,
    Trace,
    class_catalog,
    require_compute,
)


class TaxonomyTests(unittest.TestCase):
    def test_all_ugir_classes_are_explicit(self):
        catalog = class_catalog()
        self.assertEqual(len(catalog), 13)
        self.assertEqual(sum(x.role == "computed" for x in catalog.values()), 5)
        self.assertEqual(sum(x.role == "observed_only" for x in catalog.values()), 8)
        self.assertEqual(catalog["cache"].mechanisms["cache_line"], Capability.INSTRUCTION)
        self.assertEqual(catalog["branch_predictor"].mechanisms["btb"], Capability.ABSTRACT)
        self.assertEqual(catalog["branch_predictor"].mechanisms["rsb"], Capability.TRIGGER)
        self.assertEqual(catalog["tlb_page_walk"].mechanisms["tlb"], Capability.ABSTRACT)
        self.assertEqual(catalog["cache"].gate_mechanisms, frozenset({"cache_line"}))
        self.assertEqual(catalog["branch_predictor"].gate_mechanisms, frozenset())

    def test_observed_only_class_cannot_claim_gate_emulation(self):
        with self.assertRaises(ValueError):
            require_compute("prefetcher", "prefetcher")
        with self.assertRaises(ValueError):
            require_compute("branch_predictor", "unknown")
        with self.assertRaises(ValueError):
            require_compute("branch_predictor", "btb")
        with self.assertRaises(ValueError):
            require_compute("branch_predictor", "rsb")
        with self.assertRaises(ValueError):
            require_compute("transient_ooo_window", "ooo_scheduler")
        self.assertEqual(require_compute("cache", "cache_line"), Capability.INSTRUCTION)


class TraceTests(unittest.TestCase):
    def test_boolean_trace_version_is_rejected(self):
        document = json.loads(Trace().to_json())
        document["version"] = True
        with self.assertRaises(ValueError):
            Trace.from_json(json.dumps(document))

    def test_round_trip_preserves_phase_and_integer_addresses(self):
        trace = Trace()
        trace.add("spec_begin", cycle=1, phase="architectural", address=0x1000)
        trace.add("cache_fill", cycle=2, phase="transient", address=0x2000)
        trace.add("spec_end", cycle=3, phase="transient", details={"rollback": True})
        restored = Trace.from_json(trace.to_json())
        self.assertEqual(restored.events, trace.events)
        self.assertEqual(json.loads(trace.to_json())["version"], 1)

    def test_custom_cache_line_size_round_trips_and_aligns_replay(self):
        trace = Trace(line_size=128)
        trace.add("cache_fill", 0, "architectural", address=0x2041)
        restored = Trace.from_json(trace.to_json())
        self.assertEqual(restored.line_size, 128)
        self.assertEqual(Replay(line_size=128).run(restored).cache_lines, {0x2000})
        with self.assertRaises(ValueError):
            Replay(line_size=64).run(restored)

    def test_rejects_sequence_cycle_and_phase_errors(self):
        with self.assertRaises(ValueError):
            Trace([Event(1, "cache_fill", 0, "architectural", 0x1000)])
        with self.assertRaises(ValueError):
            Trace([Event(0, "cache_fill", -1, "architectural", 0x1000)])
        with self.assertRaises(ValueError):
            Trace([Event(0, "unknown", 0, "architectural")])
        trace = Trace()
        trace.add("spec_begin", cycle=0, phase="architectural")
        with self.assertRaises(ValueError):
            trace.add("cache_fill", cycle=1, phase="architectural", address=0x1000)

    def test_transient_cache_and_predictor_side_effects_survive_rollback(self):
        trace = Trace()
        trace.add("spec_begin", cycle=0, phase="architectural")
        trace.add("cache_fill", cycle=1, phase="transient", address=0x2041)
        trace.add("btb_train", cycle=2, phase="transient", address=0x1000,
                  details={"target": 0x3000})
        trace.add("store_enqueue", cycle=3, phase="transient", address=0x4000,
                  details={"value": 7})
        trace.add("spec_end", cycle=4, phase="transient", details={"rollback": True})
        state = Replay().run(trace)
        self.assertIn(0x2040, state.cache_lines)
        self.assertEqual(state.btb[0x1000], 0x3000)
        self.assertEqual(state.pending_stores, [])
        self.assertFalse(state.in_speculation)

    def test_rollback_discards_transient_store_but_keeps_older_drain(self):
        trace = Trace()
        trace.add("store_enqueue", 0, "architectural", address=0x10,
                  details={"value": 1})
        trace.add("store_enqueue", 1, "architectural", address=0x20,
                  details={"value": 2})
        trace.add("spec_begin", 2, "architectural")
        trace.add("store_enqueue", 3, "transient", address=0x30,
                  details={"value": 3})
        trace.add("store_drain", 4, "transient", address=0x10)
        trace.add("spec_end", 5, "transient", details={"rollback": True})
        self.assertEqual(Replay().run(trace).pending_stores, [(0x20, 2)])

    def test_transient_store_cannot_drain_to_memory(self):
        trace = Trace()
        trace.add("spec_begin", 0, "architectural")
        trace.add("store_enqueue", 1, "transient", address=0x30,
                  details={"value": 3})
        trace.add("store_drain", 2, "transient", address=0x30)
        trace.add("spec_end", 3, "transient", details={"rollback": True})
        with self.assertRaises(ValueError):
            Replay().run(trace)

    def test_older_store_can_drain_under_same_address_transient_store(self):
        trace = Trace()
        trace.add("store_enqueue", 0, "architectural", address=0x30,
                  details={"value": 1})
        trace.add("spec_begin", 1, "architectural")
        trace.add("store_enqueue", 2, "transient", address=0x30,
                  details={"value": 2})
        trace.add("store_drain", 3, "transient", address=0x30)
        trace.add("load_probe", 4, "transient", address=0x30)
        trace.add("spec_end", 5, "transient", details={"rollback": True})
        state = Replay().run(trace)
        self.assertEqual(state.pending_stores, [])
        self.assertEqual(state.observations[-1]["value"], 2)

    def test_bad_rsb_pop_does_not_mutate_direct_replay(self):
        state = Replay()
        state.rsb.append(0x1234)
        event = Event(sequence=0, kind="rsb_pop", cycle=0,
                      phase="architectural", details={"target": 0x5678})
        with self.assertRaises(ValueError):
            state.apply(event)
        self.assertEqual(state.rsb, [0x1234])

    def test_tlb_mdp_and_store_forwarding_have_explicit_transitions(self):
        trace = Trace()
        trace.add("tlb_fill", 0, "architectural", address=0x1234,
                  details={"physical_page": 0xA000})
        trace.add("tlb_probe", 1, "architectural", address=0x1FFF)
        trace.add("mdp_train", 2, "architectural", address=0x5000,
                  details={"wait_for_store": True})
        trace.add("mdp_predict", 3, "architectural", address=0x5000)
        trace.add("store_enqueue", 4, "architectural", address=0x6000,
                  details={"value": 9})
        trace.add("load_probe", 5, "architectural", address=0x6000)
        state = Replay().run(trace)
        self.assertEqual(state.observations, [
            {"sequence": 1, "kind": "tlb_probe", "hit": True, "physical_page": 0xA000},
            {"sequence": 3, "kind": "mdp_predict", "wait_for_store": True},
            {"sequence": 5, "kind": "load_probe", "forwarded": True, "value": 9},
        ])

    def test_missing_transition_fields_fail_closed(self):
        trace = Trace()
        trace.add("btb_train", 0, "architectural", address=0x1000)
        with self.assertRaises(ValueError):
            Replay().run(trace)

    def test_failed_replay_does_not_mutate_reusable_state(self):
        trace = Trace()
        trace.add("cache_fill", 0, "architectural", address=0x1000)
        trace.add("btb_train", 1, "architectural", address=0x2000)
        replay = Replay()
        with self.assertRaises(ValueError):
            replay.run(trace)
        self.assertEqual(replay.cache_lines, set())

    def test_recorded_rsb_pop_must_match_replay_prediction(self):
        trace = Trace()
        trace.add("rsb_push", 0, "architectural", details={"target": 0x111})
        trace.add("rsb_push", 1, "architectural", details={"target": 0x222})
        trace.add("rsb_pop", 2, "architectural", details={"target": 0x111})
        with self.assertRaises(ValueError):
            Replay().run(trace)

    def test_memory_hit_claim_requires_resident_line(self):
        trace = Trace()
        trace.add("memory_read", 0, "architectural", address=0x2000,
                  details={"size": 8, "cache_hit": True})
        with self.assertRaises(ValueError):
            Replay().run(trace)

    def test_rsb_exception_address_reports_suppressed_push(self):
        from rsb import RSB

        rsb = RSB({0x222})
        self.assertTrue(rsb.add_ret_addr(0x111))
        self.assertFalse(rsb.add_ret_addr(0x222))
        self.assertEqual(rsb.pop_ret_addr(), 0x111)


class EmulatorHookTests(unittest.TestCase):
    def test_round_reset_emits_cache_and_speculation_changes(self):
        from emulator import MuWMEmulator
        from unicorn import UC_PROT_ALL

        class TinyLoader:
            def load(self, emulator):
                emulator.uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)

        trace = Trace()
        emulator = MuWMEmulator("ugir_trace_round_reset", TinyLoader(),
                                debug=False, trace=trace)
        emulator.cache.read(0x1000, emulator.uc)
        emulator._trace_cache_state(0x1000)
        emulator._trace("spec_begin", details={"trigger": "test"})
        emulator.in_speculation = True
        emulator.reset_round_state()
        replay = Replay().run(trace)
        self.assertFalse(replay.in_speculation)
        self.assertEqual(replay.cache_lines, set())

    def test_infinite_cache_trace_updates_do_not_scan_all_resident_lines(self):
        from emulator import MuWMEmulator
        from unicorn import UC_PROT_ALL

        class TinyLoader:
            def load(self, emulator):
                emulator.uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)

        emulator = MuWMEmulator("ugir_trace_scaling", TinyLoader(),
                                debug=False, trace=Trace())
        scans = [0]
        original = emulator.cache.resident_lines

        def counted():
            scans[0] += 1
            return original()

        emulator.cache.resident_lines = counted
        emulator._trace_cache_state()
        for index in range(100):
            address = 0x100000 + index * 64
            emulator.cache.read(address, emulator.uc)
            emulator._trace_cache_state(address)
        self.assertEqual(scans[0], 1)

    def test_exit_inside_speculation_rolls_back_architectural_state(self):
        from emulator import MuWMEmulator
        from unicorn import UC_PROT_ALL
        from unicorn.x86_const import UC_X86_REG_RAX

        class TinyLoader:
            def load(self, emulator):
                emulator.uc.mem_map(0x1000, 0x1000, UC_PROT_ALL)
                emulator.uc.mem_write(0x1000, b"\x90")

        trace = Trace()
        emulator = MuWMEmulator("ugir_trace_exit", TinyLoader(),
                                debug=False, trace=trace)
        emulator.code_start_address = 0x1000
        emulator.code_exit_addr = 0x1000
        emulator.uc.reg_write(UC_X86_REG_RAX, 7)
        emulator.checkpoint(emulator.uc, 0x1000)
        emulator._trace("spec_begin", details={"trigger": "test"})
        emulator.in_speculation = True
        emulator.speculation_limit = 10
        emulator.uc.reg_write(UC_X86_REG_RAX, 99)
        emulator.emulate()
        self.assertEqual(emulator.uc.reg_read(UC_X86_REG_RAX), 7)
        self.assertFalse(emulator.in_speculation)
        self.assertEqual([event.kind for event in trace.events].count("spec_end"), 1)

    def test_exception_and_binary_emits_replayable_trace(self):
        from emulator import MuWMEmulator
        from loader import ELFLoader
        from unicorn.x86_const import UC_X86_REG_RDI

        for left, right in ((0, 0), (0, 1), (1, 0), (1, 1)):
            with self.subTest(left=left, right=right):
                trace = Trace()
                emulator = MuWMEmulator(
                    name="ugir_trace_gitm_and", loader=ELFLoader("gates/gitm/main_and.elf"),
                    debug=False, trace=trace)
                emulator.code_start_address = 0x1490
                emulator.code_exit_addr = 0x161d
                for address, bit in ((0x81c0, left), (0x79c0, right)):
                    if bit:
                        emulator.cache.read(address, emulator.uc)
                emulator.uc.reg_write(UC_X86_REG_RDI, left | (right << 1))
                emulator.emulate()
                self.assertEqual(emulator.cache.is_cached(0x71c0), bool(left & right))
                self.assertIn("spec_begin", {event.kind for event in trace.events})
                self.assertIn("spec_end", {event.kind for event in trace.events})
                replay = Replay().run(Trace.from_json(trace.to_json()))
                self.assertEqual(replay.cache_lines, emulator.cache.cache)


if __name__ == "__main__":
    unittest.main()
