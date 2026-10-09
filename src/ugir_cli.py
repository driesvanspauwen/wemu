"""Inspect WeMu/UGIR trace scope and verify external silicon evidence."""

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import List, Optional

from ugir_evidence import EvidenceError, verify_manifest
from ugir_trace import Replay, Trace, class_catalog


def _output(value):
    print(json.dumps(value, sort_keys=True, indent=2))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    command.add_parser("capabilities", help="show substrate capability and evidence scope")
    replay_parser = command.add_parser("replay", help="inspect a versioned WeMu trace")
    replay_parser.add_argument("trace", type=Path)
    evidence_parser = command.add_parser("verify-evidence", help="verify pinned UGIR source records")
    evidence_parser.add_argument("--ugir-root", required=True, type=Path)
    evidence_parser.add_argument("--manifest", type=Path,
                                 default=Path(__file__).resolve().parents[1] /
                                 "evidence" / "ugir-silicon-v1.json")
    args = parser.parse_args(argv)

    try:
        if args.command == "capabilities":
            _output({name: {"role": spec.role,
                            "gate_emulation": sorted(spec.gate_mechanisms),
                            "mechanisms": {key: capability.value
                                           for key, capability in spec.mechanisms.items()}}
                     for name, spec in class_catalog().items()})
        elif args.command == "replay":
            trace = Trace.from_json(args.trace.read_text(encoding="utf-8"))
            state = Replay(trace.line_size, trace.page_size).run(trace)
            if state.in_speculation:
                raise ValueError("incomplete trace: speculation remains active")
            _output({"trace_version": 1, "events": len(trace.events),
                     "model": {"line_size": trace.line_size,
                               "page_size": trace.page_size,
                               "clock": "logical_order"},
                     "event_counts": dict(sorted(Counter(event.kind for event in trace.events).items())),
                     "cache_lines": sorted(state.cache_lines),
                     "btb": {str(key): value for key, value in sorted(state.btb.items())},
                     "tlb": {str(key): value for key, value in sorted(state.tlb.items())},
                     "mdp": {str(key): value for key, value in sorted(state.mdp.items())},
                     "observations": state.observations,
                     "model_fidelity": "not_assessed"})
        elif args.command == "verify-evidence":
            _output({"mode": "stored_silicon_evidence_verification",
                     "cases": verify_manifest(args.manifest, args.ugir_root),
                     "emulator_fidelity": "not_assessed"})
    except (OSError, ValueError, EvidenceError, json.JSONDecodeError) as exc:
        _output({"error": str(exc)})
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
