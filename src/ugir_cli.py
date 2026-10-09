"""Inspect WeMu/UGIR trace scope and verify external silicon evidence."""

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
from typing import List, Optional

from ugir_evidence import EvidenceError, verify_manifest
from ugir_tlb_capture import MAX_CAPTURE_BYTES, parse_tlb_capture
from ugir_trace import Replay, Trace, class_catalog


def _output(value):
    print(json.dumps(value, sort_keys=True, indent=2))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    command.add_parser("capabilities", help="show substrate capability and evidence scope")
    replay_parser = command.add_parser("replay", help="inspect a versioned WeMu trace")
    replay_parser.add_argument("trace", type=Path)
    replay_parser.add_argument("--at", type=int, metavar="SEQUENCE",
                               help="show state immediately after this event")
    capture_parser = command.add_parser("ingest-tlb",
                                        help="check four-row native TLB-AND readouts and export a trace")
    capture_parser.add_argument("source", type=Path)
    capture_parser.add_argument("--threshold", required=True, type=int)
    capture_parser.add_argument("--seed", required=True, type=int)
    capture_parser.add_argument("--trials-per-row", required=True, type=int)
    capture_parser.add_argument("--output", required=True, type=Path)
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
            if args.at is not None and (args.at < 0 or args.at >= len(trace.events)):
                raise ValueError("event sequence is out of range")
            viewed = (Trace(trace.events[:args.at + 1], trace.line_size,
                            trace.page_size, trace.metadata)
                      if args.at is not None else trace)
            state = Replay(trace.line_size, trace.page_size).run(viewed)
            if args.at is None and state.in_speculation:
                raise ValueError("incomplete trace: speculation remains active")
            _output({"trace_version": 1, "events": len(viewed.events),
                     "selected_event": (asdict(trace.events[args.at])
                                        if args.at is not None else None),
                     "model": {"line_size": trace.line_size,
                                "page_size": trace.page_size,
                                "clock": "logical_order"},
                     "metadata": trace.metadata,
                     "event_counts": dict(sorted(Counter(event.kind for event in viewed.events).items())),
                     "in_speculation": state.in_speculation,
                     "cache_lines": sorted(state.cache_lines),
                     "btb": {str(key): value for key, value in sorted(state.btb.items())},
                     "tlb": {str(key): value for key, value in sorted(state.tlb.items())},
                     "mdp": {str(key): value for key, value in sorted(state.mdp.items())},
                     "pending_stores": [{"address": address, "value": value}
                                        for address, value in state.pending_stores],
                     "transient_stores": [{"address": address, "value": value}
                                          for address, value in state.transient_stores],
                     "rsb": state.rsb,
                     "observations": state.observations,
                     "model_fidelity": "not_assessed"})
        elif args.command == "ingest-tlb":
            if args.source.resolve() == args.output.resolve():
                raise ValueError("output trace must differ from native source")
            with args.source.open("rb") as stream:
                data = stream.read(MAX_CAPTURE_BYTES + 1)
            captured = parse_tlb_capture(data,
                                         threshold=args.threshold,
                                         seed=args.seed,
                                         trials_per_row=args.trials_per_row)
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(captured.trace.to_json() + "\n")
            _output({"output": str(args.output),
                     "source_sha256": captured.trace.metadata["source_sha256"],
                     "events": len(captured.trace.events),
                     "native_rows": captured.native_rows,
                     "min_row_wilson_lower_95": captured.min_row_wilson_lower_95,
                     "native_observation_only": True,
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
