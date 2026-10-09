"""Versioned UGIR substrate trace and deliberately abstract replay models.

Only the original WeMu cache/exception/RSB path executes guest instructions.
Replay models are useful for inspecting hypotheses; they do not validate a
CPU-specific predictor, TLB, or memory-dependence implementation.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple


TRACE_VERSION = 1


class Capability(str, Enum):
    INSTRUCTION = "instruction"
    TRIGGER = "trigger"
    ABSTRACT = "abstract"
    OBSERVATION = "observation"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ClassSpec:
    role: str
    mechanisms: Mapping[str, Capability]
    gate_mechanisms: frozenset = frozenset()


_CATALOG: Dict[str, ClassSpec] = {
    "cache": ClassSpec("computed", {"cache_line": Capability.INSTRUCTION},
                       frozenset({"cache_line"})),
    "transient_ooo_window": ClassSpec("computed", {"exception": Capability.TRIGGER,
                                               "rsb": Capability.TRIGGER,
                                               "ooo_scheduler": Capability.INSTRUCTION}),
    "branch_predictor": ClassSpec("computed", {"rsb": Capability.TRIGGER,
                                             "btb": Capability.ABSTRACT,
                                             "direction": Capability.UNSUPPORTED}),
    "tlb_page_walk": ClassSpec("computed", {"tlb": Capability.ABSTRACT,
                                         "page_walk_gate": Capability.UNSUPPORTED}),
    "load_store_fill_dependence_buffers": ClassSpec(
        "computed", {"store_buffer": Capability.ABSTRACT,
                     "mdp": Capability.ABSTRACT,
                     "fill_buffer_gate": Capability.UNSUPPORTED}),
    "prefetcher": ClassSpec("observed_only", {"prefetcher": Capability.OBSERVATION}),
    "execution_ports": ClassSpec("observed_only", {"ports": Capability.OBSERVATION}),
    "dram_row_buffer": ClassSpec("observed_only", {"row_buffer": Capability.OBSERVATION}),
    "interconnect_coherence": ClassSpec("observed_only", {"coherence": Capability.OBSERVATION}),
    "memory_controller": ClassSpec("observed_only", {"controller": Capability.OBSERVATION}),
    "power_frequency": ClassSpec("observed_only", {"power": Capability.OBSERVATION}),
    "gpu_accelerator_fpga": ClassSpec("observed_only", {"accelerator": Capability.OBSERVATION}),
    "uop_cache_frontend": ClassSpec("observed_only", {"frontend": Capability.OBSERVATION}),
}


def class_catalog() -> Mapping[str, ClassSpec]:
    """Return a copy so callers cannot silently change the declared scope."""
    return {key: ClassSpec(value.role, dict(value.mechanisms),
                           value.gate_mechanisms)
            for key, value in _CATALOG.items()}


def require_compute(substrate: str, mechanism: str) -> Capability:
    spec = _CATALOG.get(substrate)
    capability = spec.mechanisms.get(mechanism) if spec else None
    if spec is None or spec.role != "computed" or (
            mechanism not in spec.gate_mechanisms or
            capability != Capability.INSTRUCTION):
        raise ValueError(f"compute mechanism unavailable: {substrate}/{mechanism}")
    return capability


EVENT_KINDS = frozenset({
    "instruction", "memory_read", "memory_write", "cache_fill", "cache_flush",
    "cache_evict",
    "rsb_push", "rsb_pop", "spec_begin", "spec_end", "pending_load_fill",
    "btb_train", "btb_predict", "tlb_fill", "tlb_probe", "mdp_train",
    "mdp_predict", "store_enqueue", "store_drain", "load_probe", "readout",
})
PHASES = frozenset({"architectural", "transient"})


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Event:
    sequence: int
    kind: str
    cycle: int
    phase: str
    address: Optional[int] = None
    instruction: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not _integer(self.sequence) or self.sequence < 0:
            raise ValueError("event sequence must be a nonnegative integer")
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind: {self.kind}")
        if not _integer(self.cycle) or self.cycle < 0:
            raise ValueError("event cycle must be a nonnegative integer")
        if self.phase not in PHASES:
            raise ValueError(f"invalid phase: {self.phase}")
        for name in ("address", "instruction"):
            value = getattr(self, name)
            if value is not None and (not _integer(value) or value < 0):
                raise ValueError(f"{name} must be a nonnegative integer")
        if not isinstance(self.details, dict):
            raise ValueError("details must be a JSON object")
        try:
            json.dumps(self.details, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("details must contain finite JSON values") from exc


class Trace:
    def __init__(self, events: Optional[List[Event]] = None,
                 line_size: int = 64, page_size: int = 4096,
                 metadata: Optional[Dict[str, Any]] = None):
        for name, size in (("line_size", line_size), ("page_size", page_size)):
            if not _integer(size) or size <= 0 or size & (size - 1):
                raise ValueError(f"{name} must be a positive power of two")
        self.line_size = line_size
        self.page_size = page_size
        if metadata is not None and (not isinstance(metadata, dict) or
                                     any(type(key) is not str for key in metadata)):
            raise ValueError("trace metadata must be a JSON object with string keys")
        self.metadata = dict(metadata or {})
        try:
            json.dumps(self.metadata, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("trace metadata must contain finite JSON values") from exc
        self.events: List[Event] = []
        self._transient = False
        for event in events or []:
            self._append(event)

    def _append(self, event: Event) -> None:
        event.validate()
        if event.sequence != len(self.events):
            raise ValueError("event sequence must be contiguous from zero")
        if self.events and event.cycle < self.events[-1].cycle:
            raise ValueError("event cycles must be nondecreasing")
        expected = "transient" if self._transient else "architectural"
        if event.phase != expected:
            raise ValueError(f"expected {expected} event phase")
        if event.kind == "spec_begin":
            if self._transient:
                raise ValueError("nested speculation is unsupported")
            self._transient = True
        elif event.kind == "spec_end":
            if not self._transient:
                raise ValueError("spec_end without spec_begin")
            if type(event.details.get("rollback")) is not bool:
                raise ValueError("spec_end requires boolean rollback")
            self._transient = False
        self.events.append(event)

    def add(self, kind: str, cycle: int, phase: str,
            address: Optional[int] = None, instruction: Optional[int] = None,
            details: Optional[Dict[str, Any]] = None) -> Event:
        event = Event(len(self.events), kind, cycle, phase, address, instruction,
                      dict(details or {}))
        self._append(event)
        return event

    def to_json(self) -> str:
        return json.dumps({"version": TRACE_VERSION,
                           "model": {"line_size": self.line_size,
                                      "page_size": self.page_size,
                                      "clock": "logical_order"},
                           "metadata": self.metadata,
                           "events": [asdict(event) for event in self.events]},
                          sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, source: str) -> "Trace":
        try:
            obj = json.loads(source)
            if not isinstance(obj, dict) or type(obj.get("version")) is not int or obj["version"] != TRACE_VERSION:
                raise ValueError("unsupported trace version")
            if not isinstance(obj.get("events"), list):
                raise ValueError("trace events must be a list")
            model = obj.get("model")
            if not isinstance(model, dict) or model.get("clock") != "logical_order":
                raise ValueError("trace model configuration missing or unsupported")
            events = [Event(**entry) for entry in obj["events"]]
            return cls(events, line_size=model["line_size"],
                       page_size=model["page_size"],
                       metadata=obj.get("metadata", {}))
        except (TypeError, KeyError) as exc:
            raise ValueError("malformed trace") from exc


class Replay:
    """Deterministic hypothesis model; no CPU-specific fidelity claim."""

    def __init__(self, line_size: int = 64, page_size: int = 4096):
        if not _integer(line_size) or line_size <= 0 or line_size & (line_size - 1):
            raise ValueError("line_size must be a positive power of two")
        if not _integer(page_size) or page_size <= 0 or page_size & (page_size - 1):
            raise ValueError("page_size must be a positive power of two")
        self.line_size = line_size
        self.page_size = page_size
        self.cache_lines = set()
        self.btb: Dict[int, int] = {}
        self.tlb: Dict[int, int] = {}
        self.mdp: Dict[int, bool] = {}
        self.rsb: List[int] = []
        self.pending_stores: List[Tuple[int, Any]] = []
        self.transient_stores: List[Tuple[int, Any]] = []
        self.observations: List[Dict[str, Any]] = []
        self._btb_readout_max_hit: Optional[int] = None
        self._btb_readout_min_miss: Optional[int] = None
        self._btb_readout_seen = False
        self.in_speculation = False

    @staticmethod
    def _required_address(event: Event) -> int:
        if event.address is None:
            raise ValueError(f"{event.kind} requires an address")
        return event.address

    @staticmethod
    def _required_integer(event: Event, key: str) -> int:
        value = event.details.get(key)
        if not _integer(value) or value < 0:
            raise ValueError(f"{event.kind} requires nonnegative integer {key}")
        return value

    def apply(self, event: Event) -> None:
        kind = event.kind
        if kind == "spec_begin":
            self.in_speculation = True
        elif kind == "spec_end":
            if not event.details["rollback"]:
                self.pending_stores.extend(self.transient_stores)
            self.transient_stores.clear()
            self.in_speculation = False
        elif kind in ("cache_fill", "pending_load_fill"):
            address = self._required_address(event)
            self.cache_lines.add(address & ~(self.line_size - 1))
        elif kind == "memory_read":
            address = self._required_address(event)
            hit = event.details.get("cache_hit")
            if type(hit) is not bool:
                raise ValueError("memory_read requires boolean cache_hit")
            resident = (address & ~(self.line_size - 1)) in self.cache_lines
            if hit != resident:
                raise ValueError("recorded cache hit differs from replay state")
        elif kind in ("cache_flush", "cache_evict"):
            address = self._required_address(event)
            self.cache_lines.discard(address & ~(self.line_size - 1))
        elif kind == "btb_train":
            self.btb[self._required_address(event)] = self._required_integer(event, "target")
        elif kind == "btb_predict":
            address = self._required_address(event)
            self.observations.append({"sequence": event.sequence, "kind": kind,
                                      "target": self.btb.get(address)})
        elif kind == "tlb_fill":
            address = self._required_address(event)
            physical = self._required_integer(event, "physical_page")
            if physical % self.page_size:
                raise ValueError("physical_page must be page aligned")
            self.tlb[address & ~(self.page_size - 1)] = physical
        elif kind == "tlb_probe":
            address = self._required_address(event) & ~(self.page_size - 1)
            self.observations.append({"sequence": event.sequence, "kind": kind,
                                      "hit": address in self.tlb,
                                      "physical_page": self.tlb.get(address)})
        elif kind == "mdp_train":
            address = self._required_address(event)
            wait = event.details.get("wait_for_store")
            if type(wait) is not bool:
                raise ValueError("mdp_train requires boolean wait_for_store")
            self.mdp[address] = wait
        elif kind == "mdp_predict":
            address = self._required_address(event)
            self.observations.append({"sequence": event.sequence, "kind": kind,
                                      "wait_for_store": self.mdp.get(address)})
        elif kind == "store_enqueue":
            entry = (self._required_address(event),
                     self._required_integer(event, "value"))
            (self.transient_stores if self.in_speculation else
             self.pending_stores).append(entry)
        elif kind == "store_drain":
            address = self._required_address(event)
            for index in range(len(self.pending_stores)):
                if self.pending_stores[index][0] == address:
                    del self.pending_stores[index]
                    break
            else:
                if any(addr == address for addr, _ in self.transient_stores):
                    raise ValueError("transient store cannot drain before retirement")
                raise ValueError("store_drain without a pending store")
        elif kind == "load_probe":
            address = self._required_address(event)
            match = next((value for addr, value in reversed(
                          self.pending_stores + self.transient_stores)
                          if addr == address), None)
            self.observations.append({"sequence": event.sequence, "kind": kind,
                                      "forwarded": match is not None, "value": match})
        elif kind == "rsb_push":
            self.rsb.append(self._required_integer(event, "target"))
        elif kind == "rsb_pop":
            predicted = self.rsb[-1] if self.rsb else 0
            if self._required_integer(event, "target") != predicted:
                raise ValueError("recorded RSB prediction differs from replay")
            if self.rsb:
                self.rsb.pop()
            self.observations.append({"sequence": event.sequence, "kind": kind,
                                      "target": predicted})
        elif kind == "readout":
            if event.details.get("substrate") == "tlb_page_walk":
                row = event.details.get("row")
                if row not in ("0,0", "1,0", "0,1", "1,1"):
                    raise ValueError("TLB readout requires a valid input row")
                trial = self._required_integer(event, "trial")
                rail1 = self._required_integer(event, "rail1_latency")
                rail0 = self._required_integer(event, "rail0_latency")
                threshold = self._required_integer(event, "threshold")
                if threshold == 0:
                    raise ValueError("TLB readout threshold must be positive")
                raw1, hit0 = rail1 < threshold, rail0 < threshold
                detected = raw1 == hit0
                success = not detected and raw1 == (row == "1,1")
                for key, expected in (("raw1", raw1), ("detected", detected),
                                      ("success", success)):
                    if event.details.get(key) is not expected:
                        raise ValueError(f"TLB readout {key} differs from latencies")
                self.observations.append({"sequence": event.sequence, "kind": kind,
                                          "row": row, "trial": trial,
                                          "rail1_latency": rail1,
                                          "rail0_latency": rail0,
                                          "threshold": threshold,
                                          "raw1": raw1, "detected": detected,
                                          "success": success})
            elif event.details.get("substrate") == "branch_predictor":
                if event.details.get("scheme") != "amd_btb_one_shot_and":
                    raise ValueError("unsupported BTB readout scheme")
                values = {key: self._required_integer(event, key) for key in (
                    "round", "a", "b", "expected", "real_signal_cycles",
                    "real_signal_hit", "decoded", "correct",
                    "sham_signal_cycles", "sham_signal_hit", "committed_equal",
                    "indirect_misses", "branch_misses", "retired_branches",
                    "sham_indirect_misses", "sham_branch_misses",
                    "sham_retired_branches")}
                if any(values[key] not in (0, 1) for key in (
                        "a", "b", "expected", "real_signal_hit", "decoded",
                        "correct", "sham_signal_hit", "committed_equal")) or (
                        values["expected"] != (values["a"] & values["b"]) or
                        values["real_signal_hit"] != values["decoded"] or
                        values["correct"] != int(values["decoded"] == values["expected"])):
                    raise ValueError("BTB readout truth or status differs")
                max_hit = self._btb_readout_max_hit
                min_miss = self._btb_readout_min_miss
                for cycles, hit in ((values["real_signal_cycles"],
                                     values["real_signal_hit"]),
                                    (values["sham_signal_cycles"],
                                     values["sham_signal_hit"])):
                    if cycles == 0 or cycles > 0xFFFFFFFFFFFFFFFF:
                        raise ValueError("BTB readout cycle count is outside native range")
                    if hit:
                        max_hit = max(cycles, max_hit or 0)
                    else:
                        min_miss = min(cycles, min_miss or cycles)
                if (max_hit is not None and min_miss is not None and
                        max_hit >= min_miss):
                    raise ValueError("BTB readout labels admit no shared threshold")
                self._btb_readout_max_hit = max_hit
                self._btb_readout_min_miss = min_miss
                self._btb_readout_seen = True
                self.observations.append({"sequence": event.sequence, "kind": kind,
                                          "substrate": "branch_predictor",
                                          "scheme": "amd_btb_one_shot_and", **values})
            else:
                self.observations.append({"sequence": event.sequence,
                                          "kind": kind, "details": dict(event.details)})

    @property
    def btb_feasible_threshold_interval(self) -> Optional[List[Optional[int]]]:
        if not self._btb_readout_seen:
            return None
        return [self._btb_readout_max_hit,
                (self._btb_readout_min_miss - 1
                 if self._btb_readout_min_miss is not None else None)]

    def run(self, trace: Trace) -> "Replay":
        # Revalidate externally supplied or mutated traces before changing state.
        validated = Trace(trace.events, trace.line_size, trace.page_size,
                          trace.metadata)
        if (self.line_size, self.page_size) != (validated.line_size, validated.page_size):
            raise ValueError("replay model parameters differ from trace")
        candidate = Replay(self.line_size, self.page_size)
        for event in validated.events:
            candidate.apply(event)
        self.__dict__.update(candidate.__dict__)
        return self
