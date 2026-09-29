"""PeObservationRecord: the one wire shape a PE correlation observation
has, projected by both `--report`'s `pe_context` and `--process`'s
`pe_image`.
"""
from dataclasses import dataclass, field

from dumpex.output.records.common import ENRICHMENT_TEXT_CAP, _require_bounded_text


PE_OBSERVATION_STATES = ("consistent", "conflict", "unavailable", "not_applicable")


@dataclass(frozen=True)
class PeObservationRecord:
    """One :class:`dumpex.core.pe_correlation.Observation` reduced to a
    wire record.

    ``name`` is one of the correlation layer's frozen observation names,
    ``state`` its result, ``reason`` the dumpex-authored token behind it.
    ``sources`` names the evidence actually evaluated and ``operands`` the
    exact scalar values compared. A ``conflict`` here is a disagreement
    between two captured facts, never a maliciousness finding.

    The two states that withhold an answer stay apart: ``unavailable`` is
    evidence the dump does not carry, ``not_applicable`` a comparison an
    established fact leaves no subject for. A consumer counting the
    evidence gap counts the first alone.

    This is the one wire shape a correlation observation has. `--report`'s
    `pe_context` retains the conflicts of the main-image correlation and
    `--process`'s `pe_image` carries every observation it produced; both
    project this record, so the same observation reads identically on
    either surface."""
    name:     str
    state:    str
    reason:   str
    sources:  tuple = ()
    operands: dict = field(default_factory=dict)

    def __post_init__(self):
        _require_bounded_text(self.name, "PeObservationRecord.name", ENRICHMENT_TEXT_CAP)
        if self.state not in PE_OBSERVATION_STATES:
            raise ValueError(
                f"PeObservationRecord.state must be one of {PE_OBSERVATION_STATES}, "
                f"got {self.state!r}")
        _require_bounded_text(self.reason, "PeObservationRecord.reason", ENRICHMENT_TEXT_CAP)
        object.__setattr__(self, "sources", tuple(self.sources))
        if any(not isinstance(s, str) or not s for s in self.sources):
            raise ValueError("PeObservationRecord.sources must be non-empty strings")
        if not isinstance(self.operands, dict):
            raise TypeError("PeObservationRecord.operands must be a dict")
        for key, value in self.operands.items():
            if not isinstance(key, str):
                raise ValueError("PeObservationRecord.operands keys must be str")
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError(
                    f"PeObservationRecord.operands[{key!r}] must be a JSON scalar, "
                    f"got {value!r}")
        object.__setattr__(self, "operands", dict(self.operands))

    def to_dict(self) -> dict:
        return {"name": self.name, "state": self.state, "reason": self.reason,
                "sources": list(self.sources), "operands": dict(self.operands)}
