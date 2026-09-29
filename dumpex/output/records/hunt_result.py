"""HunterRecord: one hunter's result, composed from its judgment fields,
coverage, findings and hunter-specific details.

One HunterRecord per hunter -- `--hunt all` produces exactly 7, in a
fixed order; a single `--hunt <ttp>` produces exactly 1. See
docs/developer/hunt_architecture.md for the typed projection boundary
this module implements. `hunter`/`status`/`score`/`max_score`/
`verdict_level`/`confidence`/`lead_count`/`review_priority` are the 7
common judgment fields (8 minus coverage_status, which is NOT a judgment
field -- see that doc's legend); `coverage` is a real CoverageReport
object (dumpex.output.coverage), never a bare status string alongside
it, so there is exactly one place this fact lives; `findings` is the
existing dumpex.hunt._finding.Finding.to_dict() shape, unchanged;
`details` is one of the 7 *Details types (dumpex.output.records.
hunt_details), discriminated by `hunter`.

All seven detail types are produced by the hunt collection path.
"""
from dataclasses import dataclass

from dumpex.output.coverage import CoverageReport
from dumpex.output.records.common import _require_nonneg_int
from dumpex.output.records.hunt_details import (
    CsBeaconDetails,
    HollowingDetails,
    InjectionDetails,
    ObfuscationDetails,
    PipeDetails,
    StompingDetails,
    YaraDetails,
)
from dumpex.output.records.hunt_identity import (
    HUNTERS,
    _HUNT_CONFIDENCES,
    _HUNT_REVIEW_PRIORITIES,
    _HUNT_STATUSES,
    _HUNT_VERDICT_LEVELS,
)


_HUNTER_DETAILS_TYPES = {
    "injection":  InjectionDetails,
    "hollowing":  HollowingDetails,
    "stomping":   StompingDetails,
    "pipe":       PipeDetails,
    "cs-beacon":  CsBeaconDetails,
    "yara":       YaraDetails,
    "obfuscation": ObfuscationDetails,
}


@dataclass
class HunterRecord:
    """One hunter result in ``result.data.records``.

    ``hunter`` discriminates the seven detail types. YARA has no shared
    max-score, confidence, lead-count, or review-priority semantics, so all
    four fields are ``None`` together. Coverage is a ``CoverageReport``,
    not a second bare status/reasons representation.
    """
    hunter:          str
    status:          str
    score:           int
    max_score:       "int | None"
    verdict_level:   str
    confidence:      "str | None"
    lead_count:      "int | None"
    review_priority: "str | None"
    coverage:        CoverageReport
    findings:        list   # list[dict] -- Finding.to_dict() shape, unchanged; [] for yara
    details:         object  # one of the 7 *Details types, matching `hunter`

    def __post_init__(self):
        if self.hunter not in HUNTERS:
            raise ValueError(f"HunterRecord.hunter must be one of {HUNTERS}, got {self.hunter!r}")
        if self.status not in _HUNT_STATUSES:
            raise ValueError(
                f"HunterRecord.status must be one of {_HUNT_STATUSES}, got {self.status!r}")
        _require_nonneg_int(self.score, "HunterRecord.score")
        if self.verdict_level not in _HUNT_VERDICT_LEVELS:
            raise ValueError(
                f"HunterRecord.verdict_level must be one of {_HUNT_VERDICT_LEVELS}, "
                f"got {self.verdict_level!r}")

        yara_only_fields = {
            "max_score": self.max_score, "confidence": self.confidence,
            "lead_count": self.lead_count, "review_priority": self.review_priority,
        }
        if self.hunter == "yara":
            set_fields = [name for name, v in yara_only_fields.items() if v is not None]
            if set_fields:
                raise ValueError(
                    f"HunterRecord.{set_fields[0]} must be None for hunter='yara' "
                    f"(max_score/confidence/lead_count/review_priority are all-or-nothing null)")
        else:
            unset_fields = [name for name, v in yara_only_fields.items() if v is None]
            if unset_fields:
                raise ValueError(
                    f"HunterRecord.{unset_fields[0]} must not be None for hunter={self.hunter!r} "
                    f"(only 'yara' allows these fields to be null)")
            _require_nonneg_int(self.max_score, "HunterRecord.max_score")
            if self.confidence not in _HUNT_CONFIDENCES:
                raise ValueError(
                    f"HunterRecord.confidence must be one of {_HUNT_CONFIDENCES}, "
                    f"got {self.confidence!r}")
            _require_nonneg_int(self.lead_count, "HunterRecord.lead_count")
            if self.review_priority not in _HUNT_REVIEW_PRIORITIES:
                raise ValueError(
                    f"HunterRecord.review_priority must be one of {_HUNT_REVIEW_PRIORITIES}, "
                    f"got {self.review_priority!r}")

        if not isinstance(self.coverage, CoverageReport):
            raise TypeError("HunterRecord.coverage must be a dumpex.output.coverage.CoverageReport")
        if not isinstance(self.findings, list) or any(not isinstance(f, dict) for f in self.findings):
            raise TypeError("HunterRecord.findings must be a list of dict")
        if self.hunter == "yara" and self.findings:
            raise ValueError(
                "HunterRecord.findings must be [] for hunter='yara' -- yara deliberately stays "
                "off the shared Finding model (see the field matrix's legend)")

        expected_details_type = _HUNTER_DETAILS_TYPES[self.hunter]
        if not isinstance(self.details, expected_details_type):
            raise TypeError(
                f"HunterRecord.details must be a {expected_details_type.__name__} for "
                f"hunter={self.hunter!r}, got {type(self.details).__name__}")

    def to_dict(self) -> dict:
        return {
            "hunter":          self.hunter,
            "status":          self.status,
            "score":           self.score,
            "max_score":       self.max_score,
            "verdict_level":   self.verdict_level,
            "confidence":      self.confidence,
            "lead_count":      self.lead_count,
            "review_priority": self.review_priority,
            "coverage": {
                "status":      self.coverage.status.value,
                "reasons":     self.coverage.reasons,
                "sources":     {name: obs.to_dict() for name, obs in self.coverage.sources.items()},
                "limitations": [lim.to_dict() for lim in self.coverage.limitations],
                # How much captured memory this hunter's gaps add up to:
                # the very ranges `limitations`' own targets name, unioned,
                # so the aggregate and the per-target `unexamined_size`
                # values beside it are one set of numbers rather than two,
                # and memory two gaps both name is counted once.
                "missed_bytes": self.coverage.missed_bytes.to_dict(),
            },
            "findings": list(self.findings),
            "details":  self.details.to_dict(),
        }
