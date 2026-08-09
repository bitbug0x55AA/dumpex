"""Cross-hunter skipped-target investigation queue for `--hunt all`'s
default (metadata-only) triage pass -- see docs/CHANGELOG.md's "skipped
oversized scan targets" entries and issue #19. Like
`dumpex.hunt.region_correlation`, this reads only already-built
`HunterRecord`s (each hunter's own `coverage.limitations[].targets`, see
`dumpex.output.coverage.ScanTarget`) plus the dump's already-parsed
MemoryInfoListStream -- it never re-scans, never opens the dump's memory
content, and performs no read whose cost scales with a skipped target's
size. `TriageInfo.bytes_examined` is always `0` in this module, the
schema-enforced witness of that invariant (see docs/OUTPUT_SCHEMA.md's
v2.9 entry).

One physical region/segment can be skipped by several different hunters
(e.g. pipe's `pipe_name_scan` and stomping's `ioc_string_scan` both giving
up on the same oversized MEM_PRIVATE region) AND/OR by several scan layers
of the SAME hunter (obfuscation's sleep_mask/entropy/decode layers, each
its own `CoverageLimitation` -- see #16's fix). Neither case exists as a
single actionable item anywhere today: each hunter's own
`dumpex.hunt._coverage.CoverageTracker` is scoped to that one hunter's one
scan call. `build_investigation_queue()` is the one place that dedup
happens, keyed on `(ScanTarget.kind, base_address, size)` -- the physical
identity of the thing that was skipped, independent of who skipped it or
under which cap.

Priority is derived from exactly two independent boolean facts, each
itself derived from data already on the records (never a fresh read):

  has_exec_signal        -- the skipped target's own MemoryInfo facts
                             already look suspicious on their own, with no
                             other hunter's evidence needed: PRIVATE
                             memory that is ALSO executable (ordinary
                             MEM_PRIVATE heap/data with no execute
                             permission does NOT count), or true RWX
                             (PAGE_EXECUTE_READWRITE specifically -- an
                             ordinary read+execute code mapping does NOT
                             count as RWX). See `_is_private_executable()`/
                             `_is_rwx()`.
  has_correlation_signal -- either >1 distinct (hunter, source, scope)
                             skipped the SAME physical target, or this
                             target's region coincides with an existing
                             multi-hunter `RegionCorrelation` (built by
                             `dumpex.hunt.region_correlation`, which
                             itself only reads DETECTED/lead-bearing
                             evidence already on the records).

neither -> low, exactly one -> medium, both -> high (see
`_derive_priority()`). `evidence_availability` is a SEPARATE axis (whether
the dump's bytes are on disk at all, from `ScanTarget.file_offset`) --
never folded into priority: a missing file offset means "may need
recollection," not "more malicious" (explicit issue #19 non-goal).

This module implements the default, always-on metadata pass AND the
closed vocabulary/validation `TriageInfo`/`InvestigationAction` share with
the opt-in `--triage-skipped` budgeted deep-content triage pass (issue
#19's second, independently-scoped piece) -- see `dumpex.hunt._deep_triage`
for the engine that actually performs those budgeted reads and constructs
`TriageInfo(mode="deep", ...)` instances. Nothing in THIS module ever
reads region content or constructs `mode="deep"` itself; it only defines
the shape deep triage must produce and validates it (`TriageInfo.
__post_init__`'s mode=="deep" branch below).
"""
from dataclasses import dataclass, field
from enum import Enum

from dumpex.output.coverage import ScanTarget, ScanTargetKind, LimitationCode
from dumpex.output.records import (
    HUNTERS, HunterRecord,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.hunt.region_correlation import build_region_correlations

__all__ = [
    "InvestigationPriority", "InvestigationReasonCode", "EvidenceAvailability",
    "InvestigationActionType", "TriageMode", "TriageStatus", "ContentReasonCode",
    "ContentFindingType", "ContentFinding", "MAX_FINDINGS_PER_TARGET", "MAX_FINDING_VALUE_LEN",
    "SkipRelationship", "TriageInfo",
    "RecommendedAction", "InvestigationAction", "build_investigation_queue",
]


class InvestigationPriority(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class TriageMode(str, Enum):
    METADATA = "metadata"
    # Reserved for the future opt-in --triage-skipped budgeted
    # deep-content triage phase -- never constructed by this phase, kept
    # here (and in the JSON schema) purely so that phase does not require
    # a schema break to add it.
    DEEP = "deep"


class TriageStatus(str, Enum):
    """Closed vocabulary spanning both this phase's own single reachable
    value (`COMPLETED`, `mode == "metadata"` always uses it) and the
    future deep-content triage phase's outcomes -- see the original
    issue's own "explicit states for completed, partial/clamped,
    unreadable/not captured, and deferred because of budget" requirement.
    Reserved now so v2.9 need not be revisited when that phase lands."""
    COMPLETED       = "completed"
    PARTIAL         = "partial"
    CLAMPED         = "clamped"
    UNREADABLE      = "unreadable"
    NOT_CAPTURED    = "not_captured"
    BUDGET_DEFERRED = "budget_deferred"


class InvestigationReasonCode(str, Enum):
    # has_exec_signal
    PRIVATE_EXECUTABLE_MEMORY = "PRIVATE_EXECUTABLE_MEMORY"
    RWX_PROTECTION            = "RWX_PROTECTION"
    # has_correlation_signal
    MULTIPLE_SCOPES_SKIPPED     = "MULTIPLE_SCOPES_SKIPPED"
    CORRELATED_REGION_EVIDENCE  = "CORRELATED_REGION_EVIDENCE"


class EvidenceAvailability(str, Enum):
    CAPTURED     = "captured"
    NOT_CAPTURED = "not_captured"


class ContentReasonCode(str, Enum):
    """Closed vocabulary for `TriageInfo.content_reason_codes` -- what the
    opt-in deep-content read itself (not metadata) found in a target's
    examined bytes, via `dumpex.hunt._deep_triage`'s reuse of --report's
    own `_scan_content_range()` string/IOC/MZ scan. Only ever populated for
    `mode == "deep"` and a status where a real read actually happened
    (completed/partial/clamped -- see TriageInfo.__post_init__); always
    `()` otherwise. Deliberately its own closed enum, separate from
    `InvestigationReasonCode` (metadata-only signals) -- keeping the two
    apart preserves the metadata pass's own "zero content reads" proof
    (nothing in InvestigationReasonCode could ever require a read) and
    lets a JSON consumer tell "why is this HIGH priority" (metadata,
    always present) apart from "what did the deep read actually find"
    (deep-triage-only, may never have been attempted)."""
    IOC_PATTERN_STRING_MATCH     = "IOC_PATTERN_STRING_MATCH"
    NETWORK_PATTERN_STRING_MATCH = "NETWORK_PATTERN_STRING_MATCH"
    # MZ_HEADER_DETECTED and INJECTED_PE_HEADER are deliberately separate
    # facts, not one collapsed code: an MZ header was found at the read's
    # own start either way, but INJECTED_PE_HEADER additionally requires
    # CONFIRMING the memory is unregistered (module_context ==
    # "unregistered") -- when module classification itself is unavailable
    # (no ModuleListStream), that confirmation cannot be made, and
    # collapsing the two would silently drop the MZ signal entirely (see
    # dumpex.hunt._deep_triage._content_reason_codes()'s own docstring).
    MZ_HEADER_DETECTED = "MZ_HEADER_DETECTED"
    INJECTED_PE_HEADER = "INJECTED_PE_HEADER"


class ContentFindingType(str, Enum):
    IOC_STRING = "ioc_string"
    MZ_HEADER  = "mz_header"


MAX_FINDINGS_PER_TARGET = 20    # same "top 20" bound --report's own notable-
                                  # strings preview already uses (dumpex.
                                  # commands.report._scan_content_range())
MAX_FINDING_VALUE_LEN = 256      # same order of magnitude as ReportIocString.
                                  # context_hex's own <=256-byte/<=512-hex-char
                                  # bound -- a lead, not the full match


@dataclass(frozen=True)
class ContentFinding:
    """One piece of REAL evidence the opt-in `--triage-skipped` deep read
    itself found (issue #19 Phase 2) -- `TriageInfo.content_reason_codes`
    alone only says THAT something was found, never WHAT; this is the
    bounded, structured record of WHAT, so a JSON consumer doesn't have to
    re-run `--report --report-addr <base_address>` just to see it (though
    that remains the way to get the FULL triage card, complete string
    text, and hexdump context -- this array is a bounded lead, not a
    substitute).

    `type` discriminates two closed shapes:

      "ioc_string" -- `offset`/`encoding`/`value`/`is_network_pattern` all
                      set, `module_context` always `None`. `value` is
                      truncated to `MAX_FINDING_VALUE_LEN` characters.
      "mz_header"  -- `module_context` set (whether ownership could be
                      confirmed at all), every ioc_string-only field
                      `None`.

    `dumpex.hunt._deep_triage.run_deep_triage()` is the only real
    constructor, and it also caps the NUMBER of `ContentFinding` entries
    per target at `MAX_FINDINGS_PER_TARGET` before ever constructing one
    -- `TriageInfo.__post_init__` re-enforces that same cap here too, so
    this array can never grow unbounded even against adversarial
    content."""
    type: str
    address: str
    offset: "int | None" = None
    encoding: "str | None" = None
    value: "str | None" = None
    is_network_pattern: "bool | None" = None
    module_context: "str | None" = None

    def __post_init__(self):
        object.__setattr__(self, "type", ContentFindingType(self.type).value)
        _require_str(self.address, "ContentFinding.address")
        if self.type == ContentFindingType.IOC_STRING.value:
            if not isinstance(self.offset, int) or isinstance(self.offset, bool) or self.offset < 0:
                raise ValueError(f"ContentFinding(type='ioc_string').offset must be a "
                                  f"non-negative int, got {self.offset!r}")
            if self.encoding not in ("ASCII", "UTF16"):
                raise ValueError(f"ContentFinding(type='ioc_string').encoding must be "
                                  f"'ASCII' or 'UTF16', got {self.encoding!r}")
            _require_str(self.value, "ContentFinding(type='ioc_string').value")
            if len(self.value) > MAX_FINDING_VALUE_LEN:
                raise ValueError(f"ContentFinding(type='ioc_string').value must be at most "
                                  f"{MAX_FINDING_VALUE_LEN} chars -- truncate before "
                                  f"constructing, got {len(self.value)}")
            if not isinstance(self.is_network_pattern, bool):
                raise ValueError(f"ContentFinding(type='ioc_string').is_network_pattern must "
                                  f"be a bool, got {self.is_network_pattern!r}")
            if self.module_context is not None:
                raise ValueError("ContentFinding(type='ioc_string').module_context must be "
                                  "None -- only type='mz_header' uses it")
        else:   # mz_header
            unused = [v for v in (self.offset, self.encoding, self.value, self.is_network_pattern)
                      if v is not None]
            if unused:
                raise ValueError("ContentFinding(type='mz_header') must have "
                                  "offset/encoding/value/is_network_pattern all None -- only "
                                  "type='ioc_string' uses them")
            if self.module_context not in (MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED,
                                            MODULE_CONTEXT_UNAVAILABLE):
                raise ValueError(f"ContentFinding(type='mz_header').module_context must be one "
                                  f"of {MODULE_CONTEXT_RESOLVED!r}/{MODULE_CONTEXT_UNREGISTERED!r}/"
                                  f"{MODULE_CONTEXT_UNAVAILABLE!r}, got {self.module_context!r}")

    def to_dict(self) -> dict:
        return {
            "type": self.type, "address": self.address, "offset": self.offset,
            "encoding": self.encoding, "value": self.value,
            "is_network_pattern": self.is_network_pattern, "module_context": self.module_context,
        }


class InvestigationActionType(str, Enum):
    INSPECT_METADATA       = "inspect_metadata"
    EXTRACT_CAPTURED_RANGE = "extract_captured_range"
    TARGETED_HUNTER_RESCAN = "targeted_hunter_rescan"
    RECOLLECT_DUMP         = "recollect_dump"
    PRESERVE_ARTIFACT      = "preserve_artifact"
    # Reserved for the future --triage-skipped phase (needs a deep-triage
    # byte limit that does not exist yet) -- never emitted by this module.
    CHUNKED_ANALYSIS        = "chunked_analysis"


# Only a real hunter-specific targeted rescan (not implemented by this
# issue -- see its own "Designing the future targeted-rescan engine in
# full" non-goal) could ever resolve the ORIGINAL hunter's coverage gap;
# this module never emits any other value.
_COVERAGE_EFFECT_GAP_NOT_RESOLVED = "original_hunter_gap_not_resolved"


def _require_str(value, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty str, got {value!r}")
    return value


def _require_optional_str(value, name: str) -> "str | None":
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{name} must be a str or None, got {value!r}")
    return value


def _require_positive_int(value, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive int, got {value!r}")
    return value


@dataclass(frozen=True)
class SkipRelationship:
    """One `(hunter, source, scope)` that skipped a physical target --
    `hunter` is the owning `HunterRecord.hunter` (e.g. "pipe"), `source`/
    `scope` are the owning `CoverageLimitation.source`/`.scope` (e.g.
    "pipe_name_scan"/None, or "encoding_scan"/"entropy"). `size_limit` is
    THIS relationship's own cap -- the same physical target can legally
    have different `size_limit`s under different hunters/scopes (see
    `ScanTarget`'s own docstring)."""
    hunter: str
    source: str
    scope: "str | None" = None
    size_limit: int = 0

    def __post_init__(self):
        if self.hunter not in HUNTERS:
            raise ValueError(f"SkipRelationship.hunter must be one of {HUNTERS}, got {self.hunter!r}")
        _require_str(self.source, "SkipRelationship.source")
        _require_optional_str(self.scope, "SkipRelationship.scope")
        _require_positive_int(self.size_limit, "SkipRelationship.size_limit")

    def to_dict(self) -> dict:
        return {
            "hunter": self.hunter, "source": self.source,
            "scope": self.scope, "size_limit": self.size_limit,
        }


_TRIAGE_ZERO_BYTE_STATUSES = frozenset({
    TriageStatus.NOT_CAPTURED.value, TriageStatus.BUDGET_DEFERRED.value,
    TriageStatus.UNREADABLE.value,
})


@dataclass(frozen=True)
class TriageInfo:
    """The default metadata pass only ever produces `mode="metadata"`,
    pinned to exactly these five values by construction (see
    `__post_init__`) -- `bytes_examined=0`/`region_fully_examined=False`/
    `content_reason_codes=()`/`findings=()` are the schema-enforced proof
    that the default pass reads no region content. `mode="deep"` is
    constructed ONLY by `dumpex.hunt._deep_triage.run_deep_triage()` (the
    opt-in `--triage-skipped` budgeted deep-content triage, issue #19
    Phase 2) -- never by this module. `__post_init__` still enforces
    every mode="deep" invariant here (not in `_deep_triage`) so the two
    producers (the always-on metadata pass and the opt-in deep pass)
    share one place a reader can trust: a zero-byte status
    (not_captured/budget_deferred/unreadable) can never claim bytes were
    examined or that content was found; a real-read status
    (completed/partial/clamped) can never claim zero bytes; and only
    `completed` may claim `region_fully_examined=True`.

    `content_reason_codes` is a quick, closed-vocabulary SUMMARY of what
    a deep read found; `findings` (bounded at `MAX_FINDINGS_PER_TARGET`
    `ContentFinding` entries) is the structured EVIDENCE backing it --
    see `ContentFinding`'s own docstring. Both share the exact same
    "only populated for a real-read status" rule.

    `finding_count` is the TOTAL number of individual findings the deep
    read actually produced (an MZ header counts as at most one; every IOC
    string hit counts as one each) -- BEFORE `dumpex.hunt._deep_triage.
    _content_signals()`'s own representative-first selection caps the
    `findings` array at `MAX_FINDINGS_PER_TARGET`. `findings_truncated` is
    `True` exactly when `finding_count > len(findings)`, i.e. the array
    does not carry every finding the read produced. Both exist so a JSON
    consumer can tell "there were exactly 3 findings, all shown" apart
    from "there were 47 findings, only a bounded representative sample of
    20 is shown" -- `len(findings)` alone cannot distinguish those two
    cases once a target is string-dense enough to hit the cap."""
    mode: str = "metadata"
    status: str = "completed"
    bytes_examined: int = 0
    region_fully_examined: bool = False
    content_reason_codes: tuple = field(default_factory=tuple)
    findings: tuple = field(default_factory=tuple)
    finding_count: int = 0
    findings_truncated: bool = False

    def __post_init__(self):
        object.__setattr__(self, "mode", TriageMode(self.mode).value)
        object.__setattr__(self, "status", TriageStatus(self.status).value)
        if not isinstance(self.bytes_examined, int) or isinstance(self.bytes_examined, bool) \
                or self.bytes_examined < 0:
            raise ValueError(f"TriageInfo.bytes_examined must be a non-negative int, "
                              f"got {self.bytes_examined!r}")
        if not isinstance(self.region_fully_examined, bool):
            raise ValueError(f"TriageInfo.region_fully_examined must be a bool, "
                              f"got {self.region_fully_examined!r}")
        if not isinstance(self.content_reason_codes, tuple):
            object.__setattr__(self, "content_reason_codes", tuple(self.content_reason_codes))
        object.__setattr__(self, "content_reason_codes",
                            tuple(ContentReasonCode(c).value for c in self.content_reason_codes))
        if not isinstance(self.findings, tuple):
            object.__setattr__(self, "findings", tuple(self.findings))
        if any(type(f) is not ContentFinding for f in self.findings):
            raise ValueError("TriageInfo.findings must contain only ContentFinding instances")
        if len(self.findings) > MAX_FINDINGS_PER_TARGET:
            raise ValueError(f"TriageInfo.findings must have at most "
                              f"{MAX_FINDINGS_PER_TARGET} entries, got {len(self.findings)}")
        if not isinstance(self.finding_count, int) or isinstance(self.finding_count, bool) \
                or self.finding_count < 0:
            raise ValueError(f"TriageInfo.finding_count must be a non-negative int, "
                              f"got {self.finding_count!r}")
        if self.finding_count < len(self.findings):
            raise ValueError(
                f"TriageInfo.finding_count ({self.finding_count}) must be >= len(findings) "
                f"({len(self.findings)}) -- findings is a subset of everything found")
        if not isinstance(self.findings_truncated, bool):
            raise ValueError(f"TriageInfo.findings_truncated must be a bool, "
                              f"got {self.findings_truncated!r}")
        expect_truncated = self.finding_count > len(self.findings)
        if self.findings_truncated != expect_truncated:
            raise ValueError(
                f"TriageInfo.findings_truncated must be {expect_truncated!r} -- it must equal "
                f"finding_count > len(findings)")
        if self.mode == TriageMode.METADATA.value:
            if (self.status, self.bytes_examined, self.region_fully_examined,
                    self.content_reason_codes, self.findings, self.finding_count,
                    self.findings_truncated) \
                    != (TriageStatus.COMPLETED.value, 0, False, (), (), 0, False):
                raise ValueError(
                    "TriageInfo(mode='metadata') must have status='completed', "
                    "bytes_examined=0, region_fully_examined=False, "
                    "content_reason_codes=(), findings=(), finding_count=0, "
                    "findings_truncated=False -- the metadata pass never reads region content")
            return
        # mode == "deep" -- dumpex.hunt._deep_triage's own opt-in
        # --triage-skipped budgeted phase (issue #19 Phase 2). See this
        # class's own docstring for why these invariants live here rather
        # than in _deep_triage itself.
        if self.status in _TRIAGE_ZERO_BYTE_STATUSES:
            if (self.bytes_examined, self.region_fully_examined, self.content_reason_codes,
                    self.findings, self.finding_count, self.findings_truncated) \
                    != (0, False, (), (), 0, False):
                raise ValueError(
                    f"TriageInfo(mode='deep', status={self.status!r}) must have "
                    f"bytes_examined=0, region_fully_examined=False, "
                    f"content_reason_codes=(), findings=(), finding_count=0, "
                    f"findings_truncated=False -- no read was attempted, so no content signal "
                    f"is possible")
        else:
            if self.bytes_examined <= 0:
                raise ValueError(
                    f"TriageInfo(mode='deep', status={self.status!r}) requires "
                    f"bytes_examined > 0 -- a completed/partial/clamped read must have "
                    f"examined at least one byte")
            expect_fully_examined = self.status == TriageStatus.COMPLETED.value
            if self.region_fully_examined != expect_fully_examined:
                raise ValueError(
                    f"TriageInfo(mode='deep', status={self.status!r}) requires "
                    f"region_fully_examined={expect_fully_examined!r} -- only a "
                    f"'completed' read may claim the region was fully examined, and a "
                    f"'completed' read must claim it")

    def to_dict(self) -> dict:
        return {
            "mode": self.mode, "status": self.status,
            "bytes_examined": self.bytes_examined,
            "region_fully_examined": self.region_fully_examined,
            "content_reason_codes": list(self.content_reason_codes),
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": self.finding_count,
            "findings_truncated": self.findings_truncated,
        }


@dataclass(frozen=True)
class RecommendedAction:
    type: str
    hunters: tuple = field(default_factory=tuple)

    def __post_init__(self):
        object.__setattr__(self, "type", InvestigationActionType(self.type).value)
        if not isinstance(self.hunters, tuple):
            object.__setattr__(self, "hunters", tuple(self.hunters))
        bad = [h for h in self.hunters if h not in HUNTERS]
        if bad:
            raise ValueError(f"RecommendedAction.hunters must all be in {HUNTERS}, got {bad!r}")
        is_rescan = self.type == InvestigationActionType.TARGETED_HUNTER_RESCAN.value
        if self.hunters and not is_rescan:
            raise ValueError(
                f"RecommendedAction(type={self.type!r}) does not use hunters -- only "
                f"{InvestigationActionType.TARGETED_HUNTER_RESCAN.value!r} does")
        if is_rescan and not self.hunters:
            raise ValueError(
                f"RecommendedAction(type={InvestigationActionType.TARGETED_HUNTER_RESCAN.value!r}) "
                f"requires a non-empty hunters tuple -- a rescan recommendation naming zero "
                f"hunters is meaningless")

    def to_dict(self) -> dict:
        d = {"type": self.type}
        if self.hunters:
            d["hunters"] = list(self.hunters)
        return d


@dataclass(frozen=True)
class InvestigationAction:
    """One deduplicated physical skipped target, with every skip
    relationship that touched it merged in -- see this module's own
    docstring. `target` is a real `ScanTarget` (one representative
    instance out of the group -- see `build_investigation_queue()`)."""
    target: ScanTarget
    skipped_by: tuple
    priority: str
    priority_reason_codes: tuple
    evidence_availability: str
    triage: TriageInfo
    recommended_actions: tuple
    coverage_effect: str = _COVERAGE_EFFECT_GAP_NOT_RESOLVED

    def __post_init__(self):
        if type(self.target) is not ScanTarget:
            raise ValueError("InvestigationAction.target must be a ScanTarget")
        if not isinstance(self.skipped_by, tuple):
            object.__setattr__(self, "skipped_by", tuple(self.skipped_by))
        if any(type(s) is not SkipRelationship for s in self.skipped_by):
            raise ValueError("InvestigationAction.skipped_by must contain only SkipRelationship")
        if not self.skipped_by:
            raise ValueError("InvestigationAction.skipped_by must be non-empty")
        object.__setattr__(self, "priority", InvestigationPriority(self.priority).value)
        if not isinstance(self.priority_reason_codes, tuple):
            object.__setattr__(self, "priority_reason_codes", tuple(self.priority_reason_codes))
        object.__setattr__(self, "priority_reason_codes",
                            tuple(InvestigationReasonCode(c).value for c in self.priority_reason_codes))
        object.__setattr__(self, "evidence_availability",
                            EvidenceAvailability(self.evidence_availability).value)
        if type(self.triage) is not TriageInfo:
            raise ValueError("InvestigationAction.triage must be a TriageInfo")
        if not isinstance(self.recommended_actions, tuple):
            object.__setattr__(self, "recommended_actions", tuple(self.recommended_actions))
        if any(type(a) is not RecommendedAction for a in self.recommended_actions):
            raise ValueError("InvestigationAction.recommended_actions must contain only RecommendedAction")
        if not self.recommended_actions:
            raise ValueError("InvestigationAction.recommended_actions must be non-empty")
        if self.coverage_effect != _COVERAGE_EFFECT_GAP_NOT_RESOLVED:
            raise ValueError(
                f"InvestigationAction.coverage_effect must be "
                f"{_COVERAGE_EFFECT_GAP_NOT_RESOLVED!r} in this phase, got {self.coverage_effect!r}")

    def to_dict(self) -> dict:
        return {
            "target":                 self.target.to_dict(),
            "skipped_by":             [s.to_dict() for s in self.skipped_by],
            "priority":               self.priority,
            "priority_reason_codes":  list(self.priority_reason_codes),
            "evidence_availability":  self.evidence_availability,
            "triage":                 self.triage.to_dict(),
            "recommended_actions":    [a.to_dict() for a in self.recommended_actions],
            "coverage_effect":        self.coverage_effect,
        }


def _has_executable_protection(protection: "str | None") -> bool:
    """Substring, not exact match: `protection` can carry a combined flag
    name (e.g. "PAGE_EXECUTE_READ|PAGE_GUARD"); every executable PAGE_*
    constant contains "EXECUTE" and no non-executable one does -- the same
    idiom `dumpex.hunt.injection.memory_scan._has_executable_protection()`
    already uses, reimplemented here rather than imported across a hunter
    package boundary (this module is cross-hunter orchestration, not
    injection-specific)."""
    return isinstance(protection, str) and "EXECUTE" in protection


def _is_rwx(protection: "str | None") -> bool:
    """True RWX only -- PAGE_EXECUTE_READWRITE specifically, not any
    executable protection. PAGE_EXECUTE_READ (a perfectly ordinary
    read+execute code mapping) is not RWX and must never be labeled as
    such; conflating the two would mislabel routine executable memory as
    the specifically dangerous read+write+execute combination."""
    return protection == "PAGE_EXECUTE_READWRITE"


def _is_private_executable(target: ScanTarget) -> bool:
    """MEM_PRIVATE AND executable -- private memory alone (e.g. ordinary
    PAGE_READWRITE heap) is completely mundane and must never be flagged;
    it is specifically PRIVATE (unbacked by any file/image) memory that is
    ALSO executable that is suspicious (no legitimate loader maps
    unregistered, executable content into private memory)."""
    return target.type == "MEM_PRIVATE" and _has_executable_protection(target.protection)


def _has_exec_signal(target: ScanTarget) -> bool:
    """Private-executable OR true RWX -- two independent facts (see
    `_is_private_executable()`/`_is_rwx()`), never a bare MEM_PRIVATE type
    check or a bare "any executable protection" check on their own. Always
    `False` for a MEMORY_SEGMENT target (no MemoryInfo at all -- `type`/
    `protection` are always `None`), which therefore never contributes
    this signal."""
    return _is_private_executable(target) or _is_rwx(target.protection)


def _derive_priority(has_exec_signal: bool, has_correlation_signal: bool) -> str:
    """Centralized, unit-tested truth table -- mirrors the
    `derive_status`/`derive_coverage_status` style in
    `dumpex.hunt._coverage`. Neither signal -> low; exactly one -> medium;
    both -> high."""
    count = int(has_exec_signal) + int(has_correlation_signal)
    if count >= 2:
        return InvestigationPriority.HIGH.value
    if count == 1:
        return InvestigationPriority.MEDIUM.value
    return InvestigationPriority.LOW.value


def _recommended_actions(priority: str, evidence_availability: str, hunters: tuple) -> tuple:
    """`hunters` must be non-empty -- `build_investigation_queue()` only
    ever calls this with the real set of hunters that skipped the target
    (see `RecommendedAction.__post_init__`, which also enforces this).
    `preserve_artifact` ("preserve/export the artifact before external
    analysis") is only offered when there IS a local artifact to preserve
    -- i.e. the bytes are actually `captured` in this dump; a `high`
    -priority target whose bytes were never captured gets `recollect_dump`
    instead, never a preserve suggestion for bytes that don't exist here."""
    actions = [RecommendedAction(type=InvestigationActionType.INSPECT_METADATA.value)]
    if evidence_availability == EvidenceAvailability.CAPTURED.value:
        actions.append(RecommendedAction(type=InvestigationActionType.EXTRACT_CAPTURED_RANGE.value))
    else:
        actions.append(RecommendedAction(type=InvestigationActionType.RECOLLECT_DUMP.value))
    actions.append(RecommendedAction(
        type=InvestigationActionType.TARGETED_HUNTER_RESCAN.value, hunters=hunters))
    if priority == InvestigationPriority.HIGH.value and evidence_availability == EvidenceAvailability.CAPTURED.value:
        actions.append(RecommendedAction(type=InvestigationActionType.PRESERVE_ARTIFACT.value))
    return tuple(actions)


def _dedup_key(target: ScanTarget):
    return (target.kind, target.base_address, target.size)


def _sort_key(action: InvestigationAction):
    priority_rank = {"high": 0, "medium": 1, "low": 2}[action.priority]
    return (priority_rank, -len(action.skipped_by), action.target.base_address)


def build_investigation_queue(records: list, memory_regions: list) -> list:
    """The deduplicated, priority-ordered skipped-target investigation
    queue for `--hunt all` -- see this module's own docstring. `records`
    must be a `list[HunterRecord]` (any subset/order accepted, same
    tolerance `build_region_correlations()` itself has); `memory_regions`
    is `dumpex.core.memory.get_memory_regions(mf)`'s own return value,
    read only to resolve `CORRELATED_REGION_EVIDENCE` -- never re-scanned.
    Returns `[]` when no hunter skipped anything for being oversized."""
    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("build_investigation_queue() records must be a list of HunterRecord")

    groups: dict = {}   # dedup_key -> {"target": ScanTarget, "skips": {(hunter,source,scope): SkipRelationship}}
    for record in records:
        for limitation in record.coverage.limitations:
            if limitation.code != LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED:
                continue
            for target in limitation.targets:
                key = _dedup_key(target)
                entry = groups.setdefault(key, {"target": target, "skips": {}})
                skip_key = (record.hunter, limitation.source, limitation.scope)
                entry["skips"].setdefault(skip_key, SkipRelationship(
                    hunter=record.hunter, source=limitation.source,
                    scope=limitation.scope, size_limit=target.size_limit))

    if not groups:
        return []

    correlated_region_keys = {
        (corr.region_base, corr.region_size)
        for corr in build_region_correlations(records, memory_regions)
    }

    actions = []
    for entry in groups.values():
        target = entry["target"]
        skipped_by = tuple(sorted(
            entry["skips"].values(),
            key=lambda s: (HUNTERS.index(s.hunter), s.source, s.scope or "")))

        reason_codes = []
        has_exec = _has_exec_signal(target)
        # Independent facts, not mutually exclusive -- a target can be
        # BOTH private AND true RWX at once, and each is its own reason
        # code rather than the first one found suppressing the other.
        if _is_private_executable(target):
            reason_codes.append(InvestigationReasonCode.PRIVATE_EXECUTABLE_MEMORY.value)
        if _is_rwx(target.protection):
            reason_codes.append(InvestigationReasonCode.RWX_PROTECTION.value)

        has_correlation = False
        if len(skipped_by) > 1:
            reason_codes.append(InvestigationReasonCode.MULTIPLE_SCOPES_SKIPPED.value)
            has_correlation = True
        if (target.kind == ScanTargetKind.MEMORY_REGION
                and (target.base_address, target.size) in correlated_region_keys):
            reason_codes.append(InvestigationReasonCode.CORRELATED_REGION_EVIDENCE.value)
            has_correlation = True

        priority = _derive_priority(has_exec, has_correlation)
        evidence_availability = (EvidenceAvailability.CAPTURED.value
                                  if target.file_offset is not None
                                  else EvidenceAvailability.NOT_CAPTURED.value)
        hunters = tuple(h for h in HUNTERS if any(s.hunter == h for s in skipped_by))

        actions.append(InvestigationAction(
            target=target,
            skipped_by=skipped_by,
            priority=priority,
            priority_reason_codes=tuple(reason_codes),
            evidence_availability=evidence_availability,
            triage=TriageInfo(),
            recommended_actions=_recommended_actions(priority, evidence_availability, hunters),
        ))

    actions.sort(key=_sort_key)
    return actions
