"""Build a metadata-only queue for scan targets skipped by hunters.

Actions are deduplicated by physical base address and size across hunters,
sources, scopes, and region or segment target kinds. Priority combines
execution-like memory facts with cross-hunter correlation; evidence availability
is separate and never treated as suspiciousness.

This pass reads existing records and MemoryInfo metadata only. It performs no
content reads, so bytes_examined is zero.
"""
from dataclasses import dataclass, field
from enum import Enum

from dumpex.core.memory import prot_str
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
    "SkipCause", "SkipRelationship", "TriageInfo",
    "RecommendedAction", "InvestigationAction", "build_investigation_queue",
]


class SkipCause(str, Enum):
    """Why a `(hunter, source, scope)` skipped this target -- issue #28:
    `hunter`/`source`/`scope` alone cannot distinguish an oversized region
    a scan never attempted from one it attempted and failed to read, read
    short, or ran out of scan budget on -- the SAME (hunter, source,
    scope) can legitimately produce more than one of these for different
    targets (e.g. pipe's own pipe_name_scan both skips one oversized
    region AND fails to read a different, ordinarily-sized one), so the
    cause is part of a SkipRelationship's own identity, not a detail of
    the target it names."""
    OVERSIZED_SKIPPED = "oversized_skipped"
    READ_FAILED       = "read_failed"
    SHORT_READ        = "short_read"
    SCAN_TRUNCATED    = "scan_truncated"
    SCAN_NOT_STARTED  = "scan_not_started"
    MATCH_FAILED      = "match_failed"
    MATCH_TIMED_OUT   = "match_timed_out"
    HIT_CAP_REACHED       = "hit_cap_reached"
    SCAN_BUDGET_EXHAUSTED = "scan_budget_exhausted"


# Every LimitationCode build_investigation_queue() draws targets from, and
# the SkipCause each one means -- the single place this mapping lives, so
# widening the queue to a new target-bearing code (see this code's own
# _CODE_SPECS entry in dumpex.output.coverage) means adding one entry here,
# not touching the queue-building logic itself.
_TARGET_BEARING_LIMITATION_CAUSES = {
    LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED: SkipCause.OVERSIZED_SKIPPED,
    LimitationCode.SCAN_REGION_READ_FAILED:       SkipCause.READ_FAILED,
    LimitationCode.SCAN_REGION_SHORT_READ:        SkipCause.SHORT_READ,
    LimitationCode.PE_HEADER_READ_FAILED:         SkipCause.READ_FAILED,
    LimitationCode.PE_HEADER_SHORT_READ:          SkipCause.SHORT_READ,
    LimitationCode.PE_HEADER_SCAN_TRUNCATED:      SkipCause.SCAN_TRUNCATED,
    LimitationCode.PE_HEADER_SCAN_NOT_STARTED:    SkipCause.SCAN_NOT_STARTED,
    LimitationCode.YARA_MATCH_FAILED:             SkipCause.MATCH_FAILED,
    LimitationCode.YARA_MATCH_TIMED_OUT:          SkipCause.MATCH_TIMED_OUT,
    LimitationCode.YARA_HIT_CAP_REACHED:          SkipCause.HIT_CAP_REACHED,
    LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED:    SkipCause.SCAN_BUDGET_EXHAUSTED,
    LimitationCode.CS_BEACON_SCAN_BUDGET_EXHAUSTED: SkipCause.SCAN_BUDGET_EXHAUSTED,
    # The generic code: pipe's pipe_name/c2_context region walk names the
    # eligible regions a spent budget left unresolved. Other producers of
    # this code (encoding's sleep-mask scan) stay reason-only -- a
    # limitation with no `targets` contributes nothing to the queue.
    LimitationCode.SCAN_BUDGET_EXHAUSTED:         SkipCause.SCAN_BUDGET_EXHAUSTED,
}


# Every resource-budget name ANY hunter's own scan-budget-exhaustion code
# can put in `scope` (issue #28 P5/P6 follow-up) -- duplicated here, not
# imported, since this module sits alongside dumpex.output.coverage on
# the domain-model/cross-hunter side, never importing hunt-package
# internals (same "closed vocabulary duplicated at a module boundary"
# precedent that module's own per-hunter *_BUDGET_KINDS copies already
# document). Only used to validate `SkipRelationship.budget_kind` below
# -- `_budget_fields_from_limitation()` doesn't need to distinguish WHICH
# hunter a kind belongs to, only that the owning `CoverageLimitation`
# actually carries one.
_BUDGET_KINDS = frozenset({
    # injection (dumpex.hunt.injection.memory_scan._ScanBudget)
    "reads_per_region", "total_bytes", "validations_per_region", "validations_total",
    # yara_hunt.scanner
    "max_total_hits", "scan_deadline_seconds", "max_total_bytes_scanned",
    # cs_beacon.scanner (scan_deadline_seconds shared with yara_hunt -- the
    # same underlying fact for both)
    "max_total_scanned_bytes", "max_candidates", "max_decoded_bytes", "max_hits",
})


def _budget_fields_from_limitation(limitation) -> tuple:
    """(budget_kind, budget_limit, budget_consumed) read straight off a
    `CoverageLimitation`'s own `scope`/`budget_limit`/`budget_consumed`
    (issue #28 P6 follow-up -- a prior version of this function PARSED
    them out of `detail` text instead, which broke the moment a code that
    also uses `detail` for its own free-text reason -- e.g. CS_BEACON_
    SCAN_BUDGET_EXHAUSTED's human-readable budget_reason -- needed both
    at once; see `dumpex.output.coverage.CoverageLimitation.budget_limit`'s
    own docstring). `(None, None, None)` unless the limitation actually
    carries a budget attribution at all -- every OTHER code's `scope`
    (e.g. obfuscation's own layer-name `scope`) never has `budget_limit`
    set alongside it, so this falls through safely."""
    if limitation.budget_limit is None:
        return None, None, None
    return limitation.scope, limitation.budget_limit, limitation.budget_consumed


class InvestigationPriority(str, Enum):
    LOW    = "low"
    MEDIUM = "medium"
    HIGH   = "high"


class TriageMode(str, Enum):
    METADATA = "metadata"
    # Retained for historical document compatibility.
    DEEP = "deep"


class TriageStatus(str, Enum):
    """Closed status vocabulary shared by metadata and deep triage.

    Metadata triage is always completed. Deep triage distinguishes complete,
    partial, clamped, unreadable, uncaptured, and budget-deferred targets.
    """
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
    PARTIAL      = "partial"
    NOT_CAPTURED = "not_captured"


class ContentReasonCode(str, Enum):
    """Historical vocabulary for deep-mode content signals.

    Only valid for `mode == "deep"` and a status where a real read happened
    (completed/partial/clamped -- see TriageInfo.__post_init__); always `()`
    otherwise. Deliberately its own closed enum, separate from
    `InvestigationReasonCode` (metadata-only signals) -- keeping the two
    apart preserves the metadata pass's own "zero content reads" proof
    (nothing in InvestigationReasonCode could ever require a read) and
    lets a JSON consumer tell "why is this HIGH priority" (metadata,
    always present) apart from "what did the deep read actually find"
    (historical deep-triage data, absent from current producer output)."""
    IOC_PATTERN_STRING_MATCH     = "IOC_PATTERN_STRING_MATCH"
    NETWORK_PATTERN_STRING_MATCH = "NETWORK_PATTERN_STRING_MATCH"
    # MZ_HEADER_DETECTED and INJECTED_PE_HEADER are deliberately separate
    # facts, not one collapsed code: an MZ header was found at the read's
    # own start either way, but INJECTED_PE_HEADER additionally requires
    # CONFIRMING the memory is unregistered (module_context ==
    # "unregistered") -- when module classification itself is unavailable
    # (no ModuleListStream), that confirmation cannot be made, and
    # collapsing the two would silently drop the MZ signal entirely.
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
    """One piece of evidence retained in historical deep-mode output.

    `TriageInfo.content_reason_codes`
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

    `TriageInfo.__post_init__` caps the number of entries at
    `MAX_FINDINGS_PER_TARGET`, preserving the historical structured shape."""
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
    # Emitted by deep triage when a target was not fully examined.
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


def _require_nonnegative_int(value, name: str) -> int:
    # Distinct from _require_positive_int above: a configured scan budget
    # (issue #28 P6 follow-up) can legitimately be `0` -- e.g.
    # PE_SCAN_MAX_VALIDATIONS_TOTAL=0, meaning "no validations at all" --
    # unlike size_limit (an oversized-skip target's cap, which can never
    # legally be 0: a target that "exceeds" a 0 cap while itself having a
    # positive size is not a meaningful oversized-skip scenario in
    # practice, and every real producer's own configured caps are
    # positive). budget_limit/budget_consumed are the two fields that
    # actually need this relaxed floor.
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_optional_positive_int(value, name: str) -> "int | None":
    if value is not None:
        _require_positive_int(value, name)
    return value


@dataclass(frozen=True)
class SkipRelationship:
    """One `(hunter, source, scope, cause)` that skipped a physical target
    -- `hunter` is the owning `HunterRecord.hunter` (e.g. "pipe"),
    `source`/`scope` are the owning `CoverageLimitation.source`/`.scope`
    (e.g. "pipe_name_scan"/None, or "encoding_scan"/"entropy"). `cause`
    (issue #28) is WHY this relationship skipped the target -- see
    `SkipCause`'s own docstring for why `hunter`/`source`/`scope` alone
    cannot distinguish an oversized-skip from a read-failed/short-read/
    scan-truncated gap from the same scan source. `size_limit` is THIS
    relationship's own cap, set only when `cause` is
    `oversized_skipped` -- the same physical target can legally have
    different `size_limit`s under different hunters/scopes (see
    `ScanTarget`'s own docstring); every other cause leaves it `None`,
    since there is no cap being exceeded for an I/O failure or a scan-
    budget exhaustion.

    `budget_kind`/`budget_limit`/`budget_consumed` (issue #28 P5
    follow-up) are the STRUCTURED counterpart of what previously only
    reached `scope` (the kind) and the owning `CoverageLimitation.detail`
    free text (limit/consumed) for `scan_truncated`/`scan_not_started` --
    parsed once here, at construction, from the owning limitation's own
    `scope`/`detail` (see `_budget_fields_from_limitation()`), so a JSON
    consumer reading `investigation_actions[].skipped_by[]` never has to
    parse `detail`'s free text itself just to learn a numeric limit. All
    three stay `None` together for every OTHER cause -- there is no
    budget being tracked for an oversized-skip, a plain read failure, or
    a YARA match failure/timeout."""
    hunter: str
    source: str
    cause: str = SkipCause.OVERSIZED_SKIPPED.value
    scope: "str | None" = None
    size_limit: "int | None" = None
    budget_kind: "str | None" = None
    budget_limit: "int | None" = None
    budget_consumed: "int | None" = None

    def __post_init__(self):
        if self.hunter not in HUNTERS:
            raise ValueError(f"SkipRelationship.hunter must be one of {HUNTERS}, got {self.hunter!r}")
        _require_str(self.source, "SkipRelationship.source")
        object.__setattr__(self, "cause", SkipCause(self.cause).value)
        _require_optional_str(self.scope, "SkipRelationship.scope")
        _require_optional_positive_int(self.size_limit, "SkipRelationship.size_limit")
        if self.cause == SkipCause.OVERSIZED_SKIPPED.value and self.size_limit is None:
            raise ValueError(
                "SkipRelationship(cause='oversized_skipped') requires size_limit -- an "
                "oversized-skip relationship always has the cap it exceeded")
        if self.cause != SkipCause.OVERSIZED_SKIPPED.value and self.size_limit is not None:
            raise ValueError(
                f"SkipRelationship(cause={self.cause!r}) must leave size_limit unset -- only "
                f"an oversized-skip relationship has a cap it exceeded, got "
                f"size_limit={self.size_limit!r}")
        budget_values = (self.budget_kind, self.budget_limit, self.budget_consumed)
        if any(v is None for v in budget_values) and any(v is not None for v in budget_values):
            raise ValueError(
                f"SkipRelationship.budget_kind/budget_limit/budget_consumed must be all None "
                f"or all set together, got {budget_values!r}")
        if self.budget_kind is not None:
            if self.budget_kind not in _BUDGET_KINDS:
                raise ValueError(f"SkipRelationship.budget_kind must be one of "
                                  f"{sorted(_BUDGET_KINDS)}, got {self.budget_kind!r}")
            _require_nonnegative_int(self.budget_limit, "SkipRelationship.budget_limit")
            _require_nonnegative_int(self.budget_consumed, "SkipRelationship.budget_consumed")
            # issue #28 review follow-up: budget_consumed is the REAL
            # measured consumption, not assumed equal to budget_limit --
            # see CoverageLimitation.budget_consumed's own docstring for
            # why it can land on either side of the limit.
            # issue #28 P6 follow-up: originally injection-only
            # (scan_truncated/scan_not_started); now also YARA's own
            # hit_cap_reached/scan_budget_exhausted and CS Beacon's own
            # scan_budget_exhausted.
            if self.cause not in (SkipCause.SCAN_TRUNCATED.value, SkipCause.SCAN_NOT_STARTED.value,
                                    SkipCause.HIT_CAP_REACHED.value, SkipCause.SCAN_BUDGET_EXHAUSTED.value):
                raise ValueError(
                    f"SkipRelationship(cause={self.cause!r}) must leave budget_kind/_limit/"
                    f"_consumed unset -- this cause never tracks a scan budget")

    def to_dict(self) -> dict:
        return {
            "hunter": self.hunter, "source": self.source, "cause": self.cause,
            "scope": self.scope, "size_limit": self.size_limit,
            "budget_kind": self.budget_kind, "budget_limit": self.budget_limit,
            "budget_consumed": self.budget_consumed,
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
    that the default pass reads no region content. `mode="deep"` remains
    accepted for historical document compatibility, although the current
    producer does not emit it. `__post_init__` still enforces every historical
    deep-mode invariant: a zero-byte status
    (not_captured/budget_deferred/unreadable) can never claim bytes were
    examined or that content was found; a real-read status
    (completed/partial/clamped) can never claim zero bytes; and only
    `completed` may claim `region_fully_examined=True`.

    `content_reason_codes` is a quick, closed-vocabulary SUMMARY of what
    a deep read found; `findings` (bounded at `MAX_FINDINGS_PER_TARGET`
    `ContentFinding` entries) is the structured EVIDENCE backing it --
    see `ContentFinding`'s own docstring. Both share the exact same
    "only populated for a real-read status" rule.

    `finding_count` is the TOTAL number of individual findings represented by
    a historical deep-mode record. `findings_truncated` is
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
        # Historical deep-mode compatibility invariants.
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

    `evidence_availability == "partial"` (issue #28 P1 follow-up) gets
    BOTH `extract_captured_range` and `recollect_dump` -- the classic
    short-read shape: a real prefix IS sitting in the dump already in
    hand (worth extracting now) AND the rest of the target genuinely
    isn't there (recollection is still the only way to see the whole
    thing), so recommending only one of the two would silently drop a
    real, actionable option. `preserve_artifact` ("preserve/export the
    artifact before external analysis") is only offered when there IS a
    local artifact to preserve at all -- captured or partial -- never for
    a target whose bytes are entirely absent from this dump."""
    actions = [RecommendedAction(type=InvestigationActionType.INSPECT_METADATA.value)]
    has_captured_bytes = evidence_availability in (
        EvidenceAvailability.CAPTURED.value, EvidenceAvailability.PARTIAL.value)
    if has_captured_bytes:
        actions.append(RecommendedAction(type=InvestigationActionType.EXTRACT_CAPTURED_RANGE.value))
    if evidence_availability != EvidenceAvailability.CAPTURED.value:
        actions.append(RecommendedAction(type=InvestigationActionType.RECOLLECT_DUMP.value))
    actions.append(RecommendedAction(
        type=InvestigationActionType.TARGETED_HUNTER_RESCAN.value, hunters=hunters))
    if priority == InvestigationPriority.HIGH.value and has_captured_bytes:
        actions.append(RecommendedAction(type=InvestigationActionType.PRESERVE_ARTIFACT.value))
    return tuple(actions)


def _evidence_availability_for(target: ScanTarget) -> str:
    """Three-way evidence-availability fact (issue #28 P1 follow-up),
    preferring `target.capture_state` -- the STRUCTURAL "how much of this
    target's own size is actually in the .dmp file" answer (see
    `dumpex.core.memory.va_range_captured_bytes`) -- over the older,
    coarser "does the start address resolve to a file offset at all"
    check. `capture_state` is `None` only for a target that never went
    through `region_scan_target()`/`segment_scan_target()` (every real
    producer does); that legacy fallback is kept so a hand-built
    `ScanTarget` (e.g. in a test) still gets a sensible answer rather than
    raising."""
    state = target.capture_state
    if state == "complete":
        return EvidenceAvailability.CAPTURED.value
    if state == "partial":
        return EvidenceAvailability.PARTIAL.value
    if state == "none":
        return EvidenceAvailability.NOT_CAPTURED.value
    return (EvidenceAvailability.CAPTURED.value if target.file_offset is not None
            else EvidenceAvailability.NOT_CAPTURED.value)


def _dedup_key(target: ScanTarget):
    """The PHYSICAL identity of a skipped/gap target (issue #28 P4
    follow-up) -- deliberately `(base_address, size)` ONLY. `kind` is
    NOT part of a target's physical identity: the same VA range can
    surface as a `memory_region` target (MemoryInfo-sourced, e.g. from
    pipe/injection/encoding/stomping) under one hunter and as a
    `memory_segment` target (Memory64List/MemoryList-sourced, e.g. from
    CS Beacon/YARA) under another. Keying on `kind` too used to produce
    TWO separate investigation actions for what is really one physical
    range -- each seeing only its own hunter's relationship, so neither
    ever crossed the `>1 distinct scope` threshold `MULTIPLE_SCOPES_
    SKIPPED`/priority escalation depends on. See `_merge_target_group()`
    for how a group's one representative target is built once `kind` no
    longer splits it."""
    return (target.base_address, target.size)


def _find_matching_memory_info(base_address: int, size: int, memory_regions: list):
    """The raw MemoryInfo region (from `get_memory_regions(mf)`) whose
    own `[BaseAddress, BaseAddress+RegionSize)` contains
    `[base_address, base_address+size)` -- an exact-bounds match is the
    common case (a segment built from the same allocation a MemoryInfo
    region already describes), a strictly-containing match is kept too
    since Memory64List/MemoryList segment boundaries need not line up
    exactly with MemoryInfo region boundaries. `None` when nothing in
    this dump's own MemoryInfoListStream covers the range at all."""
    end = base_address + size
    for r in memory_regions:
        if r.BaseAddress <= base_address and end <= r.BaseAddress + r.RegionSize:
            return r
    return None


def _merge_target_group(targets: list, memory_regions: list) -> ScanTarget:
    """One representative `ScanTarget` for a dedup group that may mix
    `memory_region` and `memory_segment` kinds describing the SAME
    physical `(base_address, size)` range (issue #28 P4 follow-up) --
    see `_dedup_key()`'s own docstring for why `kind` is no longer part
    of a group's identity.

    A `memory_region` target already carries this dump's own MemoryInfo
    facts (allocation_base/state/type/protection) -- used directly, and
    in insertion order when more than one is present (matches the
    single-kind behavior this function replaces). A group with ONLY
    `memory_segment` targets carries none of that: `memory_regions`
    (already read by `build_investigation_queue()` to resolve
    `CORRELATED_REGION_EVIDENCE`) is searched for a MemoryInfo region
    covering the same range, and if one exists, a NEW `memory_region`
    target is built from it -- this dump's own type/protection facts,
    plus the SEGMENT's own file_offset/captured_size (a segment is
    definitionally backed by the file, so its own capture facts are at
    least as trustworthy as anything freshly re-derived from MemoryInfo
    could be). Falls back to the bare segment target, unchanged, when no
    matching MemoryInfo region exists -- exactly today's behavior for a
    segment-only group."""
    region_targets = [t for t in targets if t.kind == ScanTargetKind.MEMORY_REGION]
    if region_targets:
        return region_targets[0]
    segment_target = targets[0]
    info = _find_matching_memory_info(segment_target.base_address, segment_target.size, memory_regions)
    if info is None:
        return segment_target
    return ScanTarget(
        kind=ScanTargetKind.MEMORY_REGION,
        base_address=segment_target.base_address,
        size=segment_target.size,
        size_limit=segment_target.size_limit,
        file_offset=segment_target.file_offset,
        allocation_base=getattr(info, "AllocationBase", None),
        state=prot_str(info.State),
        type=prot_str(info.Type),
        protection=prot_str(info.Protect),
        captured_size=segment_target.captured_size,
    )


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
    Returns `[]` when no hunter skipped anything for a supported, target-
    bearing reason (see `_TARGET_BEARING_LIMITATION_CAUSES`)."""
    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("build_investigation_queue() records must be a list of HunterRecord")

    groups: dict = {}   # dedup_key -> {"targets": [ScanTarget, ...], "skips": {(hunter,source,scope,cause): SkipRelationship}}
    for record in records:
        for limitation in record.coverage.limitations:
            cause = _TARGET_BEARING_LIMITATION_CAUSES.get(limitation.code)
            if cause is None:
                continue
            for target in limitation.targets:
                key = _dedup_key(target)
                entry = groups.setdefault(key, {"targets": [], "skips": {}})
                # Every target instance the group has seen is kept (not
                # just the first) -- a group can legitimately mix
                # `memory_region` and `memory_segment` kinds for the
                # same physical range (see `_dedup_key()`'s own
                # docstring), and `_merge_target_group()` needs the
                # whole set to pick/build the one representative below.
                entry["targets"].append(target)
                # `cause` is part of the skip key, not just of the
                # SkipRelationship's own payload (issue #28): the SAME
                # (hunter, source, scope) can skip different targets for
                # different reasons (e.g. pipe's pipe_name_scan both skips
                # one oversized region and fails to read another,
                # ordinarily-sized one) -- collapsing those into one
                # dict key would silently keep only whichever cause was
                # seen first for that (hunter, source, scope).
                skip_key = (record.hunter, limitation.source, limitation.scope, cause.value)
                budget_kind, budget_limit, budget_consumed = _budget_fields_from_limitation(limitation)
                entry["skips"].setdefault(skip_key, SkipRelationship(
                    hunter=record.hunter, source=limitation.source, cause=cause.value,
                    scope=limitation.scope, size_limit=target.size_limit,
                    budget_kind=budget_kind, budget_limit=budget_limit,
                    budget_consumed=budget_consumed))

    if not groups:
        return []

    correlated_region_keys = {
        (corr.region_base, corr.region_size)
        for corr in build_region_correlations(records, memory_regions)
    }

    actions = []
    for entry in groups.values():
        target = _merge_target_group(entry["targets"], memory_regions)
        skipped_by = tuple(sorted(
            entry["skips"].values(),
            key=lambda s: (HUNTERS.index(s.hunter), s.source, s.scope or "", s.cause)))

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
        # Distinct (hunter, source, scope) count, NOT len(skipped_by):
        # `cause` is part of skip_key (see above), so the SAME hunter/
        # source/scope can legitimately contribute more than one
        # SkipRelationship for this target (e.g. injection's hidden_pe_scan
        # finding both a read failure AND a short read on different reads
        # within the SAME region). That is not a cross-hunter/cross-scope
        # correlation signal -- only genuinely distinct scopes skipping the
        # same physical target are.
        distinct_scopes = {(s.hunter, s.source, s.scope) for s in skipped_by}
        if len(distinct_scopes) > 1:
            reason_codes.append(InvestigationReasonCode.MULTIPLE_SCOPES_SKIPPED.value)
            has_correlation = True
        if (target.kind == ScanTargetKind.MEMORY_REGION
                and (target.base_address, target.size) in correlated_region_keys):
            reason_codes.append(InvestigationReasonCode.CORRELATED_REGION_EVIDENCE.value)
            has_correlation = True

        priority = _derive_priority(has_exec, has_correlation)
        evidence_availability = _evidence_availability_for(target)
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
