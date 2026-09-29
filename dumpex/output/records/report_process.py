"""`--report` process enrichment: the process-wide environment, handle,
token and identity projections (ReportProcessEnrichment).
"""
from dataclasses import dataclass

from dumpex.output.records.base import _MODULE_CONTEXTS
from dumpex.output.records.common import (
    ENRICHMENT_TEXT_CAP,
    _require_bool,
    _require_bounded_text,
    _require_nonneg_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
    _require_optional_nonneg_int,
)
from dumpex.output.records.report_common import (
    ENRICHMENT_MISSING,
    ENRICHMENT_SCOPE_PROCESS,
    EnrichmentSection,
    _require_enrichment_section,
)
from dumpex.output.records.stream_state import _STREAM_PARSER_STATES


@dataclass(frozen=True)
class ReportEnvironmentValue:
    """One allowlisted environment variable of the dumped process.

    Only names on the report's own session allowlist reach this type: the
    full environment block is `--sysinfo`'s inventory, not the report's.
    `truncated` says the captured value was longer than
    ENRICHMENT_TEXT_CAP and `value` holds its leading characters."""
    name:      str
    value:     str
    truncated: bool

    def __post_init__(self):
        _require_bounded_text(self.name, "ReportEnvironmentValue.name", ENRICHMENT_TEXT_CAP)
        if not isinstance(self.value, str):
            raise ValueError("ReportEnvironmentValue.value must be a str")
        if len(self.value) > ENRICHMENT_TEXT_CAP:
            raise ValueError(
                f"ReportEnvironmentValue.value must be at most {ENRICHMENT_TEXT_CAP} characters")
        _require_bool(self.truncated, "ReportEnvironmentValue.truncated")

    def to_dict(self) -> dict:
        return {"name": self.name, "value": self.value, "truncated": self.truncated}


@dataclass(frozen=True)
class ReportEnvironmentSummary:
    """The allowlisted session slice of the process environment block."""
    section: EnrichmentSection
    entries: tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportEnvironmentSummary.section",
                                    scope=ENRICHMENT_SCOPE_PROCESS, name="environment")
        object.__setattr__(self, "entries", tuple(self.entries))
        if any(not isinstance(e, ReportEnvironmentValue) for e in self.entries):
            raise TypeError(
                "ReportEnvironmentSummary.entries must be ReportEnvironmentValue instances")
        if len(self.entries) != self.section.included:
            raise ValueError(
                "ReportEnvironmentSummary.entries length must equal section.included")

    def to_dict(self) -> dict:
        return {"section": self.section.to_dict(),
                "entries": [e.to_dict() for e in self.entries]}


@dataclass(frozen=True)
class ReportHandleTypeCount:
    """One `type_name -> count` row of the process-wide handle census,
    carrying the same display label and bucketing `--handles` publishes."""
    type_name:           str
    count:               int
    type_name_truncated: bool = False

    def __post_init__(self):
        _require_bounded_text(self.type_name, "ReportHandleTypeCount.type_name",
                              ENRICHMENT_TEXT_CAP)
        _require_nonneg_int(self.count, "ReportHandleTypeCount.count")
        _require_bool(self.type_name_truncated, "ReportHandleTypeCount.type_name_truncated")
        if self.count == 0:
            raise ValueError(
                "ReportHandleTypeCount.count must be positive -- a type holding no handle has "
                "no row")

    def to_dict(self) -> dict:
        return {"type_name": self.type_name, "count": self.count,
                "type_name_truncated": self.type_name_truncated}


@dataclass(frozen=True)
class ReportHandleSummary:
    """The process-wide handle inventory reduced to a bounded per-type
    census.

    `total_handles` is every handle the handle collector returned,
    independent of how many type rows survived the cap. The full
    inventory stays with `--handles`, which this summary points at rather
    than reproduces."""
    section:       EnrichmentSection
    total_handles: "int | None"
    by_type:       tuple = ()

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportHandleSummary.section",
                                    scope=ENRICHMENT_SCOPE_PROCESS, name="handles")
        _require_optional_nonneg_int(self.total_handles, "ReportHandleSummary.total_handles")
        object.__setattr__(self, "by_type", tuple(self.by_type))
        if any(not isinstance(r, ReportHandleTypeCount) for r in self.by_type):
            raise TypeError("ReportHandleSummary.by_type must be ReportHandleTypeCount instances")
        if len(self.by_type) != self.section.included:
            raise ValueError("ReportHandleSummary.by_type length must equal section.included")
        if self.section.status == ENRICHMENT_MISSING and self.total_handles is not None:
            raise ValueError(
                "ReportHandleSummary.total_handles must be None when the handle stream is "
                "missing -- an absent stream counts nothing, it does not count zero")

    def to_dict(self) -> dict:
        return {"section": self.section.to_dict(),
                "total_handles": self.total_handles,
                "by_type": [r.to_dict() for r in self.by_type]}


TOKEN_CAPABILITY_STATUSES = ("available", "limited", "unavailable")


@dataclass(frozen=True)
class ReportTokenCapability:
    """Whether the dump's TokenStream can contribute anything to this
    report.

    `stream_present` is a directory fact -- the dump declares the stream
    -- and is independent of `parser_state`, which says what dumpex can
    do with it. A dump carrying a TokenStream dumpex has no parser for is
    `stream_present=True`, `parser_state='unparsed'`,
    `status='unavailable'`: "no token evidence was captured" and "token
    evidence was captured and cannot be read" are different facts, and
    keeping them apart is the whole reason this section exists."""
    stream_present: bool
    parser_state:   "str | None"   # StreamParserState value; None when no stream is declared
    status:         str            # TOKEN_CAPABILITY_STATUSES
    detail:         str

    def __post_init__(self):
        _require_bool(self.stream_present, "ReportTokenCapability.stream_present")
        if self.parser_state is not None and self.parser_state not in _STREAM_PARSER_STATES:
            raise ValueError(
                f"ReportTokenCapability.parser_state must be None or one of "
                f"{_STREAM_PARSER_STATES}, got {self.parser_state!r}")
        if self.stream_present != (self.parser_state is not None):
            raise ValueError(
                "ReportTokenCapability.parser_state must be set exactly when stream_present is "
                "True -- an undeclared stream has no parse outcome to report")
        if self.status not in TOKEN_CAPABILITY_STATUSES:
            raise ValueError(
                f"ReportTokenCapability.status must be one of {TOKEN_CAPABILITY_STATUSES}, "
                f"got {self.status!r}")
        _require_bounded_text(self.detail, "ReportTokenCapability.detail", ENRICHMENT_TEXT_CAP)

    def to_dict(self) -> dict:
        return {"stream_present": self.stream_present, "parser_state": self.parser_state,
                "status": self.status, "detail": self.detail}


IDENTITY_CONFLICT_SEVERITIES = ("info", "warning")


@dataclass(frozen=True)
class ReportIdentityConflict:
    """One disagreement between two captured identity sources, as the
    canonical process-identity boundary resolved it.

    A conflict is not a coverage gap. Both sources were captured and both
    were read; they simply do not agree, which is a fact an analyst wants
    and an automated consumer must not read as missing evidence. That is
    why these live here rather than in the section's `limitations`, which
    are what drive its evidence state."""
    code:     str
    severity: str
    message:  str

    def __post_init__(self):
        _require_bounded_text(self.code, "ReportIdentityConflict.code", ENRICHMENT_TEXT_CAP)
        if self.severity not in IDENTITY_CONFLICT_SEVERITIES:
            raise ValueError(
                f"ReportIdentityConflict.severity must be one of "
                f"{IDENTITY_CONFLICT_SEVERITIES}, got {self.severity!r}")
        _require_bounded_text(self.message, "ReportIdentityConflict.message",
                              ENRICHMENT_TEXT_CAP)

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "message": self.message}


@dataclass(frozen=True)
class ReportProcessEnrichment:
    """The one process-wide enrichment of a `--report` run: who the dumped
    process is, the session context around it, its bounded handle census,
    and what its TokenStream can contribute.

    Identity fields come from the canonical process-identity boundary, so
    a report and `--process` never disagree about the same dump.
    `path_source` says which claim won the path precedence ("peb" or
    "module") and is None when no path resolved at all.

    `identity_conflicts` carries disagreements between captured sources.
    They are deliberately not `section.limitations`: a limitation says
    evidence was missing and drives the section's evidence state, while a
    conflict says two sources were both read and disagree, which leaves
    the evaluation complete. Nothing here is a maliciousness judgment."""
    section:              EnrichmentSection
    pid:                  "int | None"
    process_name:         "str | None"
    process_path:         "str | None"
    path_source:          "str | None"
    command_line:         "str | None"
    process_start_utc:    "str | None"
    image_base_address:   "str | None"
    module_match_state:   "str | None"
    environment:          ReportEnvironmentSummary
    handles:              ReportHandleSummary
    token:                ReportTokenCapability
    process_path_truncated: bool = False   # a PEB path, name, or command line is bounded only
    command_line_truncated: bool = False   # by the UNICODE_STRING that carried it (a name with
    process_name_truncated: bool = False   # no path separator in it is the whole string), so
                                             # all three go through the enrichment
                                             # retained-text cap like every other dump-derived
                                             # string here
    identity_conflicts:       tuple = ()   # bounded ReportIdentityConflict list -- captured
    identity_conflicts_total: int   = 0    # sources that disagree, never a coverage gap and
                                             # never an input to section.status

    def __post_init__(self):
        _require_enrichment_section(self.section, "ReportProcessEnrichment.section",
                                    scope=ENRICHMENT_SCOPE_PROCESS, name="process")
        if self.pid is not None:
            _require_nonneg_int(self.pid, "ReportProcessEnrichment.pid")
        for field_name in ("process_name", "process_path", "path_source", "command_line",
                           "process_start_utc", "module_match_state"):
            _require_optional_diff_str(getattr(self, field_name),
                                       f"ReportProcessEnrichment.{field_name}")
        _require_optional_hex_address(self.image_base_address,
                                      "ReportProcessEnrichment.image_base_address")
        if self.path_source is not None and self.path_source not in ("peb", "module"):
            raise ValueError(
                "ReportProcessEnrichment.path_source must be None, 'peb', or 'module', got "
                f"{self.path_source!r}")
        if self.path_source is not None and self.process_path is None:
            raise ValueError(
                "ReportProcessEnrichment.path_source requires a resolved process_path")
        if self.module_match_state is not None and self.module_match_state not in _MODULE_CONTEXTS:
            raise ValueError(
                f"ReportProcessEnrichment.module_match_state must be None or one of "
                f"{_MODULE_CONTEXTS}, got {self.module_match_state!r}")
        if not isinstance(self.environment, ReportEnvironmentSummary):
            raise TypeError(
                "ReportProcessEnrichment.environment must be a ReportEnvironmentSummary")
        if not isinstance(self.handles, ReportHandleSummary):
            raise TypeError("ReportProcessEnrichment.handles must be a ReportHandleSummary")
        if not isinstance(self.token, ReportTokenCapability):
            raise TypeError("ReportProcessEnrichment.token must be a ReportTokenCapability")
        for field_name in ("process_path_truncated", "command_line_truncated",
                           "process_name_truncated"):
            _require_bool(getattr(self, field_name), f"ReportProcessEnrichment.{field_name}")
        object.__setattr__(self, "identity_conflicts", tuple(self.identity_conflicts))
        if any(not isinstance(c, ReportIdentityConflict) for c in self.identity_conflicts):
            raise TypeError(
                "ReportProcessEnrichment.identity_conflicts must be ReportIdentityConflict "
                "instances")
        _require_nonneg_int(self.identity_conflicts_total,
                            "ReportProcessEnrichment.identity_conflicts_total")
        if len(self.identity_conflicts) > self.identity_conflicts_total:
            raise ValueError(
                "ReportProcessEnrichment.identity_conflicts_total must count every conflict "
                "the boundary reported, including those the cap dropped")
        for value_field, flag_field in (("process_path", "process_path_truncated"),
                                        ("command_line", "command_line_truncated"),
                                        ("process_name", "process_name_truncated")):
            value = getattr(self, value_field)
            if value is not None and len(value) > ENRICHMENT_TEXT_CAP:
                raise ValueError(
                    f"ReportProcessEnrichment.{value_field} must be at most "
                    f"{ENRICHMENT_TEXT_CAP} characters")
            if getattr(self, flag_field) and value is None:
                raise ValueError(
                    f"ReportProcessEnrichment.{flag_field} requires a {value_field}")

    def to_dict(self) -> dict:
        return {
            "section":            self.section.to_dict(),
            "pid":                self.pid,
            "process_name":       self.process_name,
            "process_path":       self.process_path,
            "path_source":        self.path_source,
            "command_line":       self.command_line,
            "process_start_utc":  self.process_start_utc,
            "image_base_address": self.image_base_address,
            "module_match_state": self.module_match_state,
            "environment":        self.environment.to_dict(),
            "handles":            self.handles.to_dict(),
            "token":              self.token.to_dict(),
            "process_path_truncated": self.process_path_truncated,
            "command_line_truncated": self.command_line_truncated,
            "process_name_truncated": self.process_name_truncated,
            "identity_conflicts": [c.to_dict() for c in self.identity_conflicts],
            "identity_conflicts_total": self.identity_conflicts_total,
        }
