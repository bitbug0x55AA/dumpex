"""`--report` triage cards: TriageCardRecord and its anchor, verdict and
finding vocabularies.

One TriageCardRecord per triage card -- see dumpex.commands.report's own
module docstring for why this is NOT a --diff-style tagged union of
independent thread/region/string entities: a card's thread/region/
strings/verdict are one coherent, MECE-scored narrative about one anchor,
not independent things a consumer would count/filter separately.
--report-string's N hits become N TriageCardRecords in one
CommandResult.records list; tid/addr mode always produces exactly one.
"""
from dataclasses import dataclass

from dumpex.output.records.common import (
    _require_bool,
    _require_hex_address,
    _require_nonneg_int,
    _require_optional_diff_str,
    _require_optional_hex_address,
)
from dumpex.output.records.extraction import StringRecord, _STRING_RECORD_ENCODINGS
from dumpex.output.records.report_context import (
    ReportAllocationNeighborhood,
    ReportExceptionContext,
    ReportHandleCorrelation,
    ReportStringContext,
)
from dumpex.output.records.report_iat import ReportIatCorrelation
from dumpex.output.records.report_instruction import ReportInstructionContext
from dumpex.output.records.report_pe import ReportAnchorPeContext
from dumpex.output.records.report_thread import ReportIocString, ReportRegionInfo, ReportThreadInfo


TRIAGE_ANCHOR_TID            = "tid"
TRIAGE_ANCHOR_ADDRESS        = "address"
TRIAGE_ANCHOR_STRING_HIT     = "string_hit"
# A --report-tid card for a thread with no established start address --
# no ThreadInfoListStream entry at all, or an entry whose own DumpFlags
# disown every field but ThreadId (the card's own thread.
# start_address_state says which) -- which therefore anchors on that
# thread's independently captured current IP instead. Distinct from
# TRIAGE_ANCHOR_TID, which always means the anchor is the thread's
# recorded start address. Keeps the fallback's own address and source
# explicit on the wire rather than indistinguishable from an ordinary
# start-address anchor.
TRIAGE_ANCHOR_TID_CURRENT_IP = "tid_current_ip"
_TRIAGE_ANCHOR_SOURCES = (TRIAGE_ANCHOR_TID, TRIAGE_ANCHOR_ADDRESS, TRIAGE_ANCHOR_STRING_HIT,
                           TRIAGE_ANCHOR_TID_CURRENT_IP)

# Mirrors dumpex.core.memory.VERDICT_CLEAN/_SUSPICIOUS/_LIKELY_MALICIOUS/
# _HIGH_CONFIDENCE_MALICIOUS by convention (same four literal strings) --
# not imported from there, the same way ThreadRecord.module_context's own
# MODULE_CONTEXT_* vocabulary (base) is this package's own closed set
# rather than importing dumpex.hunt._context's. Keeps the dependency
# direction command/domain model -> output layer, never the reverse.
_TRIAGE_VERDICTS = ("CLEAN", "SUSPICIOUS", "LIKELY_MALICIOUS", "HIGH_CONFIDENCE_MALICIOUS")

# Mirrors dumpex.core.memory.INDICATOR_DIMS' own four keys by convention,
# for the same reason _TRIAGE_VERDICTS mirrors VERDICT_CLEAN/etc rather
# than importing them -- a TriageCardRecord.findings entry outside this
# set is rejected at construction time, not just left undocumented.
_TRIAGE_FINDING_KEYS = ("unbacked_thread", "rwx_private", "injected_pe", "ioc_strings")


@dataclass
class TriageCardRecord:
    """One triage card -- see this module's own docstring for why
    this is one record per card, not a tagged union of its constituent
    thread/region/string facts. `anchor_source` says which of --report-tid/
    --report-addr/--report-string produced THIS card (string-hit mode
    produces N cards, one per private hit region, each with
    anchor_source="string_hit" and anchor_address set to that region's
    base -- report_tid is never forwarded into those, see
    dumpex.commands.report's own note on why). A --report-tid card whose
    thread has no recorded StartAddress at all gets
    anchor_source="tid_current_ip" instead of the ordinary "tid" value,
    with `anchor_address` set to that thread's own captured current IP --
    the one case where the anchor examined is NOT the value `anchor_source`
    would otherwise suggest, so it is labeled with its own distinct value
    rather than left for a consumer to infer from `thread.start_address`
    being null. `notable_strings` reuses
    StringRecord as-is (matched_grep always None -- --report has no
    --grep concept). `ioc_strings` is a list of ReportIocString, NOT
    StringRecord -- see that class's own docstring for why (an extra
    is_network_pattern bool plus a bounded, collect-time-computed hexdump
    context that has no meaning for plain `--strings` output).
    `findings`/`finding_details` are today's `dims`
    dict, split into its ordered keys and their detail text -- `findings`
    entries are restricted to _TRIAGE_FINDING_KEYS, the same closed
    vocabulary as
    dumpex.core.memory.INDICATOR_DIMS' own keys (unbacked_thread/
    rwx_private/injected_pe/ioc_strings), mirrored locally rather than
    imported (see _TRIAGE_VERDICTS' own note on why this package doesn't
    import from core.memory) -- an invented finding key is rejected here,
    not just left undocumented. `verdict` is verdict_for(dims)'s output --
    provably the same MECE rule the console's own colored text renders
    from (see core.memory._verdict); __post_init__ cross-checks verdict
    against len(findings) using the same four-tier rule, mirrored locally
    for the same reason. `artifact_id` correlates to this
    card's own entry in result.artifacts when --output was given for this
    card, else None.

    `string_scan`/`string_scan_error` capture Section 4's own scan
    metadata that neither notable_strings nor ioc_strings (both filtered
    subsets) can reconstruct: `requested_bytes` is how much this card
    asked read_region() for (post MAX_REGION_READ clamping -- `clamped`
    says whether that clamp actually reduced the ask below the region's
    own size); `bytes_read` is the real `len(data)` read_region() handed
    back (which can independently come up short of `requested_bytes` when
    the dump itself doesn't back that much of the region -- `truncated`
    flags exactly that, a genuine evidence-completeness gap distinct from
    `clamped`'s own self-imposed scan-budget policy). Both None (all
    string_scan fields, string_scan_error) when region is None (Section 4
    never ran); string_scan None with string_scan_error set to the
    exception text when region is not None but the read/extraction itself
    raised. `thread_region_correlation_excluded` is True
    exactly when this card's thread was confirmed unbacked but that fact
    was excluded from `findings`/verdict because it is not correlated
    with the independently-resolved region (see
    dumpex.commands.report._collect_triage_card's own reconciliation
    note) -- a fact with no other home in this record, since `findings`
    only lists dimensions that DID fire."""
    anchor_tid:               "int | None"
    anchor_address:           "str | None"
    anchor_source:            str          # TRIAGE_ANCHOR_TID / _ADDRESS / _STRING_HIT / _TID_CURRENT_IP
    thread:                   "ReportThreadInfo | None"
    region:                   "ReportRegionInfo | None"
    string_hit:               "dict | None"   # {"offset", "address", "encoding"} -- the exact
                                                # location _search_string_in_memory found the
                                                # needle at, for anchor_source == string_hit cards
                                                # only; None otherwise. Kept separate from
                                                # notable_strings/ioc_strings (Section 4's own,
                                                # independently-run string extraction, which is
                                                # not guaranteed to re-find this exact substring
                                                # position, e.g. across a min_len boundary).
    other_threads_in_region:  list         # list[ReportThreadInfo]
    notable_strings:          list         # list[StringRecord]
    ioc_strings:              list         # list[ReportIocString]
    string_scan:              "dict | None"   # {"requested_bytes", "bytes_read", "clamped",
                                                # "truncated", "total", "ascii_count", "utf16_count"}
    string_scan_error:        "str | None"
    thread_region_correlation_excluded: bool
    findings:                 list         # list[str] -- _TRIAGE_FINDING_KEYS subset that fired
    finding_details:          dict         # {key: human detail string}
    verdict:                  str          # verdict_for()'s output
    artifact_id:              "str | None"
    extract_read_clamped:     "bool | None"   # None when no --output was given for this card
                                                # (extract never attempted); True/False once it
                                                # was, whether MAX_REGION_READ clamped the bytes
                                                # actually written below the region's own size
    extract_read_truncated:   "bool | None"   # None when no --output was given for this card;
                                                # True/False once it was, whether read_region()
                                                # itself came up short of whatever was requested
                                                # (post-clamp) -- a genuine evidence gap distinct
                                                # from extract_read_clamped's own self-imposed
                                                # policy cap (same clamped-vs-truncated split as
                                                # string_scan above). True here means the written
                                                # artifact is itself incomplete, not just smaller
                                                # than the region by policy.
    # ── Card-scoped enrichment (see dumpex.output.records.report_common) ──
    # Each is bounded, carries its own EnrichmentSection, and is captured
    # evidence only: none of them appears in findings/finding_details/
    # verdict, and none of them can move the exit code. None means the
    # producer built no projection at all for this card, which is distinct
    # from a projection whose section status is "missing".
    exception_context:        "ReportExceptionContext | None" = None
    allocation_neighborhood:  "ReportAllocationNeighborhood | None" = None
    handle_correlation:       "ReportHandleCorrelation | None" = None
    string_context:           "ReportStringContext | None" = None
    anchor_pe_context:        "ReportAnchorPeContext | None" = None
    instruction_context:      "ReportInstructionContext | None" = None
    iat_correlation:          "ReportIatCorrelation | None" = None

    def __post_init__(self):
        if self.anchor_tid is not None:
            _require_nonneg_int(self.anchor_tid, "TriageCardRecord.anchor_tid")
        _require_optional_hex_address(self.anchor_address, "TriageCardRecord.anchor_address")
        if self.anchor_source not in _TRIAGE_ANCHOR_SOURCES:
            raise ValueError(
                f"TriageCardRecord.anchor_source must be one of {_TRIAGE_ANCHOR_SOURCES}, "
                f"got {self.anchor_source!r}")
        if self.thread is not None and not isinstance(self.thread, ReportThreadInfo):
            raise TypeError("TriageCardRecord.thread must be None or a ReportThreadInfo")
        if self.region is not None and not isinstance(self.region, ReportRegionInfo):
            raise TypeError("TriageCardRecord.region must be None or a ReportRegionInfo")
        if self.string_hit is not None:
            if not isinstance(self.string_hit, dict) or set(self.string_hit.keys()) != {
                    "offset", "address", "encoding"}:
                raise ValueError(
                    "TriageCardRecord.string_hit must be None or a dict with exactly "
                    "'offset'/'address'/'encoding' keys")
            _require_nonneg_int(self.string_hit["offset"], "TriageCardRecord.string_hit['offset']")
            _require_hex_address(self.string_hit["address"], "TriageCardRecord.string_hit['address']")
            if self.string_hit["encoding"] not in _STRING_RECORD_ENCODINGS:
                raise ValueError(
                    f"TriageCardRecord.string_hit['encoding'] must be one of "
                    f"{_STRING_RECORD_ENCODINGS}, got {self.string_hit['encoding']!r}")
        if self.anchor_source == TRIAGE_ANCHOR_STRING_HIT and self.string_hit is None:
            raise ValueError(
                "TriageCardRecord.string_hit is required when anchor_source == 'string_hit'")
        if self.anchor_source != TRIAGE_ANCHOR_STRING_HIT and self.string_hit is not None:
            raise ValueError(
                "TriageCardRecord.string_hit must be None when anchor_source != 'string_hit'")
        if not isinstance(self.other_threads_in_region, list) or any(
                not isinstance(t, ReportThreadInfo) for t in self.other_threads_in_region):
            raise TypeError(
                "TriageCardRecord.other_threads_in_region must be a list of ReportThreadInfo")
        if not isinstance(self.notable_strings, list) or any(
                not isinstance(s, StringRecord) for s in self.notable_strings):
            raise TypeError("TriageCardRecord.notable_strings must be a list of StringRecord")
        if not isinstance(self.ioc_strings, list) or any(
                not isinstance(s, ReportIocString) for s in self.ioc_strings):
            raise TypeError("TriageCardRecord.ioc_strings must be a list of ReportIocString")
        if self.string_scan is not None:
            if not isinstance(self.string_scan, dict):
                raise TypeError("TriageCardRecord.string_scan must be None or a dict")
            required = {"requested_bytes", "bytes_read", "clamped", "truncated",
                        "total", "ascii_count", "utf16_count"}
            if set(self.string_scan.keys()) != required:
                raise ValueError(
                    f"TriageCardRecord.string_scan must have exactly the keys {sorted(required)}, "
                    f"got {sorted(self.string_scan.keys())}")
            for key in ("clamped", "truncated"):
                _require_bool(self.string_scan[key], f"TriageCardRecord.string_scan[{key!r}]")
            for key in ("requested_bytes", "bytes_read", "total", "ascii_count", "utf16_count"):
                _require_nonneg_int(self.string_scan[key], f"TriageCardRecord.string_scan[{key!r}]")
            if self.string_scan["bytes_read"] > self.string_scan["requested_bytes"]:
                raise ValueError(
                    "TriageCardRecord.string_scan['bytes_read'] must not exceed "
                    "['requested_bytes'] -- a read can come up short, never long")
            if self.string_scan["truncated"] != (
                    self.string_scan["bytes_read"] < self.string_scan["requested_bytes"]):
                raise ValueError(
                    "TriageCardRecord.string_scan['truncated'] must equal "
                    "bytes_read < requested_bytes")
        _require_optional_diff_str(self.string_scan_error, "TriageCardRecord.string_scan_error")
        if self.string_scan is not None and self.string_scan_error is not None:
            raise ValueError(
                "TriageCardRecord.string_scan and string_scan_error are mutually exclusive -- "
                "a scan either produced counts or failed, never both")
        _require_bool(self.thread_region_correlation_excluded,
                      "TriageCardRecord.thread_region_correlation_excluded")
        if self.extract_read_clamped is not None:
            _require_bool(self.extract_read_clamped, "TriageCardRecord.extract_read_clamped")
        if self.extract_read_truncated is not None:
            _require_bool(self.extract_read_truncated, "TriageCardRecord.extract_read_truncated")
        if (self.extract_read_clamped is None) != (self.extract_read_truncated is None):
            raise ValueError(
                "TriageCardRecord.extract_read_clamped and extract_read_truncated must both be "
                "None (no --output attempted for this card) or both be set (once it was)")
        if not isinstance(self.findings, list) or any(
                f not in _TRIAGE_FINDING_KEYS for f in self.findings):
            raise ValueError(
                f"TriageCardRecord.findings entries must all be one of {_TRIAGE_FINDING_KEYS}, "
                f"got {self.findings!r}")
        if len(set(self.findings)) != len(self.findings):
            raise ValueError("TriageCardRecord.findings must not contain duplicate keys")
        if not isinstance(self.finding_details, dict) or any(
                not isinstance(k, str) or not isinstance(v, str)
                for k, v in self.finding_details.items()):
            raise TypeError(
                "TriageCardRecord.finding_details must be a dict of str -> str")
        if set(self.findings) != set(self.finding_details.keys()):
            raise ValueError(
                "TriageCardRecord.findings and finding_details must name the same keys, got "
                f"findings={self.findings!r} finding_details keys={list(self.finding_details)!r}")
        if self.verdict not in _TRIAGE_VERDICTS:
            raise ValueError(
                f"TriageCardRecord.verdict must be one of {_TRIAGE_VERDICTS}, got {self.verdict!r}")
        expected_verdict = _TRIAGE_VERDICTS[min(len(self.findings), 3)]
        if self.verdict != expected_verdict:
            raise ValueError(
                f"TriageCardRecord.verdict={self.verdict!r} does not match the four-tier rule "
                f"for {len(self.findings)} finding(s) (expected {expected_verdict!r}) -- mirrors "
                f"dumpex.core.memory.verdict_for()'s own len(dims) rule")
        _require_optional_diff_str(self.artifact_id, "TriageCardRecord.artifact_id")
        for field_name, cls in (("exception_context", ReportExceptionContext),
                                ("allocation_neighborhood", ReportAllocationNeighborhood),
                                ("handle_correlation", ReportHandleCorrelation),
                                ("string_context", ReportStringContext),
                                ("anchor_pe_context", ReportAnchorPeContext),
                                ("instruction_context", ReportInstructionContext),
                                ("iat_correlation", ReportIatCorrelation)):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, cls):
                raise TypeError(
                    f"TriageCardRecord.{field_name} must be None or a {cls.__name__}")
        if (self.anchor_pe_context is not None
                and self.anchor_pe_context.anchor_address != self.anchor_address):
            raise ValueError(
                "TriageCardRecord.anchor_pe_context.anchor_address must be this card's own "
                "anchor_address")
        if (self.instruction_context is not None
                and self.instruction_context.anchor_address is not None
                and self.anchor_address is None):
            raise ValueError(
                "TriageCardRecord.instruction_context resolves an anchor the card does not have")
        if self.string_context is not None and self.anchor_address is None:
            raise ValueError(
                "TriageCardRecord.string_context requires a resolved anchor_address -- string "
                "context is selected by distance from an anchor")
        if (self.string_context is not None
                and self.string_context.anchor_address != self.anchor_address):
            raise ValueError(
                "TriageCardRecord.string_context.anchor_address must be this card's own "
                "anchor_address")

    def to_dict(self) -> dict:
        return {
            "anchor_tid":              self.anchor_tid,
            "anchor_address":          self.anchor_address,
            "anchor_source":           self.anchor_source,
            "thread":                  self.thread.to_dict() if self.thread else None,
            "region":                  self.region.to_dict() if self.region else None,
            "string_hit":              dict(self.string_hit) if self.string_hit else None,
            "other_threads_in_region": [t.to_dict() for t in self.other_threads_in_region],
            "notable_strings":         [s.to_dict() for s in self.notable_strings],
            "ioc_strings":             [s.to_dict() for s in self.ioc_strings],
            "string_scan":             dict(self.string_scan) if self.string_scan else None,
            "string_scan_error":       self.string_scan_error,
            "thread_region_correlation_excluded": self.thread_region_correlation_excluded,
            "findings":                list(self.findings),
            "finding_details":         dict(self.finding_details),
            "verdict":                 self.verdict,
            "artifact_id":             self.artifact_id,
            "extract_read_clamped":    self.extract_read_clamped,
            "extract_read_truncated":  self.extract_read_truncated,
            "exception_context":       (self.exception_context.to_dict()
                                        if self.exception_context else None),
            "allocation_neighborhood": (self.allocation_neighborhood.to_dict()
                                        if self.allocation_neighborhood else None),
            "handle_correlation":      (self.handle_correlation.to_dict()
                                        if self.handle_correlation else None),
            "string_context":          (self.string_context.to_dict()
                                        if self.string_context else None),
            "anchor_pe_context":       (self.anchor_pe_context.to_dict()
                                        if self.anchor_pe_context else None),
            "instruction_context":     (self.instruction_context.to_dict()
                                        if self.instruction_context else None),
            "iat_correlation":         (self.iat_correlation.to_dict()
                                        if self.iat_correlation else None),
        }
