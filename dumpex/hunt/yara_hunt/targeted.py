"""Targeted YARA rescan: every compiled rule over one segment slice.

A targeted ``--hunt-addr`` YARA invocation asks the segment scanner to match
every compiled rule against one investigator-selected half-open
virtual-address range. :func:`run_targeted_yara` is the executor the analyzer
registry resolves as ``yara``'s ``AnalyzerSpec.targeted_adapter`` (through the
``dumpex.hunt._run_targeted_yara`` facade seam).

The requested range is resolved to the captured segment containing its base and
handed to :func:`dumpex.hunt.yara_hunt.scanner.scan_segments` as a single
:class:`~dumpex.hunt._targeted.SyntheticSegment`: virtual base at the requested
address, size the requested (clipped) extent, and file offset the containing
segment's own offset displaced by the slice's distance from that segment's
base. Hit virtual addresses and dump-file offsets the scanner derives from
``slice base + match offset`` are therefore the same absolute values a
full-scope scan of the whole segment would report.

Only ``YARA_MAX_SEG_SCAN`` is bypassed, and only for this one slice. Every
other budget is retained at its full-scope value -- the per-match timeout, the
whole-scan deadline, the total-bytes-scanned cap, the hit cap, and the
per-match retained-string cap.

Those budgets are fresh per ADAPTER CALL, not accumulated across a
:class:`~dumpex.hunt._execution.HuntExecutionContext`: the scanner builds its
own deadline and byte counters internally and nothing here is registered on
``context.budgets``. One targeted command runs this adapter once, so today that
is the same thing. An orchestrator that ever runs several ranges on one context
must thread a shared budget through instead, or each range would silently get a
whole fresh deadline and byte allowance. Rules are compiled through the same
``dumpex.hunt.yara_hunt._resolve_rule_files`` prerequisite chain the full-scope
builder uses, so the ``RulesProvenance`` behind a targeted verdict names the
same rule content.

Source eligibility and evaluation are anchored to the containing segment: a
request that runs past its end is captured in full but evaluated only up to the
boundary, and the closure is ``partial`` with
``SCAN_REGION_EVALUATION_TRUNCATED``. A request lying wholly inside a larger
segment carries a diagnostic naming that segment, because a signature spanning
either requested boundary is evaluated by neither this rescan nor the bytes
around it.

A budget that stops the scan before a single byte is read names the exact
unexamined suffix -- the whole request -- as its own
:class:`~dumpex.output.coverage.ScanTarget`. A budget that stops AFTER the read
does not, and does not claim to: YARA matches a whole buffer per rule, so work
a hit cap or a deadline left undone is "some rules did not finish over these
bytes", which no single byte offset expresses. Those gaps keep the scanner's
own whole-slice target -- a conservative superset, never a narrower range than
what is actually unresolved. A short read is separate and is exact: its unread
suffix is carried by ``SCAN_REGION_SHORT_READ`` and by the closure's
``read_slice``.

The result is one :class:`~dumpex.hunt._observation.ObservationResult` with a
single ``segment_scan`` closure and a :class:`TargetedYaraEvidence` payload
carrying the scanner's own matches, diagnostics, and rules provenance plus the
containing-segment :class:`~dumpex.output.coverage.ScanTarget`.
"""
import dataclasses

from dumpex.core import va_range
from dumpex.core.memory import get_memory_regions, get_modules
from dumpex.core.va_range import CaptureState

import dumpex.hunt.yara_hunt as _yara
from dumpex.hunt import _registry, _targeted
from dumpex.hunt._observation import ObservationClosure, ObservationResult
from dumpex.hunt._runtime import HunterRuntime
from dumpex.hunt.yara_hunt import domain, scanner
from dumpex.output.coverage import CoverageLimitation, LimitationCode

__all__ = [
    "run_targeted_yara", "TargetedYaraEvidence", "TargetedYaraError",
    "ALGORITHM_VERSION", "TARGETED_SOURCE",
]

# The observation-key algorithm identity for this executor -- bumped only when
# a change to which bytes reach the matcher would make a cached result from an
# earlier version unsafe to reuse.
ALGORITHM_VERSION = "yara-targeted/1"

# The one granted coverage source (the capability matrix grants `yara` exactly
# `segment_scan`, with no finer subdivision, so the closure carries no scope).
TARGETED_SOURCE = "segment_scan"

# Raised in place of `YARA_MAX_SEG_SCAN`. Far above the 256 MiB yara request
# ceiling, so no slice inside a valid targeted request is ever skipped for
# size -- and nothing here is a buffer allocation, only a `seg.size > cap`
# comparison.
_CAP_BYPASS = 1 << 40


class TargetedYaraError(Exception):
    """The context handed to :func:`run_targeted_yara` is not a legal YARA
    targeted request. Raised before any dump read, so the
    ``dumpex.hunt._run_targeted_yara`` monkeypatch seam cannot route another
    analyzer's request into this executor and past its own request ceiling."""


@dataclasses.dataclass(frozen=True)
class TargetedYaraEvidence:
    """The scan results behind one targeted ``ObservationResult`` -- carried as
    its ``payload`` so a consumer can render what the rescan found.

    ``matches`` is the scanner's tuple of
    :class:`~dumpex.hunt.yara_hunt.models.RuleMatchEvidence`, each carrying
    absolute ``seg_va`` / ``seg_fo`` for the slice and per-string absolute
    addresses. ``diagnostics`` is the scanner's own
    :class:`~dumpex.hunt.yara_hunt.domain.ScanDiagnostics`, or ``None`` when
    the scanner never ran because no rule was usable -- in which case
    ``matches`` is empty and ``rules`` still carries the full provenance for
    every candidate file considered, so a consumer must not reach through
    ``diagnostics`` without checking it. ``rules`` is the
    :class:`~dumpex.hunt.yara_hunt.domain.RulesDiagnostics` naming the rule
    content behind the matches. ``containing_segment`` is the
    :class:`~dumpex.output.coverage.ScanTarget` for the captured segment the
    requested range was evaluated inside -- distinct from the requested range
    and from any hit address, so a consumer can tell whether a full-segment
    closure is licensed."""
    matches: tuple
    diagnostics: object
    rules: object
    containing_segment: object


def _validate_request(request) -> None:
    """Fail closed unless ``request`` is a YARA ``segment_scan`` targeted
    request covering exactly the granted (empty) scope set."""
    if not getattr(request, "is_targeted", False):
        raise TargetedYaraError("run_targeted_yara requires a targeted HuntRequest")
    if request.selected != "yara" or request.targeted_source != TARGETED_SOURCE:
        raise TargetedYaraError(
            f"run_targeted_yara is yara/{TARGETED_SOURCE} only, got "
            f"{request.selected!r}/{request.targeted_source!r}")
    granted = _registry.REGISTRY.granted_scopes("yara", TARGETED_SOURCE)
    if request.targeted_scopes != granted:
        raise TargetedYaraError(
            f"a yara targeted request covers exactly {sorted(granted)}, got "
            f"{sorted(request.targeted_scopes)}")


def _not_evaluated_result(key, capture, note: str, *,
                          limitations: tuple = (), payload=None) -> ObservationResult:
    """A not-evaluated result for the whole request.

    ``captured_bytes`` is the measured availability of the requested range,
    carried even though nothing ran: a closure that never reached its algorithm
    still knows how much of the range the dump holds, and reporting that as
    unknown would cost an investigator the one number a re-collection or a
    chunked rescan is sized from.
    """
    return ObservationResult(
        key=key,
        closures=(ObservationClosure(
            source=TARGETED_SOURCE, coverage_status="not_evaluated",
            capture_state=capture.state, captured_bytes=capture.captured_bytes,
            limitations=limitations, diagnostics=(note,)),),
        payload=payload)


def _prerequisite_note(rules) -> str:
    """Which rule prerequisite stopped this rescan before any dump byte was
    read -- recovered from the ``RulesDiagnostics`` alone, the same way
    ``report_facts.project_coverage_reasons`` recovers it.

    A directory whose candidate files all failed to compile is named as such:
    rule files DO exist there, so reporting it as an empty directory would send
    an investigator looking for the wrong problem."""
    if not rules.yara_available:
        return "yara-python is not installed; no rule could be matched against the range"
    if rules.rules_dir is None:
        return "no YARA rules directory found; no rule could be matched against the range"
    if rules.compile_failed:
        return (f"all {rules.compile_failed} candidate rule file(s) in {rules.rules_dir} "
                f"failed to compile; no rule could be matched against the range")
    return f"no usable .yar/.yara files in {rules.rules_dir}"


def _rule_compile_limitation(rules) -> tuple:
    """``YARA_RULE_COMPILE_FAILED`` for a rules directory some of whose
    candidate files did not compile -- structurally identical to the one
    ``report_facts.project_coverage_report`` builds, and emitted whether or not
    any rule survived to be matched: a rule that never compiled was never
    applied to the requested range either way."""
    if not rules.compile_failed:
        return ()
    return (CoverageLimitation(
        code=LimitationCode.YARA_RULE_COMPILE_FAILED, source="yara_rules",
        affected_count=rules.compile_failed),)


def _coverage_status(diag, rules, matches, capture_state: CaptureState, *,
                     truncated: bool) -> str:
    """This closure's honest ``coverage_status`` -- the same reduction
    ``YaraReport.scan_complete`` applies full-scope, over one slice.

    ``not_evaluated`` -- the slice never reached a ``match()`` call: the read
    raised or returned nothing, or a retained whole-scan budget was already
    spent when the scan reached it.

    Otherwise ``partial`` on any gap -- a short capture, evaluation stopped at
    the containing segment's end, a short read, a failed or timed-out match, a
    hit/byte/deadline cap, a rule file that never compiled, or hits none of
    which could be context-classified -- and ``complete`` only when the whole
    requested range was captured and every compiled rule finished against all
    of it.

    The last two are as load-bearing as the scan-loop gaps: a rule that failed
    to compile was never applied to these bytes, and a hit nothing could
    classify is itself a reason the negative around it cannot be trusted.
    Either one reaching ``complete`` would license a
    ``NOT_DETECTED_IN_SCANNED_SCOPE`` the evidence does not support.
    """
    if diag.scanned == 0:
        return "not_evaluated"
    if capture_state != CaptureState.COMPLETE or truncated:
        return "partial"
    if not diag.scan_complete or rules.compile_failed:
        return "partial"
    if domain.match_context_incomplete(matches):
        return "partial"
    return "complete"


def _limitations(diag, rules, matches, *, truncation_limitation, budget_targets,
                 search_incomplete: tuple) -> tuple:
    """The structured gaps for the closure -- the same ``CoverageLimitation``
    shapes ``report_facts.project_coverage_report`` builds for a full-scope
    YARA run, over this one slice.

    ``budget_targets`` replaces the scanner's own whole-slice target list on
    the two codes that name unexamined scope, and is non-empty only when the
    budget stopped the scan before a single byte was read -- see
    :func:`run_targeted_yara`."""
    out = list(_rule_compile_limitation(rules))
    if diag.skipped_oversize:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source=TARGETED_SOURCE,
            affected_count=diag.skipped_oversize,
            targets=list(diag.skipped_oversize_targets)))
    if diag.read_failed:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source=TARGETED_SOURCE,
            affected_count=diag.read_failed, targets=list(diag.read_failed_targets)))
    if diag.short_reads:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source=TARGETED_SOURCE,
            affected_count=diag.short_reads, targets=list(diag.short_read_targets)))
    if diag.match_failed:
        out.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_FAILED, source=TARGETED_SOURCE,
            affected_count=diag.match_failed, targets=list(diag.match_failed_targets)))
    if diag.timed_out:
        out.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_TIMED_OUT, source=TARGETED_SOURCE,
            affected_count=diag.timed_out, targets=list(diag.timed_out_targets)))
    if truncation_limitation is not None:
        out.append(truncation_limitation)
    if diag.truncated:
        targets = budget_targets if budget_targets else list(diag.truncated_targets)
        out.append(CoverageLimitation(
            code=LimitationCode.YARA_HIT_CAP_REACHED, source=TARGETED_SOURCE,
            affected_count=len(targets), targets=targets, scope="max_total_hits",
            budget_limit=diag.truncated_budget_limit,
            budget_consumed=diag.truncated_budget_limit))
    if diag.has_real_budget_gap:
        targets = budget_targets if budget_targets else list(diag.budget_exhausted_targets)
        out.append(CoverageLimitation(
            code=LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED, source=TARGETED_SOURCE,
            affected_count=len(targets), targets=targets,
            scope=diag.budget_exhausted_kind, budget_limit=diag.budget_exhausted_limit,
            budget_consumed=diag.budget_exhausted_consumed))
    # Gated and counted exactly as full-scope: raised only when NOTHING was
    # confidently classified, and counting distinct RULES, not hits -- the same
    # code must not mean a rule count on one path and a hit count on the other.
    if domain.match_context_incomplete(matches):
        out.append(CoverageLimitation(
            code=LimitationCode.YARA_MATCH_CONTEXT_UNVERIFIED, source="yara_context",
            affected_count=len(domain.unverified_rule_names(matches))))
    for detail in search_incomplete:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source=TARGETED_SOURCE,
            detail=detail, affected_count=1))
    return tuple(out)


def run_targeted_yara(context) -> ObservationResult:
    """Match every compiled rule against ``context.request.target_range`` and
    return one :class:`~dumpex.hunt._observation.ObservationResult` with a
    single ``segment_scan`` closure and a :class:`TargetedYaraEvidence`
    payload.

    ``context`` is a targeted :class:`~dumpex.hunt._execution.HuntExecutionContext`.
    Raises :class:`TargetedYaraError` for any other request shape, before any
    dump read.
    """
    _validate_request(context.request)

    mf = context.mf
    requested = context.request.target_range
    key = context.observation_key("yara", algorithm_version=ALGORITHM_VERSION)

    capture = context.capture_of(requested)
    segment_enum = context.captured_segment_enumeration()
    containing = va_range.segment_containing(requested.base_address, segment_enum.views)

    if containing is None:
        dropped = ""
        if segment_enum.skipped:
            dropped = (f" ({segment_enum.skipped} segment descriptor(s) were dropped as "
                       f"unrepresentable; the requested base may lie inside one of them)")
        return _not_evaluated_result(
            key, capture,
            f"no captured segment contains the requested base "
            f"{requested.base_address:#018x}; the dump holds no bytes to match against"
            + dropped)

    boundary = _targeted.resolve_segment_boundary(
        requested, containing, captured_bytes=capture.captured_bytes)

    rule_files, rules_diag = _yara._resolve_rule_files(context.request.options.rules_dir)
    if not rule_files:
        # No rule survived to be matched, but which rules were CONSIDERED, and
        # why each was unusable, is exactly the provenance an investigator needs
        # to fix the run -- so the compile gap and the RulesProvenance travel
        # with the not-evaluated closure rather than being dropped with it.
        return _not_evaluated_result(
            key, capture, _prerequisite_note(rules_diag),
            limitations=_rule_compile_limitation(rules_diag),
            payload=TargetedYaraEvidence(
                matches=(), diagnostics=None, rules=rules_diag,
                containing_segment=boundary.containing_target))

    # Two independent context sources decide whether a scoped or
    # PE_In_Private_Memory hit is really in unbacked memory -- the same sources
    # the full-scope builder threads in, resolved against the same real module
    # and region tables.
    #
    # The judgement is anchored per string instance rather than at the scanned
    # range's base: a requested range can span several MemoryInfo regions, and
    # a rule matching inside a private one must not be discarded because the
    # range happens to begin in a loaded module.
    modules_available = bool(mf.modules and mf.modules.modules)
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    config = dataclasses.replace(_yara._yara_config(), max_seg_scan=_CAP_BYPASS)
    runtime = HunterRuntime(monotonic=_yara.time.monotonic)
    scan_result = scanner.scan_segments(
        mf, [boundary.slice_segment], rule_files, modules, regions,
        modules_available, mem_info_available, config, runtime.monotonic,
        hit_addresses=scanner.string_instance_addresses)
    diag = scan_result.diagnostics

    # The scanner reads the slice exactly once, so its cumulative
    # total_bytes_scanned IS this run's read length. Clamped to the captured
    # prefix: a read that somehow over-served past what the dump's own segment
    # table backs must not be recorded as evidence the dump does not hold.
    read_bytes = min(diag.total_bytes_scanned, capture.captured_bytes)
    read_slice = (None if capture.state == CaptureState.NONE
                  else capture.read_input(read_bytes))

    status = _coverage_status(diag, rules_diag, scan_result.matches, capture.state,
                              truncated=boundary.truncated)
    reached = status != "not_evaluated"

    # A negative over an ambiguous capture is "not found in the bytes that were
    # searched", not "not found after a full search": the dump's segment table
    # places one or more requested addresses at more than one file offset, so
    # the analyzed bytes are one arbitrary choice among conflicting claims.
    search_incomplete = ("overlapping_capture",) if reached and capture.overlapping else ()
    if search_incomplete and status == "complete":
        status = "partial"

    # Only a stop INSIDE the slice leaves an unexamined suffix this closure has
    # to name here: bytes past the containing segment's end were never in this
    # scan's scope at all and are already reported by the truncation
    # limitation. When the scan did stop short, the suffix runs from where the
    # read stopped through the end of the whole request.
    stopped_short = read_slice is not None and read_slice.read_bytes < boundary.eval_range.size
    unexamined = _targeted.unexamined_suffix_target(read_slice) if stopped_short else None
    # The suffix REPLACES a budget limitation's target only when the budget
    # stopped the scan before a single byte was read, because only then is the
    # suffix the whole of what that budget left unexamined. Once bytes were
    # read, the rules that did not finish over the read prefix are unresolved
    # too, so the scanner's own whole-slice target is the honest superset and
    # the suffix stays where it belongs -- on the short-read gap.
    budget_targets = ([unexamined] if unexamined is not None and read_slice.read_bytes == 0
                      else [])
    truncation_limitation = (
        _targeted.evaluation_truncated_limitation(
            TARGETED_SOURCE, None, boundary)
        if boundary.truncated and reached else None)
    limitations = _limitations(
        diag, rules_diag, scan_result.matches,
        truncation_limitation=truncation_limitation, budget_targets=budget_targets,
        search_incomplete=search_incomplete)

    diagnostics = []
    if boundary.truncated and reached:
        diagnostics.append(_targeted.truncation_diagnostic(
            boundary.segment_range, requested, boundary.eval_range, unit="segment"))
    if boundary.sub_segment and reached:
        diagnostics.append(_targeted.sub_segment_diagnostic(
            boundary.segment_range, requested))
    if unexamined is not None:
        diagnostics.append(
            f"[{unexamined.base_address:#018x}, "
            f"{unexamined.base_address + unexamined.size:#018x}) of the requested range "
            f"never reached a match() call")
    if "overlapping_capture" in search_incomplete:
        diagnostics.append(
            "the dump's segment table maps one or more requested virtual addresses to "
            "multiple file offsets (overlapping segments); the matched bytes are one "
            "arbitrary choice among conflicting claims")

    closure = ObservationClosure(
        source=TARGETED_SOURCE, coverage_status=status, capture_state=capture.state,
        captured_bytes=capture.captured_bytes,
        read_slice=read_slice if reached else None,
        limitations=limitations, diagnostics=tuple(diagnostics))
    payload = TargetedYaraEvidence(
        matches=scan_result.matches, diagnostics=diag, rules=rules_diag,
        containing_segment=boundary.containing_target)
    return ObservationResult(key=key, closures=(closure,), payload=payload)


def project_targeted_report(context, result) -> "_yara.domain.YaraReport":
    """The :class:`~dumpex.hunt.yara_hunt.domain.YaraReport` behind one
    targeted rescan's :class:`~dumpex.output.records.HunterRecord`.

    The rescan's own matches, scan diagnostics, and rules provenance are fed
    to the SAME ``aggregate.build_report`` full scope uses, so a targeted
    verdict is scored, classified, and rendered by one authority rather than a
    parallel targeted-only rule. The report describes one slice: its coverage
    snapshot is the slice's, never the dump's, and the record's own
    document-level coverage is rebuilt from the observation's closures (see
    :mod:`dumpex.hunt._targeted_record`).

    ``context`` is unused here -- YARA's report needs no dump-wide stream fact
    beyond what the adapter already resolved -- and is accepted so every
    analyzer's projector has the one registered call shape.
    """
    payload = result.payload
    if payload is None:
        # No captured segment held the requested base: nothing was matched
        # and no rules diagnostics were resolved, which is exactly the empty
        # report's own "never evaluated" shape.
        return domain.YaraReport()
    # A prerequisite that stopped the rescan before the matcher ran still goes
    # through `aggregate.build_report` -- an empty scan rather than a second
    # place this analyzer's report is constructed, so a derived field added to
    # `YaraReport` later cannot appear on one path and not the other. The
    # candidate rules that WERE considered travel with it, so the report's
    # console/JSON projection still names them.
    diagnostics = (payload.diagnostics if payload.diagnostics is not None
                   else domain.ScanDiagnostics())
    return _yara.aggregate.build_report(
        scanner.ScanResult(matches=payload.matches, diagnostics=diagnostics),
        payload.rules)
