"""Targeted stomping rescan: the unscored IOC-string scan over one range.

A targeted ``--hunt-addr`` stomping invocation asks the region scanner to
extract strings from one investigator-selected half-open virtual-address range
and match them against the IOC pattern sets. :func:`run_targeted_stomping` is
the executor the analyzer registry resolves as ``stomping``'s
``AnalyzerSpec.targeted_adapter`` (through the
``dumpex.hunt._run_targeted_stomping`` facade seam).

Only ``IOC_SCAN_MAX`` is bypassed, and only for this one range. Nothing else
about the scan changes: the same rules-file pattern sets, the same whitelist
decision (a range attributed to a whitelisted network DLL is still scanned
without the network-IOC set -- reported here as
``SCAN_REGION_SEARCH_INCOMPLETE``/``pattern_set_withheld``, since a closure
that applied fewer patterns cannot carry a full-search negative), the same
weak-token demotion, and the same absolute VA resolution per hit.

The IOC scan has no retained-evidence budget of the kind pipe, obfuscation, and
CS Beacon each carry: :func:`~dumpex.core.memory._extract_ioc_strings`
materializes one decoded string per printable run and ``_classify_ioc_hits``
retains one hit per match, both unquota'd. Full scope bounds that per region at
``IOC_SCAN_MAX``; this executor is the first caller able to hand a single scan
the whole 256 MiB request ceiling, so peak memory for a printable, IOC-dense
range scales with the range rather than with the cap.

Source eligibility and evaluation are anchored to the ``MemoryInfo`` region
containing the requested base -- committed ``MEM_IMAGE`` with executable
protection, exactly as full-scope. A request that runs past that region's end
is captured in full but evaluated only up to the boundary, and the closure is
``partial`` with ``SCAN_REGION_EVALUATION_TRUNCATED``. A request lying wholly
inside a larger allocation carries a diagnostic naming that allocation, because
a string spanning either requested boundary is examined by neither this rescan
nor the bytes around it.

The result is one :class:`~dumpex.hunt._observation.ObservationResult` with a
single ``ioc_string_scan`` closure and a :class:`TargetedStompingEvidence`
payload. That closure speaks for the IOC source ALONE. Module registration, PE
header parsing, reference-file comparison, executable-section checks, and the
relocation-normalized content diff are independent stomping coverage sources
this executor does not evaluate; a clean IOC closure never asserts that
stomping as a whole was ruled out for the range.
"""
import dataclasses

from dumpex.core import va_range
from dumpex.core.memory import get_modules, read_region_spanning
from dumpex.core.va_range import CaptureState
from dumpex.rules_pkg.loader import get_rules

import dumpex.hunt.stomping as _stomping
from dumpex.hunt import _registry, _targeted
from dumpex.hunt._observation import ObservationClosure, ObservationResult
from dumpex.hunt.stomping import memory_scan
from dumpex.output.coverage import CoverageLimitation, LimitationCode

__all__ = [
    "run_targeted_stomping", "project_targeted_report",
    "TargetedStompingEvidence", "TargetedStompingError",
    "ALGORITHM_VERSION", "TARGETED_SOURCE",
]

# The observation-key algorithm identity for this executor -- bumped only when
# a change to which bytes reach string extraction would make a cached result
# from an earlier version unsafe to reuse.
ALGORITHM_VERSION = "stomping-targeted/1"

# The one granted coverage source (the capability matrix grants `stomping`
# exactly `ioc_string_scan`, with no finer subdivision, so the closure carries
# no scope).
TARGETED_SOURCE = "ioc_string_scan"

# Raised in place of `IOC_SCAN_MAX`. Far above the 256 MiB stomping request
# ceiling, so no range inside a valid targeted request is ever skipped for
# size -- and nothing here is a buffer allocation, only a `RegionSize > cap`
# comparison.
_CAP_BYPASS = 1 << 40


class TargetedStompingError(Exception):
    """The context handed to :func:`run_targeted_stomping` is not a legal
    stomping targeted request. Raised before any dump read, so the
    ``dumpex.hunt._run_targeted_stomping`` monkeypatch seam cannot route
    another analyzer's request into this executor and past its own request
    ceiling."""


@dataclasses.dataclass(frozen=True)
class TargetedStompingEvidence:
    """The scan results behind one targeted ``ObservationResult`` -- carried as
    its ``payload`` so a consumer can render what the rescan found.

    ``hits`` is the scanner's tuple of
    :class:`~dumpex.hunt.stomping.models.IocHitEvidence` -- one entry when the
    range held at least one strong (non-weak) IOC token, each token carrying
    its own absolute ``va``. ``weak_only_regions`` is 1 when every token the
    range produced was a weak/common-API one, which is deliberately not
    surfaced as a lead. ``coverage`` is the frozen
    :class:`~dumpex.hunt.stomping.models.IocCoverage` the closure was derived
    from. ``containing_region`` is the
    :class:`~dumpex.output.coverage.ScanTarget` for the allocation the
    requested range was evaluated inside -- distinct from the requested range
    and from any hit address, so a consumer can tell whether a full-region
    closure is licensed."""
    hits: tuple
    weak_only_regions: int
    coverage: object
    containing_region: object


def _validate_request(request) -> None:
    """Fail closed unless ``request`` is a stomping ``ioc_string_scan``
    targeted request covering exactly the granted (empty) scope set."""
    if not getattr(request, "is_targeted", False):
        raise TargetedStompingError(
            "run_targeted_stomping requires a targeted HuntRequest")
    if request.selected != "stomping" or request.targeted_source != TARGETED_SOURCE:
        raise TargetedStompingError(
            f"run_targeted_stomping is stomping/{TARGETED_SOURCE} only, got "
            f"{request.selected!r}/{request.targeted_source!r}")
    granted = _registry.REGISTRY.granted_scopes("stomping", TARGETED_SOURCE)
    if request.targeted_scopes != granted:
        raise TargetedStompingError(
            f"a stomping targeted request covers exactly {sorted(granted)}, got "
            f"{sorted(request.targeted_scopes)}")


def _not_evaluated_result(key, capture, note: str, payload=None) -> ObservationResult:
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
            diagnostics=(note,)),),
        payload=payload)


def _unreconciled(cov) -> int:
    return cov.unaccounted + cov.over_accounted + cov.ledger_imbalance


def ioc_region_ineligible_reason(region) -> "str | None":
    """Why ``scan_ioc_strings``'s descriptor gate declines this target, or
    ``None`` when it accepts it -- a statement of that loop's own filters, in
    the vocabulary ``LimitationCode.TARGETED_SOURCE_NOT_APPLICABLE`` renders.

    ``region`` is a :class:`~dumpex.core.va_range.CapturedRegion`, whose
    state/type/protection strings are already resolved."""
    if region.state != "MEM_COMMIT":
        return "region_not_committed"
    if "MEM_IMAGE" not in region.type:
        return "region_type_ineligible"
    if "EXECUTE" not in region.protection:
        return "region_protection_ineligible"
    return None


def _coverage_status(cov, capture_state: CaptureState, *,
                     ineligible_reason: "str | None", truncated: bool) -> str:
    """This closure's honest ``coverage_status``.

    ``not_applicable`` -- the containing region is not committed executable
    ``MEM_IMAGE``, which is the whole population this source examines. Nothing
    here was missed, and no re-collection or narrower request would change
    that.

    ``not_evaluated`` -- the range would have been examined and was not: the
    read returned nothing.

    Otherwise ``partial`` on any gap -- a short capture, evaluation stopped at
    the containing region's end, a short read, a size skip, or a ledger that
    does not balance -- and ``complete`` only when the whole requested range
    was captured and the scan got through all of it. Extracting strings and
    legitimately matching no IOC token is a result, not a gap.
    """
    if ineligible_reason is not None:
        return "not_applicable"
    if not cov.scanned:
        return "not_evaluated"
    if capture_state != CaptureState.COMPLETE or truncated:
        return "partial"
    if (cov.short_reads or cov.skipped_oversize_targets or cov.read_failed
            or _unreconciled(cov)):
        return "partial"
    return "complete"


def _limitations(cov, *, truncation_limitation, search_incomplete: tuple) -> tuple:
    """The structured gaps for the closure -- the same ``CoverageLimitation``
    shapes ``report_facts.project_coverage_report`` builds for a full-scope
    stomping IOC scan, over this one range."""
    out = []
    if cov.skipped_oversize_targets:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source=TARGETED_SOURCE,
            affected_count=len(cov.skipped_oversize_targets),
            targets=list(cov.skipped_oversize_targets)))
    if cov.read_failed:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source=TARGETED_SOURCE,
            affected_count=cov.read_failed, targets=list(cov.read_failed_targets)))
    if cov.short_reads:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source=TARGETED_SOURCE,
            affected_count=cov.short_reads, targets=list(cov.short_read_targets)))
    if truncation_limitation is not None:
        out.append(truncation_limitation)
    unreconciled = _unreconciled(cov)
    if unreconciled:
        # No `targets` -- see SCAN_ITEMS_UNACCOUNTED on LimitationCode for why
        # this gap cannot name what it lost.
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_ITEMS_UNACCOUNTED, source=TARGETED_SOURCE,
            affected_count=unreconciled))
    for detail in search_incomplete:
        out.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SEARCH_INCOMPLETE, source=TARGETED_SOURCE,
            detail=detail, affected_count=1))
    return tuple(out)


def run_targeted_stomping(context) -> ObservationResult:
    """Scan ``context.request.target_range`` for IOC-pattern strings and return
    one :class:`~dumpex.hunt._observation.ObservationResult` with a single
    ``ioc_string_scan`` closure and a :class:`TargetedStompingEvidence`
    payload.

    ``context`` is a targeted :class:`~dumpex.hunt._execution.HuntExecutionContext`.
    Raises :class:`TargetedStompingError` for any other request shape, before
    any dump read.
    """
    _validate_request(context.request)

    mf = context.mf
    requested = context.request.target_range
    key = context.observation_key("stomping", algorithm_version=ALGORITHM_VERSION)

    capture = context.capture_of(requested)
    region_enum = context.captured_region_enumeration()
    containing = va_range.region_containing(requested.base_address, region_enum.views)

    if containing is None:
        dropped = ""
        if region_enum.skipped:
            dropped = (f" ({region_enum.skipped} region descriptor(s) were dropped as "
                       f"unrepresentable; the requested base may lie inside one of them)")
        return _not_evaluated_result(
            key, capture,
            f"no representable MemoryInfoListStream region contains the requested base "
            f"{requested.base_address:#018x}; source eligibility could not be established"
            + dropped)

    boundary = _targeted.resolve_region_boundary(mf, requested, containing)
    eval_range = boundary.eval_range

    # One read of the requested (clipped) bytes, clamped to the captured prefix
    # the dump's own segment table backs -- the raw reader can over-serve past
    # a descriptor the capture model dropped, and no hit may be retained from
    # bytes the closure then reports as uncaptured. A clamp shorter than the
    # synthetic region's size surfaces to the scanner as an ordinary short read.
    buf = read_region_spanning(
        mf, eval_range.base_address, eval_range.size)[:capture.captured_bytes]
    read_slice = (None if capture.state == CaptureState.NONE
                  else capture.read_input(len(buf)))

    def _reader(_mf, addr, size):
        if addr == eval_range.base_address:
            return buf[:size]
        return b""

    modules = get_modules(mf)
    rules = get_rules(announce=False)
    synthetic = _targeted.SyntheticRegion.from_captured_region(
        eval_range.base_address, eval_range.size, containing)

    scan = memory_scan.scan_ioc_strings(
        mf, _reader, [synthetic], modules, rules["stomping_whitelist"],
        rules["stomping_ioc_patterns"], rules["stomping_net_ioc_patterns"],
        scan_max=_CAP_BYPASS)
    cov = scan.coverage

    ineligible_reason = ioc_region_ineligible_reason(containing)
    status = _coverage_status(cov, capture.state, ineligible_reason=ineligible_reason,
                              truncated=boundary.truncated)
    reached = status not in ("not_evaluated", "not_applicable")

    # A negative over an ambiguous capture is "not found in the bytes that were
    # searched", not "not found after a full search": the dump's segment table
    # places one or more requested addresses at more than one file offset, so
    # the searched bytes are one arbitrary choice among conflicting claims.
    search_incomplete = []
    if reached and capture.overlapping:
        search_incomplete.append("overlapping_capture")
    # A range attributed to a whitelisted network DLL is scanned WITHOUT the
    # network IOC pattern set -- expected inside such a module, and unchanged
    # from full scope. But a whole pattern class not being applied is exactly
    # the "searched for fewer indicators than a full scan applies" case, and a
    # targeted closure is the only statement about the range an investigator
    # named by address: it must not read as a clean network-IOC negative.
    if reached and cov.network_ioc_withheld:
        search_incomplete.append("pattern_set_withheld")
    search_incomplete = tuple(search_incomplete)
    if search_incomplete and status == "complete":
        status = "partial"

    truncation_limitation = (
        _targeted.evaluation_truncated_limitation(
            TARGETED_SOURCE, None, boundary)
        if boundary.truncated and reached else None)
    limitations = _limitations(
        cov, truncation_limitation=truncation_limitation,
        search_incomplete=search_incomplete)

    # Only a stop INSIDE the evaluated range leaves an unexamined suffix this
    # closure has to name: bytes past the containing region's end were never in
    # this scan's scope and are already reported by the truncation limitation.
    stopped_short = read_slice is not None and read_slice.read_bytes < eval_range.size
    unexamined = (_targeted.unexamined_suffix_target(read_slice)
                  if stopped_short and reached else None)

    diagnostics = []
    if not reached:
        diagnostics.append(_not_evaluated_note(cov, ineligible_reason))
    if boundary.truncated and reached:
        diagnostics.append(_targeted.truncation_diagnostic(
            boundary.region_range, requested, eval_range))
    if boundary.sub_region and reached:
        diagnostics.append(_targeted.sub_region_diagnostic(
            boundary.region_range, requested))
    if unexamined is not None:
        diagnostics.append(
            f"[{unexamined.base_address:#018x}, "
            f"{unexamined.base_address + unexamined.size:#018x}) of the requested range "
            f"was never examined for an IOC string")
    if "overlapping_capture" in search_incomplete:
        diagnostics.append(
            "the dump's segment table maps one or more requested virtual addresses to "
            "multiple file offsets (overlapping segments); the searched bytes are one "
            "arbitrary choice among conflicting claims")
    if "pattern_set_withheld" in search_incomplete:
        diagnostics.append(
            f"the requested range is attributed to "
            f"{', '.join(sorted(set(cov.network_ioc_withheld)))}, a whitelisted network "
            f"module, so the network IOC pattern set (URLs, IP:port, socket/loader API "
            f"names) was not applied to it; those indicators were not searched for here")

    measurements = _targeted.region_context_measurements(
        boundary, containing, capture, modules) + (
        _targeted.bytes_measurement("bytes_evaluated",
                                    len(buf) if cov.scanned else 0),
    )
    if reached:
        measurements += (
            _targeted.count_measurement("ioc_strings_retained", len(scan.hits)),
            _targeted.count_measurement("weak_only_regions", scan.weak_only_regions),
            _targeted.text_measurement(
                "network_ioc_pattern_set",
                "withheld" if cov.network_ioc_withheld else "applied"),
        )

    closure = ObservationClosure(
        source=TARGETED_SOURCE, coverage_status=status, capture_state=capture.state,
        captured_bytes=capture.captured_bytes,
        read_slice=read_slice if reached else None,
        applicability_reason=ineligible_reason if status == "not_applicable" else None,
        limitations=limitations, measurements=measurements,
        diagnostics=tuple(diagnostics))
    payload = TargetedStompingEvidence(
        hits=scan.hits, weak_only_regions=scan.weak_only_regions, coverage=cov,
        containing_region=boundary.containing_target)
    return ObservationResult(key=key, closures=(closure,), payload=payload)


_INAPPLICABLE_NOTES = {
    "region_not_committed":
        "the MemoryInfo region containing the requested base is not committed memory, so "
        "the IOC-string scan does not apply to it",
    "region_type_ineligible":
        "the MemoryInfo region containing the requested base is not MEM_IMAGE memory, so "
        "the IOC-string scan -- which examines module-backed executable code -- does not "
        "apply to it",
    "region_protection_ineligible":
        "the MemoryInfo region containing the requested base is not executable, so the "
        "IOC-string scan does not apply to it",
}


def _not_evaluated_note(cov, ineligible_reason: "str | None") -> str:
    """Why no conclusion is available -- the eligibility gate that declined the
    target, or, past that gate, the scan's own frozen coverage, so the note and
    the closure's status always name the same cause."""
    if ineligible_reason is not None:
        return _INAPPLICABLE_NOTES[ineligible_reason]
    if cov.read_failed:
        return "the requested range returned no readable bytes; no string was extracted"
    return "the requested range never reached string extraction"


def project_targeted_report(context, result):
    """The :class:`~dumpex.hunt.stomping.domain.StompingReport` behind one
    targeted rescan's :class:`~dumpex.output.records.HunterRecord`.

    The range's own IOC hits and scan coverage are fed to the SAME
    ``aggregate.build_report`` full scope uses, so a targeted result is scored
    and classified by one authority rather than a parallel targeted-only rule.

    Every module-walk input stays empty and ``module_list_stream`` /
    ``ref_dir_supplied`` stay ``False``: a targeted rescan evaluates
    ``ioc_string_scan`` alone, so module registration, PE headers, reference
    files, and section diffs are sources this run did not read -- not sources
    it found clean. Their gaps therefore remain open, exactly as the
    targeted-rescan contract requires of a clean IOC closure.
    """
    payload = result.payload
    evaluated = any(closure.coverage_status != "not_evaluated"
                    for closure in result.closures)
    if payload is None:
        return _stomping.build_report(memory_info_stream=False, module_list_stream=False)
    cov = payload.coverage
    return _stomping.build_report(
        (), (), (), (), (), payload.hits,
        memory_info_stream=evaluated, module_list_stream=False, ref_dir_supplied=False,
        ioc_oversized=cov.skipped_oversize_targets,
        ioc_read_failed=cov.read_failed, ioc_read_failed_targets=cov.read_failed_targets,
        ioc_short_reads=cov.short_reads, ioc_short_read_targets=cov.short_read_targets,
        ioc_unaccounted=cov.unaccounted, ioc_over_accounted=cov.over_accounted,
        ioc_ledger_imbalance=cov.ledger_imbalance,
        ioc_whitelisted_modules=cov.whitelisted_skipped)
