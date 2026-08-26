"""Project a ``HollowingReport`` into the current ``HunterRecord``.

Each detail is ``None`` when its check could not run, rather than ``False``;
unavailable regions, failed header reads, and missing module data must not
be represented as clean observations.
"""
from dumpex.hunt.hollowing.domain import HollowingReport
from dumpex.hunt.hollowing.report_facts import finding_from_check_result, project_coverage_report
from dumpex.output.records import HunterRecord, HollowingDetails, hex_address


def _details(report: HollowingReport) -> HollowingDetails:
    context = report.context
    if context is None:
        # PEB absent: there is no image base to report at all -- the one
        # `HunterRecord` in this codebase whose details are entirely null
        # (see HollowingDetails' own docstring).
        return HollowingDetails(
            image_base=None, mem_private_at_base=None, mz_header_present=None,
            is_rwx_at_base=None, peb_image_path=None, module_name=None,
            name_mismatch=None)

    # Checks 1 and 3 both need the image-base region: with no region
    # captured neither ran, so both are null rather than False.
    if context.region is not None:
        mem_private_at_base = bool(report.evidence.mem_private)
        is_rwx_at_base = bool(report.evidence.rwx)
    else:
        mem_private_at_base = None
        is_rwx_at_base = None

    # Check 4 ran only if the module list was available at all: without it
    # `addr_to_module()` returns None for every address, so "no mismatch"
    # would be a claim about a comparison that never happened.
    name_mismatch = (bool(report.evidence.name_mismatches)
                     if report.coverage.modules_available else None)

    return HollowingDetails(
        image_base=hex_address(context.image_base),
        mem_private_at_base=mem_private_at_base,
        # None when the read failed (short read or exception) -- see
        # models.HeaderRead.header_present, which owns that tri-state.
        mz_header_present=context.header.header_present,
        is_rwx_at_base=is_rwx_at_base,
        peb_image_path=context.peb_image_path,
        # `or None`, not just the bare name: `ModuleRef.name` coerces a
        # module whose own recorded path was None to "" (a str field on an
        # identity snapshot), and the wire contract's `str | None` means
        # null for "no recorded name", never an empty string.
        module_name=(context.module.name or None) if context.module is not None else None,
        name_mismatch=name_mismatch,
    )


def project_hunter_record(report: HollowingReport) -> HunterRecord:
    """Pure `HollowingReport` -> `HunterRecord` conversion -- no scanning,
    no printing."""
    findings_list = [finding_from_check_result(r, report) for r in report.results]

    return HunterRecord(
        hunter="hollowing", status=report.status, score=report.score,
        max_score=report.max_score, verdict_level=report.verdict_level,
        confidence=report.confidence, lead_count=report.lead_count,
        review_priority=report.review_priority,
        coverage=project_coverage_report(report.coverage),
        findings=[f.to_dict() for f in findings_list], details=_details(report),
    )
