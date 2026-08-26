"""Shared projection logic for `HollowingReport` (dumpex/hunt/hollowing/
domain.py) -- everything `report_legacy.py`, `report_record.py`, and
`report_console.py` all three need, so it is built exactly once. Mirrors
`dumpex.hunt.stomping.report_facts`/`dumpex.hunt.pipe.report_facts`/
`dumpex.hunt.injection.report_facts`/`dumpex.hunt.encoding.report_facts`
(the four completed reference pilots): see those modules' own docstrings
for why `verbose_facts` is deliberately never populated here (that policy
belongs to `report_console.py` alone).

Every fact string below is written to match the pre-migration
`_build_hollowing_report()`'s own `Finding.facts` text byte-for-byte for
the same evidence -- these arrays are embedded verbatim in BOTH the v1.1
findings dict and the typed `HunterRecord` (and feed `Finding.id`'s hash
basis), and tests/fixtures/hunt_cli_golden/hollowing_hunt_dict.json is
frozen against them. Verified by tests/hunt/test_hollowing_projectors.py's
own fact-text parity test.

This module owns no dependency on `dumpex.hunt.hollowing.aggregate`:
`build_report()` is the ONE place a `HollowingReport` is constructed, and
this module stays a pure function of that already-built Report.
"""
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.hunt._finding import Finding
from dumpex.hunt.hollowing.config import HEADER_PREVIEW_BYTES
from dumpex.hunt.hollowing.domain import (
    CoverageSnapshot, HollowingReport, PEB_MISSING_REASON,
)
from dumpex.output.coverage import (
    CoverageReport, EvaluationRequirement, LimitationCode, SourceObservation,
    SourceRequirement, SourceState, build_coverage_report, observe_source,
)


def header_preview(header_bytes: bytes) -> str:
    """The leading `config.HEADER_PREVIEW_BYTES` of a header read, as hex --
    the pre-migration `header[:8].hex()`, named once because BOTH the wire
    fact (`hollowing.mz_header_missing`) and the console's own image-base
    evidence block quote it, and they must quote the same bytes."""
    return header_bytes[:HEADER_PREVIEW_BYTES].hex()


def file_offset_text(file_offset) -> str:
    """"(not captured)" for None -- the bytes were never written to the
    .dmp at all, which an investigator needs to tell apart from "offset
    zero" (an ordinary, valid offset). Same wording every other migrated
    hunter's own facts use."""
    return f"0x{file_offset:x}" if file_offset is not None else "(not captured)"


# ── Fact-string builders -- byte-identical to the pre-migration builder ───

def _mem_private_fact(ev, report: HollowingReport) -> str:
    return (f"VA=0x{ev.region.base_address:x} type={ev.region.type} "
            f"protect={ev.region.protect}")


def _wiped_header_fact(ev, report: HollowingReport) -> str:
    return f"VA=0x{ev.image_base:x} header_bytes={header_preview(ev.header_bytes)}"


def _rwx_fact(ev, report: HollowingReport) -> str:
    return f"VA=0x{ev.region.base_address:x} protect={ev.region.protect}"


def _name_mismatch_fact(ev, report: HollowingReport) -> str:
    # `module_list_match` is the pre-migration `bool(main_mod)` -- True when
    # the module list DID attribute this base to a module (and the names
    # simply disagreed), False when the base is in no module at all.
    return (f"PEB_image_path={ev.image_path!r} "
            f"module_list_match={ev.module is not None}")


def _correlation_fact(ev, report: HollowingReport) -> str:
    return f"VA=0x{ev.image_base:x} " + " + ".join(ev.corroborators)


_FACT_ITEM_RENDERERS = {
    "hollowing.mem_private_at_image_base": _mem_private_fact,
    "hollowing.mz_header_missing":         _wiped_header_fact,
    "hollowing.rwx_at_image_base":         _rwx_fact,
    "hollowing.peb_module_name_mismatch":  _name_mismatch_fact,
    "hollowing.structural_correlation":    _correlation_fact,
}


def _facts_for(result, report: HollowingReport) -> tuple:
    """`CheckResult.facts`'s replacement -- rendered from `result.evidence`
    (capped at `result.evidence_limit`, with a "... and N more" summary line
    when the cap trims anything, matching every other migrated hunter).

    No hollowing check sets `evidence_limit` at all: each of the five is
    anchored on the ONE image base the PEB reports and therefore carries
    exactly one evidence item, so there is nothing to cap. The cap handling
    is kept anyway rather than special-cased away -- it is the shared
    contract `CheckResult.evidence_limit` defines, and a future check that
    did enumerate would otherwise silently truncate without saying so.
    """
    renderer = _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        raise ValueError(
            f"report_facts: no fact renderer registered for check {result.check!r} -- "
            f"every hollowing check id must have one (see _FACT_ITEM_RENDERERS)")
    items = result.evidence
    limit = result.evidence_limit
    shown = items if limit is None else items[:limit]
    facts = [renderer(item, report) for item in shown]
    if limit is not None and len(items) > limit:
        facts.append(f"... and {len(items) - limit} more")
    return tuple(facts)


def finding_from_check_result(result, report: HollowingReport) -> Finding:
    """The transient compatibility `Finding` for one `CheckResult` -- built
    fresh on every call, never stored anywhere. Carries no `verbose_facts`
    -- that is `report_console.py`'s own normal/verbose detail policy to
    apply, not a wire-shaped fact every projector needs."""
    return Finding(
        check=result.check,
        facts=list(_facts_for(result, report)),
        inference=result.inference,
        confidence=result.confidence,
        rationale=result.rationale,
        limitations=list(result.limitations),
        tag=result.tag,
        technique_ids=list(result.technique_ids),
        evidence_refs=list(result.evidence_refs),
        iocs=list(result.iocs),
        rule_id=result.rule_id,
        rule_version=result.rule_version,
    )


# ── Coverage projections ──────────────────────────────────────────────────

def project_coverage_v1(coverage: CoverageSnapshot) -> tuple:
    """`(coverage_status, coverage_reasons)` -- the v1.1 shape the
    pre-migration builder assembled inline, reproduced fact-for-fact from
    `CoverageSnapshot`'s own named fields.

    A two-element tuple, not the three-element `(coverage_counts,
    coverage_status, coverage_reasons)` stomping's own projector returns:
    the hollowing hunter's v1.1 findings dict has never carried a
    `coverage_counts` mapping, and inventing one here would be a public
    schema change this migration explicitly does not make.

    Reason ORDER is part of the output contract and is preserved exactly.
    The PEB's absence is its OWN single reason rather than the first of a
    list: when the PEB is missing, none of the three per-check gaps below
    was ever reached, so reporting them would describe checks that were
    never attempted (see `CoverageSnapshot.gap_reasons`' own docstring).
    """
    if not coverage.peb_present:
        reasons = [PEB_MISSING_REASON]
    else:
        reasons = list(coverage.gap_reasons())
    coverage_status = derive_coverage_status(coverage.evaluated, coverage.complete)
    return coverage_status, reasons


def project_coverage_report(coverage: CoverageSnapshot) -> CoverageReport:
    """The structured `dumpex.output.coverage.CoverageReport` for a
    hollowing run -- built at each gap site `project_coverage_v1` above
    already derives coverage_status/coverage_reasons from (never parsed back
    out of that free text; see docs/developer/hunt_architecture.md's
    structured-facts ownership rule). The returned report is the authoritative
    coverage value consumed by structured and console projectors
    attribute.

    The two branches are genuinely different reports, not one report with
    optional parts:

      PEB ABSENT -- matches v2.12's now-retired
        `dumpex.commands.peb.collect_peb()`'s own PEB_UNAVAILABLE
        precedent exactly. That command's own docstring explained
        why this needs a dedicated code rather than the automatic
        single-source SOURCE_ABSENT default: "PEB could not be parsed
        (missing sysinfo or thread list in dump)" doesn't fit the generic
        "X not present in this dump" template.

      PEB PRESENT -- `peb` itself is the sole `evaluation_sources` gate and
        is deliberately NOT repeated as a completeness_check: per
        `build_coverage_report()`'s own docstring that group short-circuits
        to NOT_EVALUATED before completeness_checks are ever consulted, so
        listing it again would only ever matter for a state this branch is
        never reached in. `image_base_region`/`mz_header_read` are synthetic
        sources (not real minidump streams) purely so PE-style per-check
        gaps have a source key to attach a limitation to -- the same pattern
        injection's own `hidden_pe_scan` source uses.
    """
    if not coverage.peb_present:
        sources = {"peb": observe_source("peb", present=False)}
        return build_coverage_report(
            sources,
            evaluation_sources=EvaluationRequirement(
                sources=("peb",), all_absent_code=LimitationCode.PEB_UNAVAILABLE),
        )

    sources = {
        "peb": observe_source("peb", present=True, items=["present"]),
        "image_base_region": observe_source(
            "image_base_region", present=coverage.image_base_region_found,
            items=["found"] if coverage.image_base_region_found else []),
        # FAILED, not ABSENT: the read was attempted at a known address and
        # came back unusable, which is a different fact from "this dump has
        # no such source at all".
        "mz_header_read": (SourceObservation(name="mz_header_read", state=SourceState.FAILED)
                           if coverage.mz_read_failed else
                           observe_source("mz_header_read", present=True, items=["read"])),
        "modules": observe_source(
            "modules", present=coverage.modules_available,
            items=["present"] if coverage.modules_available else []),
    }
    completeness_checks = [
        "image_base_region",
        "mz_header_read",
        SourceRequirement(source="modules",
                          absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
    ]
    return build_coverage_report(
        sources, evaluation_sources=("peb",), completeness_checks=completeness_checks)
