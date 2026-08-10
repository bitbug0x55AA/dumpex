"""`InjectionReport` -> console lines pure projector -- this is now the
ONE console renderer for the injection hunter (the pre-2C-cutover
`dumpex.hunt.injection.presentation.render()`, which conflated printing,
legacy-dict projection, and rendering off the old dict-`Report`, has been
deleted). This module never prints (returns the exact lines a caller would
print) and never returns a legacy-dict projection (see `report_legacy.py`
for that, an independent pure function of the SAME `InjectionReport`);
`dumpex.hunt.injection._render_injection_console()` (in
`dumpex/hunt/injection/__init__.py`) composes `print_console()` below with
`report_legacy.project_legacy_dict()` for callers that need both.

Reproduces the approved verdict-first structure the old `presentation.py`
implemented, byte-for-byte for the same underlying facts (verdict block ->
KEY SIGNALS -> WHY THIS VERDICT (normal only) -> unified COVERAGE ->
verbose hint) -- see tests/hunt/test_injection_projectors.py's golden-
scenario parity test, which diffs this module's output against
tests/fixtures/hunt_cli_golden/injection_console.txt/
injection_verbose_console.txt for an equivalent scenario.

This is also the one place this hunter's normal/verbose CONSOLE detail
POLICY lives: `report_facts.finding_from_check_result` builds a compat
`Finding` carrying only wire-shaped `facts` (never `verbose_facts` -- see
that module's own docstring for why); `_console_finding` below is what
augments it with `verbose_facts` for the three checks whose evidence type
has a richer, uncapped --verbose rendering, entirely locally, so
`report_legacy.py`/`report_record.py` never execute this policy at all.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_LEAD,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    header_lines, sorted_for_display, render_key_signal_compact,
    render_why_this_verdict, render_coverage, with_verbose_facts,
)
from dumpex.hunt.injection.domain import InjectionReport
from dumpex.hunt.injection.report_facts import finding_from_check_result, project_coverage_v1


# ── Verbose-only evidence-item fact rendering (console policy only) ──────
# Byte-identical to aggregate.py's own _rwx_verbose_fact/
# _hidden_pe_verbose_fact/_unbacked_thread_verbose_fact -- see
# report_facts.py's own fact-string builders for why these are duplicated
# rather than imported from aggregate.py.

def _rwx_verbose_fact(ev) -> str:
    r, location = ev.region, ev.location
    fo_str = f"0x{location.file_offset:x}" if location.file_offset is not None else "(not captured)"
    return (f"VA (process)=0x{r.base_address:016x} size=0x{r.size:x} "
            f"AllocationBase=0x{r.allocation_base:016x} File_offset={fo_str} "
            f"{r.protect} {r.type}")


def _hidden_pe_verbose_fact(ev) -> str:
    r, pe, location = ev.region, ev.pe, ev.location
    fo_str = f"0x{location.file_offset:x}" if location.file_offset is not None else "(not captured)"
    return (f"VA (process)=0x{r.base_address:016x} AllocationBase=0x{r.allocation_base:016x} "
            f"File_offset={fo_str} Page_type={r.type} {r.protect} "
            f"PE_machine={pe.machine_name} PE_sections={pe.number_of_sections} "
            f"Entry_point_RVA=0x{pe.address_of_entry_point:x} "
            f"Declared_ImageBase=0x{pe.image_base:x}")


def _unbacked_thread_verbose_fact(ev) -> str:
    fo_str = f"0x{ev.location.file_offset:x}" if ev.location.file_offset is not None else "(not captured)"
    return (f"TID=0x{ev.thread_id:x} StartAddress_VA=0x{(ev.start_address or 0):016x} "
            f"File_offset={fo_str}")


# Only these three checks carry the richer, uncapped --verbose detail --
# see aggregate.py's own _rwx_verbose_fact/_hidden_pe_verbose_fact/
# _unbacked_thread_verbose_fact comment for why the other checks don't.
_VERBOSE_ITEM_RENDERERS = {
    "injection.rwx_regions":                  _rwx_verbose_fact,
    "injection.hidden_pe_validated":          _hidden_pe_verbose_fact,
    "injection.unbacked_thread_startaddress": _unbacked_thread_verbose_fact,
}


def _verbose_facts_for(result) -> tuple:
    """Uncapped, only for the three checks with a richer verbose
    rendering (see `_VERBOSE_ITEM_RENDERERS`); every other check gets no
    verbose_facts, matching aggregate.py's own Finding(...) calls, which
    simply never pass verbose_facts= for those checks."""
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check)
    if renderer is None:
        return ()
    return tuple(renderer(item) for item in result.evidence)


def _console_finding(result, report: InjectionReport):
    """The compat `Finding` `report_facts.finding_from_check_result`
    builds, augmented with `verbose_facts` -- this module's own
    normal/verbose detail policy (see this module's own docstring)."""
    finding = finding_from_check_result(result, report)
    return with_verbose_facts(finding, _verbose_facts_for(result))


_TITLES = {
    "injection.rwx_regions":                        "RWX memory",
    "injection.hidden_pe_validated":                 "Hidden PE header",
    "injection.hidden_pe_validated_context_only":    "Hidden PE header (context-only)",
    "injection.mz_prefix_unvalidated":               "Unvalidated MZ prefix",
    "injection.unbacked_thread_startaddress":        "Unbacked thread start",
    "injection.rip_correlation_unavailable":         "RIP/EIP correlation unavailable",
    "injection.allocation_correlation":              "Live execution in a correlated allocation",
    "injection.structural_allocation_correlation":   "RWX and hidden PE share an allocation",
}

_COVERAGE_ONLY_CHECKS = frozenset({"injection.rip_correlation_unavailable"})


def _coverage_only_impacts(findings: list, coverage_reasons: list) -> list:
    seen = set(coverage_reasons)
    impacts = []
    for f in findings:
        if f.check not in _COVERAGE_ONLY_CHECKS:
            continue
        for limitation in f.limitations:
            if limitation not in seen:
                seen.add(limitation)
                impacts.append(limitation)
    return impacts


def _render_verdict_block(status: str, score: int, max_score: int, confidence: str,
                           coverage_status: str, review_priority: str,
                           findings: list) -> list:
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "no required stream present in this dump")
    else:
        verdict_text = (
            RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
            YELLOW("LIKELY INJECTION") if score == 2 else
            YELLOW("POSSIBLE INJECTION") if score == 1 else
            GREEN("CLEAN" + leads_suffix(findings)) if status == NOT_DETECTED_IN_SCANNED_SCOPE else
            YELLOW("INCONCLUSIVE — partial stream coverage" + leads_suffix(findings)))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", confidence),
        ("Score",      f"{score}/{max_score}"),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def render_console_lines(report: InjectionReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `InjectionReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value. `render_console_lines(report, False)` and
    `render_console_lines(report, True)` may be called in either order (or
    repeatedly) against the SAME `report` with no effect on each other, on
    `report` itself, or on `report_legacy.project_legacy_dict`/
    `report_record.project_hunter_record`'s output for that `report`."""
    findings = [_console_finding(r, report) for r in report.results]
    coverage_dict, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(header_lines("Process Injection"))

    lines.extend(_render_verdict_block(report.status, report.score, report.max_score,
                                        report.confidence, coverage_status,
                                        report.review_priority, findings))
    lines.append("")

    ordered = sorted_for_display(findings, exclude_checks=_COVERAGE_ONLY_CHECKS)
    if ordered:
        lines.append(f"  {BOLD('KEY SIGNALS')}")
        lines.append("")
        for f in ordered:
            if verbose:
                title = _TITLES.get(f.check, f.check)
                lines.extend(render_finding_lines(f, level=level, indent=2, width=w, title=title))
            else:
                lines.extend(render_key_signal_compact(f, w, _TITLES))
                lines.append("")

    if not verbose:
        driving = ordered[0] if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD) else None
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    if coverage_reasons:
        impacts = _coverage_only_impacts(findings, coverage_reasons)
        lines.extend(render_coverage(coverage_status, coverage_reasons, w, impacts))

    evidence = report.evidence
    if not verbose and (evidence.rwx or evidence.validated_pe_hits or evidence.start_threads):
        lines.append(DIM("  Use --verbose for complete per-region evidence and file offsets.\n"))

    return lines


def print_console(report: InjectionReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns. Never the target of a test or of the
    other two projectors' parity checks; `render_console_lines` itself is."""
    for line in render_console_lines(report, verbose):
        print(line)
