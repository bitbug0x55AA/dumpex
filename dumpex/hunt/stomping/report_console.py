"""Render a ``StompingReport`` as verdict-first console lines.

Verbose output carries bounded scan and evidence detail. Wire facts remain
capped and stable for legacy and structured projections.
"""
import dataclasses

from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_LEAD,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    coverage_kv_value, header_lines, sorted_for_display, render_key_signal_compact,
    render_why_this_verdict, render_coverage, with_verbose_facts,
)
from dumpex.hunt.stomping.domain import StompingReport
from dumpex.hunt.stomping.report_facts import (
    _FACT_ITEM_RENDERERS, finding_from_check_result, project_coverage_report,
    project_coverage_v1,
)
from dumpex.output.records import hex_address


_VERIFIED_CONTENT_CHANGE = "stomping.verified_content_change"
_IOC_STRING_LEAD         = "stomping.ioc_string_lead"


# ── Verbose-only evidence-item fact rendering (console policy only) ──────
# Address-typed fields (`VA`/`va_start`/`va_end`, the `Region` base, and a
# token's absolute `VA`) go through the shared `hex_address()` helper here
# too, so a verbose line renders an address in the same fixed-width,
# zero-padded 16-hex-digit form as the wire fact, the structured record,
# and `--json` `details`. `File_offset`, `size`, `compared` length, and
# the `+0x..` changed-range offsets stay compact.

def _file_offset_text(file_offset) -> str:
    """"(not captured)" for None -- the bytes were never written to the
    .dmp at all, which an investigator needs to tell apart from "offset
    zero" (an ordinary, valid offset). Same wording every other migrated
    hunter's verbose facts use."""
    return f"0x{file_offset:x}" if file_offset is not None else "(not captured)"


def _protection_lead_verbose_fact(ev, report: StompingReport) -> str:
    """The wire-shaped fact plus the two fields --json consumers were
    never meant to need: the section's full VA range and its .dmp file
    offset (where to point --extract/--strings)."""
    return (f"module={ev.module.basename or '(unnamed module)'} "
            f"section={ev.section.name!r} "
            f"VA={hex_address(ev.va_start)}-{hex_address(ev.va_end)} "
            f"File_offset={_file_offset_text(ev.file_offset)} "
            f"Region={hex_address(ev.region.base_address)} size=0x{ev.region.size:x} "
            f"declared={ev.expected} actual={ev.actual} page_type={ev.region.type}")


def _verified_change_verbose_fact(vc, report: StompingReport) -> str:
    """Every differing range (uncapped, unlike the wire fact's own first
    five), the full hashes rather than 16-char prefixes, and the section's
    .dmp file offset."""
    ranges_str = ", ".join(f"+0x{off:x}(len 0x{length:x})" for off, length in vc.diff_ranges)
    if vc.ranges_truncated:
        ranges_str += (f" ({vc.total_ranges} total differing range(s), "
                        f"{len(vc.diff_ranges)} kept for display)")
    live = "  [LIVE RIP/EIP inside changed range]" if vc.rip_in_changed_range else ""
    return (f"module={vc.module.basename or '(unnamed module)'} "
            f"section={vc.section.name!r} VA={hex_address(vc.va_start)} "
            f"File_offset={_file_offset_text(vc.file_offset)} "
            f"compared={vc.compared_len} bytes changed_ranges=[{ranges_str}] "
            f"disk_sha256={vc.disk_sha256} mem_sha256={vc.mem_sha256}{live}")


_VERBOSE_ITEM_RENDERERS = {
    "stomping.protection_deviation_lead": _protection_lead_verbose_fact,
    "stomping.verified_content_change":   _verified_change_verbose_fact,
}


def _ioc_verbose_fact(ev) -> list:
    """Per-TOKEN detail (absolute VA, string encoding, weak/common-API
    classification) the wire-shaped fact never carries: that one dedupes to
    a single entry per REGION with a capped, deduped term list, built for
    --json. Byte-identical to the pre-migration aggregate.py's own
    `_ioc_verbose_facts()`, which is the one piece of presentation
    formatting that used to live in the aggregation layer."""
    name = ev.module.basename if ev.module is not None else "(unknown)"
    return [f"module={name} region={hex_address(ev.region.base_address)} VA={hex_address(token.va)} "
            f"encoding={token.encoding} token={token.token}"
            + (" (weak/common API)" if token.is_weak else "")
            for token in ev.tokens]


def _verbose_facts_for(result, report: StompingReport) -> tuple:
    """Three shapes, all uncapped:

      * `stomping.ioc_string_lead` expands per-TOKEN (see
        `_ioc_verbose_fact`), where the wire fact is one line per REGION;
      * `stomping.protection_deviation_lead`/`verified_content_change`
        get a richer rendering carrying the .dmp file offset, the full VA
        range/hashes, and every differing byte range (see
        `_VERBOSE_ITEM_RENDERERS`);
      * every other check renders the SAME text as its wire-shaped facts,
        since each already carries every field that check knows about its
        own evidence item -- the only delta --verbose provides there is
        completeness.
    """
    if result.check == _IOC_STRING_LEAD:
        return tuple(fact for item in result.evidence for fact in _ioc_verbose_fact(item))
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check) or _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None or not result.evidence:
        # The evidence-free `stomping.protection_deviation_lead` ("no
        # anomaly anywhere") lands here: its single fact comes from the
        # coverage snapshot, and `Finding.print()` falls back to `facts`
        # when `verbose_facts` is empty, so there is nothing to expand.
        return ()
    return tuple(renderer(item, report) for item in result.evidence)


_COVERAGE_GAP_LIMITATION_PREFIX = "Coverage gap — "


def _console_finding(result, report: StompingReport):
    """The compat `Finding` `report_facts.finding_from_check_result`
    builds, augmented with `verbose_facts` -- this module's own
    normal/verbose detail policy (see this module's own docstring).

    For `stomping.ioc_string_lead` specifically, also strips any
    `"Coverage gap — ..."`-prefixed limitation: aggregate.py embeds
    `CoverageSnapshot.ioc_gap_reasons()` into this Finding's own
    `limitations` so --json's `findings[].limitations` carries them (that
    wire shape is unchanged here), but the SAME reasons are also part of
    `coverage_reasons` and get rendered once, unconditionally, in the
    COVERAGE section below. Printing a Finding's full `limitations` block
    only happens in --verbose (`render_finding_lines`); left unstripped, a
    --verbose transcript would show every IOC coverage-gap reason twice.
    Console-only: report_facts.py / report_legacy.py / report_record.py
    never see this stripped copy, so JSON output is untouched."""
    finding = finding_from_check_result(result, report)
    finding = with_verbose_facts(finding, _verbose_facts_for(result, report))
    if result.check == _IOC_STRING_LEAD:
        finding = dataclasses.replace(finding, limitations=[
            l for l in finding.limitations
            if not l.startswith(_COVERAGE_GAP_LIMITATION_PREFIX)])
    return finding


_TITLES = {
    "stomping.protection_deviation_lead":     "Section protection deviation",
    "stomping.rip_in_anomalous_section_lead": "Live RIP/EIP inside an anomalously-protected "
                                               "section",
    "stomping.verified_content_change":       "Verified module code modification",
    "stomping.reference_identity_mismatch":   "Reference build identity mismatch",
    "stomping.module_header_invalid":         "Module PE header failed validation",
    "stomping.ioc_string_lead":               "IOC strings in module code regions",
}


# `stomping.reference_identity_mismatch`/`stomping.module_header_invalid`
# are pure coverage-gap admissions -- "this section/module could not be
# checked", not a signal about content -- exactly the category issue #1's
# approved contract means by "coverage-only findings never appear in KEY
# SIGNALS or WHY THIS VERDICT". Mirrors
# `dumpex.hunt.injection.report_console._COVERAGE_ONLY_CHECKS`.
_COVERAGE_ONLY_CHECKS = frozenset({
    "stomping.reference_identity_mismatch",
    "stomping.module_header_invalid",
})


def _coverage_only_impacts(findings: list, coverage_reasons: list) -> list:
    """Fold each coverage-only finding's own `limitations` into the
    COVERAGE section as an impact line, deduped against `coverage_reasons`
    (and against each other) -- mirrors
    `dumpex.hunt.injection.report_console._coverage_only_impacts`. Keeps
    the "supply a matching reference file" / "these modules are excluded
    from both checks" guidance visible exactly once, in the section that
    owns coverage, instead of inside KEY SIGNALS."""
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


def _coverage_gap_detail_lines(findings: list, level: DetailLevel, w: int) -> list:
    """VERBOSE-only bounded evidence for the coverage-only checks excluded
    from KEY SIGNALS above. Unlike injection's `rip_correlation_unavailable`
    (which carries no evidence at all), `stomping.reference_identity_
    mismatch`/`stomping.module_header_invalid` each cite real per-item
    evidence (which module/section, and why) -- issue #1's approved
    hierarchy reserves exactly this slot ("an optional bounded
    hunter-specific evidence section") for detail that must not drive KEY
    SIGNALS/WHY THIS VERDICT but also must not silently vanish from
    --verbose."""
    detailed = [f for f in findings if f.check in _COVERAGE_ONLY_CHECKS]
    if not detailed:
        return []
    lines = [f"  {BOLD('COVERAGE-GAP DETAIL')}", ""]
    for f in detailed:
        title = _TITLES.get(f.check, f.check)
        lines.extend(render_finding_lines(f, level=level, indent=2, width=w, title=title))
    return lines


def _scan_detail_lines(report: StompingReport) -> list:
    """Verbose-only scan-detail block replacing the pre-migration
    "[*] Scanning executable MEM_IMAGE regions ..." pre-scan progress line
    and the "[·] Whitelisted network DLLs skipped ..." note -- this module
    is a pure post-hoc projection (see this module's own docstring), so
    neither can print DURING the scan any more, and neither belongs ahead
    of the verdict in normal-mode triage output.

    The whitelist note is genuinely informational rather than a coverage
    gap: those modules' regions WERE fully read, just with the network-IOC
    pattern set deliberately not applied (network strings are expected in
    wininet/winhttp/ws2_32/...), so it must not be reported as memory that
    went unexamined."""
    lines = [DIM("  Scan detail:"),
             DIM("    Executable MEM_IMAGE regions scanned for IOC strings (unscored lead only)")]
    whitelisted = report.coverage.ioc_whitelisted_modules
    if whitelisted:
        lines.append(DIM(f"    Whitelisted network DLLs skipped (network strings expected): "
                          f"{', '.join(sorted(set(whitelisted)))}"))
    lines.append("")
    return lines


def _render_verdict_block(report: StompingReport, coverage_status: str, findings: list,
                           coverage_report) -> list:
    """Reproduces the pre-migration verdict TEXT decisions exactly.

    score==1 is a verified, relocation-normalized byte difference with NO
    corroborating live execution in the changed range -- that is also
    exactly what a legitimate hotpatch/EDR-hook trampoline produces (see
    stomping.verified_content_change's limitations), so it is reported as a
    neutral, factual "modification confirmed" rather than "STOMPING", which
    would over-attribute malicious intent from content-diff alone. The
    "stomping" framing is reserved for score==2, where a thread's own
    RIP/EIP is executing inside the changed bytes.

    The old verdict line's trailing "(N/2, requires --ref-dir;
    protection-deviation and string-IOC leads above are informational and
    not counted)" clause is folded onto the Score row, where the score it
    qualifies actually lives."""
    status, score = report.status, report.score
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "no required stream present in this dump")
    elif status == DETECTED:
        verdict_text = (
            RED("HIGH CONFIDENCE STOMPING — verified content change, RIP/EIP inside "
                "the changed range") if score == 2 else
            YELLOW("VERIFIED MODULE CODE MODIFICATION — content differs from reference "
                   "file, but no observed thread executes inside the changed range "
                   "(uncorroborated; consistent with hotpatch/EDR-hook activity as well "
                   "as stomping)"))
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict_text = GREEN("CLEAN — no verified stomping indicators" + leads_suffix(findings))
    else:
        verdict_text = YELLOW("INCONCLUSIVE — partial coverage" + leads_suffix(findings))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", report.confidence),
        ("Score",      f"{score}/{report.max_score}  "
                       + DIM("(only a verified content-diff scores; requires --ref-dir)")),
        ("Coverage",   coverage_kv_value(coverage_status, coverage_report)),
        ("Review",     report.review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _coverage_impacts(report: StompingReport, coverage_status: str) -> list:
    """The score/verdict consequences the COVERAGE section spells out --
    the new home for two notices the pre-migration renderer printed
    separately (see this module's own docstring).

    The first replaces the ad-hoc "INCOMPLETE — part of the eligible
    executable module memory was not examined" check line plus its
    follow-up guidance: an IOC result is a FLOOR, not a total, whenever an
    eligible region was never read, and an analyst needs to be told which
    tool to point at the addresses named just above.

    The second replaces the "[~] Coverage incomplete despite a detection"
    line: a DETECTED verdict does not carry coverage_reasons in its own
    text (unlike NOT_EVALUATED/INCONCLUSIVE, which used to inline them), so
    a detection over partial coverage must not leave a red verdict standing
    on its own."""
    impacts = []
    if report.coverage.ioc_gap_reasons():
        impacts.append("An IOC result cannot be called clean for memory that was never read "
                       "— targeted follow-up needed on the region(s) above: --extract / "
                       "--strings that VA, or re-scan it with an external scanner.")
    if report.status == DETECTED and coverage_status == "partial":
        impacts.append("Coverage incomplete despite a detection — additional stomped modules "
                       "may exist beyond what could be checked.")
    return impacts


def _driving_finding(ordered: list):
    """The single check that actually justified the verdict.
    `stomping.verified_content_change` when present -- it is this hunter's
    ONLY scored check, so it drives the verdict whenever it fired,
    regardless of display order. Otherwise the highest-ranked signal, and
    only when that is a DETECTION/LEAD (a lone CONTEXT observation
    explains nothing about a CLEAN/INCONCLUSIVE verdict)."""
    for finding in ordered:
        if finding.check == _VERIFIED_CONTENT_CHANGE:
            return finding
    if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD):
        return ordered[0]
    return None


def render_console_lines(report: StompingReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `StompingReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value. `render_console_lines(report, False)` and
    `render_console_lines(report, True)` may be called in either order (or
    repeatedly) against the SAME `report` with no effect on each other, on
    `report` itself, or on `report_legacy.project_legacy_dict`/
    `report_record.project_hunter_record`'s output for that `report`."""
    findings = [_console_finding(r, report) for r in report.results]
    _, coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(header_lines("Module Stomping"))
    if verbose:
        lines.extend(_scan_detail_lines(report))

    lines.extend(_render_verdict_block(report, coverage_status, findings,
                                        project_coverage_report(report.coverage)))
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

    # WHY THIS VERDICT is deliberately suppressed for a NOT_EVALUATED
    # result, even when `ordered` holds a real DETECTION/LEAD: this
    # hunter's evaluation gate is asymmetric (the unscored IOC sub-scan
    # only needs MemoryInfoListStream, so it can still fire real evidence
    # while the scored path is NOT_EVALUATED for a missing ModuleListStream
    # -- see domain.CoverageSnapshot.evaluated). That evidence is still
    # shown in KEY SIGNALS above; explaining a NOT_EVALUATED VERDICT with
    # it here would misattribute the verdict to a lead that has nothing to
    # do with why evaluation didn't happen.
    if not verbose and report.status != NOT_EVALUATED:
        driving = _driving_finding(ordered)
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    # The bounded hunter-specific evidence section (issue #1's approved
    # hierarchy, item 5) comes BEFORE the unified COVERAGE section (item
    # 6) -- COVERAGE-GAP DETAIL is exactly that section for the two
    # coverage-only checks, so it must render here, ahead of COVERAGE.
    if verbose:
        lines.extend(_coverage_gap_detail_lines(findings, level, w))

    if coverage_reasons:
        # `_coverage_only_impacts` is NORMAL-mode only: in VERBOSE mode the
        # SAME limitation text just rendered above (COVERAGE-GAP DETAIL's
        # full Finding output already includes each one's own Limitations
        # block) -- folding it into COVERAGE too would print it twice.
        # `_coverage_impacts` (the IOC-gap follow-up guidance and the
        # DETECTED+partial notice) is unrelated to that detail section and
        # stays in both modes.
        impacts = [*([] if verbose else _coverage_only_impacts(findings, coverage_reasons)),
                   *_coverage_impacts(report, coverage_status)]
        lines.extend(render_coverage(coverage_status, coverage_reasons, w, impacts))

    evidence = report.evidence
    has_expandable_evidence = bool(evidence.verified_changes or evidence.protection_leads
                                   or evidence.ioc_hits or evidence.identity_mismatches
                                   or evidence.parse_failures)
    if not verbose and has_expandable_evidence:
        lines.append(DIM("  Use --verbose for every verified change, protection lead, and "
                          "per-token IOC hit in detail.\n"))

    return lines


def print_console(report: StompingReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
