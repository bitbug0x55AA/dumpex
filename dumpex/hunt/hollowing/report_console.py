"""`HollowingReport` -> console lines pure projector -- the ONE console
renderer for the process-hollowing hunter, replacing the pre-migration
`_render_hollowing_console(mf, report, verbose)` (which took the DUMP as
its first parameter, printed a three-line image-base header, then four
ad-hoc `_print_check` blocks re-deriving `prot_str()`/`va_to_file_offset()`
off raw minidump objects the Report was carrying purely for that purpose,
then every Finding in construction order -- restating the same four checks
a second time in full narrative form -- then the verdict last, and
additionally returned the legacy findings dict from the same call).

This module never prints (returns the exact lines a caller would print),
never returns a legacy-dict projection (see `report_legacy.py` for that, an
independent pure function of the SAME `HollowingReport`), and never
receives `mf`: every VA, file offset, protection string, header byte, and
module name it renders was resolved once, at scan time, onto
`report.context` (dumpex.hunt.hollowing.models.ImageBaseContext).

Implements the verdict-first structure approved in issue #1 (verdict block
-> KEY SIGNALS -> WHY THIS VERDICT (normal only) -> bounded evidence detail
(verbose only) -> unified COVERAGE -> verbose hint), mirroring
`dumpex.hunt.stomping.report_console`/`dumpex.hunt.pipe.report_console`/
`dumpex.hunt.injection.report_console`/`dumpex.hunt.encoding.report_console`
(the four completed reference pilots). Legacy console byte parity is
intentionally NOT preserved (see issue #10's own console scope) -- reviewed
goldens in tests/fixtures/hunt_cli_golden/hollowing_console.txt/
hollowing_verbose_console.txt are the new target.

What moved, and where (issue #10's console scope, point by point):

  * the hunt header is emitted HERE, via
    `dumpex.hunt._report_console.header_lines()`, instead of by
    `_print_hollowing_pre_build_console()` -- a separate function that ran
    an ANNOUNCING `get_rules()` call before the builder purely to order the
    one-time "Rules loaded from ..." line ahead of the header this renderer
    printed after it. Nothing prints before the Report exists any more (the
    same resolution dumpex.hunt.stomping and dumpex.hunt.pipe applied);
  * the verdict, confidence, score, coverage status, and review priority
    are the FIRST thing rendered, as a key/value block, instead of the
    verdict being the last line of the transcript;
  * the four `_print_check` blocks are gone. Their status lines duplicated
    what the corresponding Finding's own inference already said (each check
    was rendered twice, in two different vocabularies), and their `Detail:`
    text -- PEB image path, image-base VA and .dmp offset, memory type and
    protection, header bytes, and the module-name comparison -- is now
    `_image_base_lines()`, the bounded VERBOSE-only hunter-specific
    evidence section (issue #1's hierarchy, item 5);
  * the "[~] ..." partial-coverage line that used to print between the
    findings and the verdict is now a COVERAGE reason (already carried by
    `project_coverage_v1`) plus a COVERAGE *impact*, so each gap and its
    judgment consequence are stated once, in the section that owns
    coverage, rather than inlined into the verdict text as well;
  * the PEB-missing case's "[!] PEB not available — cannot run hollowing
    check." line is likewise a COVERAGE reason plus an impact -- and, being
    a projection of the same Report as every other state, it no longer
    needs its own hand-written early-return dict (see report_legacy.py).

This is also the one place this hunter's normal/verbose CONSOLE detail
POLICY lives: `report_facts.finding_from_check_result` builds a compat
`Finding` carrying only wire-shaped `facts` (never `verbose_facts`);
`_console_finding` below is what augments it with `verbose_facts`, entirely
locally, so `report_legacy.py`/`report_record.py` never execute this policy
at all.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import (
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text,
)
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines, TAG_DETECTION, TAG_LEAD,
)
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    header_lines, render_key_signal_compact, render_why_this_verdict, render_coverage,
    with_verbose_facts, wrap_block, TAG_RANK,
)
from dumpex.hunt.hollowing.domain import HollowingReport
from dumpex.hunt.hollowing.models import (
    OUTCOME_CLEAN, OUTCOME_EXCEPTION, OUTCOME_SHORT_READ, OUTCOME_WIPED_OTHER,
    OUTCOME_WIPED_ZERO, basename_lower,
)
from dumpex.hunt.hollowing.report_facts import (
    _FACT_ITEM_RENDERERS, file_offset_text, finding_from_check_result, header_preview,
    project_coverage_v1,
)


_STRUCTURAL_CORRELATION = "hollowing.structural_correlation"
_MEM_PRIVATE            = "hollowing.mem_private_at_image_base"
_MZ_HEADER_MISSING      = "hollowing.mz_header_missing"
_RWX                    = "hollowing.rwx_at_image_base"
_NAME_MISMATCH          = "hollowing.peb_module_name_mismatch"


_TITLES = {
    _STRUCTURAL_CORRELATION: "Correlated structural hollowing indicators",
    _MEM_PRIVATE:            "MEM_PRIVATE memory at the image base",
    _MZ_HEADER_MISSING:      "Missing/wiped MZ header at the image base",
    _RWX:                    "RWX protection at the image base",
    _NAME_MISMATCH:          "PEB image name vs module list",
}


# KEY SIGNALS display order, as issue #10 specifies it: the structural
# correlation/detection first, then MEM_PRIVATE, the wiped/missing MZ
# header, RWX, and the name mismatch, in that order.
#
# An explicit per-check rank rather than
# `dumpex.hunt._report_console.sorted_for_display`'s tag-rank sort, because
# ranking by tag alone cannot produce this order: FOUR of the five checks
# are LEAD-tagged, so a stable tag sort would fall back to construction
# order -- which is fixed by the frozen `findings[]` array in --json
# (hollowing_hunt_dict.json) and puts the structural correlation LAST,
# since it is built only after the anchors it correlates. Reordering
# aggregate.py to satisfy the console would change the wire contract;
# ordering here does not.
#
# The order among the four leads is evidentiary, not alphabetical: the two
# ANCHORS (MEM_PRIVATE, wiped MZ) come before the two CORROBORATORS (RWX,
# name mismatch), and the name mismatch is last because it is the one
# signal with no memory-state observation behind it at all -- a path/case
# comparison that DLL redirection or a WoW64 path difference can produce on
# its own.
_DISPLAY_RANK = {
    _STRUCTURAL_CORRELATION: 0,
    _MEM_PRIVATE:            1,
    _MZ_HEADER_MISSING:      2,
    _RWX:                    3,
    _NAME_MISMATCH:          4,
}


def _ordered_for_display(findings: list) -> list:
    """`findings` in `_DISPLAY_RANK` order, with an unranked check (a new
    one added to aggregate.py without a rank here) falling back to the
    shared tag ranking and then to construction order -- never silently
    dropped."""
    ranked = sorted(enumerate(findings),
                    key=lambda pair: (_DISPLAY_RANK.get(pair[1].check,
                                                         10 + TAG_RANK.get(pair[1].tag, 3)),
                                       pair[0]))
    return [f for _, f in ranked]


# ── Verbose-only evidence-item fact rendering (console policy only) ──────

def _mem_private_verbose_fact(ev, report: HollowingReport) -> str:
    """The wire-shaped fact plus the two fields --json consumers were never
    meant to need: the containing region's full extent and its .dmp file
    offset (where to point --extract/--strings)."""
    region = ev.region
    offset = report.context.region_file_offset if report.context is not None else None
    return (f"VA=0x{region.base_address:016x} File_offset={file_offset_text(offset)} "
            f"size=0x{region.size:x} state={region.state} type={region.type} "
            f"protect={region.protect}")


def _rwx_verbose_fact(ev, report: HollowingReport) -> str:
    """Same region detail as above, framed on the protection this check is
    actually about."""
    region = ev.region
    offset = report.context.region_file_offset if report.context is not None else None
    return (f"VA=0x{region.base_address:016x} File_offset={file_offset_text(offset)} "
            f"protect={region.protect} type={region.type}")


def _wiped_header_verbose_fact(ev, report: HollowingReport) -> str:
    """The wire fact's 8-byte preview plus how the read was classified and
    how many bytes actually came back -- "zeroed" and "unexpected bytes"
    are materially different situations that the single
    `hollowing.mz_header_missing` check deliberately treats alike."""
    outcome = report.context.header.outcome if report.context is not None else ""
    return (f"VA=0x{ev.image_base:016x} File_offset="
            f"{file_offset_text(report.context.file_offset if report.context else None)} "
            f"header_bytes={header_preview(ev.header_bytes)} "
            f"read_bytes={len(ev.header_bytes)} outcome={outcome}")


def _name_mismatch_verbose_fact(ev, report: HollowingReport) -> str:
    """Both sides of the comparison spelled out, rather than the wire
    fact's `module_list_match=True/False` boolean. Derived from the
    evidence item's OWN recorded path rather than from `report.context`:
    this check's whole claim is about the two names, so it must render from
    the same value the comparison itself was made against."""
    module_name = ev.module.basename_lower if ev.module is not None else "(no module-list entry)"
    return (f"PEB_image_path={ev.image_path!r} peb_name={basename_lower(ev.image_path)!r} "
            f"module_list_name={module_name!r}")


def _correlation_verbose_fact(ev, report: HollowingReport) -> str:
    """The correlating signals enumerated one per clause with the address
    they all share, rather than the wire fact's ` + `-joined label list."""
    return (f"VA=0x{ev.image_base:016x} corroborators={len(ev.corroborators)} "
            + "; ".join(ev.corroborators))


_VERBOSE_ITEM_RENDERERS = {
    _MEM_PRIVATE:            _mem_private_verbose_fact,
    _RWX:                    _rwx_verbose_fact,
    _MZ_HEADER_MISSING:      _wiped_header_verbose_fact,
    _NAME_MISMATCH:          _name_mismatch_verbose_fact,
    _STRUCTURAL_CORRELATION: _correlation_verbose_fact,
}


def _verbose_facts_for(result, report: HollowingReport) -> tuple:
    """Every check here has a genuinely richer --verbose rendering (see
    `_VERBOSE_ITEM_RENDERERS`), carrying the region's .dmp file offset and
    full extent, the header read's own outcome and length, or both sides of
    the name comparison -- none of which may reach `facts`, since that array
    is embedded verbatim in the frozen v1.1 dict and typed `HunterRecord`.

    `report_facts._FACT_ITEM_RENDERERS` is consulted as a fallback purely so
    a check added to aggregate.py without a verbose renderer here still
    expands to SOMETHING rather than silently rendering nothing."""
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check) or _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None or not result.evidence:
        return ()
    return tuple(renderer(item, report) for item in result.evidence)


def _console_finding(result, report: HollowingReport):
    """The compat `Finding` `report_facts.finding_from_check_result` builds,
    augmented with `verbose_facts` -- this module's own normal/verbose
    detail policy (see this module's own docstring)."""
    finding = finding_from_check_result(result, report)
    return with_verbose_facts(finding, _verbose_facts_for(result, report))


# ── Bounded, verbose-only image-base evidence ─────────────────────────────

_HEADER_OUTCOME_TEXT = {
    OUTCOME_CLEAN:       "MZ present",
    OUTCOME_WIPED_ZERO:  "zeroed out (header wiping)",
    OUTCOME_WIPED_OTHER: "unexpected bytes where MZ should be",
    OUTCOME_SHORT_READ:  "short read — could not check",
    OUTCOME_EXCEPTION:   "could not read",
}


def _image_base_lines(report: HollowingReport, w: int) -> list:
    """The bounded, VERBOSE-only hunter-specific evidence section (issue
    #1's approved hierarchy, item 5): the observed STATE of the image base,
    as opposed to the signals that state produced.

    This is the new home for what the pre-migration renderer printed as a
    three-line header plus four `_print_check` blocks, ahead of the verdict:
    the PEB image path, the image-base VA and its .dmp file offset, the
    containing region's memory type/protection, the header read's bytes and
    outcome, and the PEB-vs-module-list name comparison. Issue #10 asks for
    exactly this material to live in "a bounded evidence section/verbose
    output rather than duplicating raw check blocks and Finding narratives"
    -- in normal mode the corresponding Findings already say what each of
    these observations MEANS, and repeating the raw values above them made
    an analyst read the same four checks twice in two vocabularies.

    Bounded by construction, not by a cap: this hunter examines ONE address,
    so the section is a fixed handful of lines no dump can grow.

    Nothing is rendered when the PEB was absent -- there is no image base to
    describe, and COVERAGE already says so.
    """
    context = report.context
    if context is None:
        return []

    lines = [f"  {BOLD('IMAGE BASE')}", ""]
    lines.extend(wrap_block(f"PEB ImagePath: {context.image_path}", w, 6))
    lines.extend(wrap_block(
        f"ImageBase: VA 0x{context.image_base:016x}  "
        f"File offset {file_offset_text(context.file_offset)}", w, 6))

    if context.region is None:
        lines.extend(wrap_block(
            "Memory: image base page not captured in this dump — memory-type and RWX "
            "checks could not run", w, 6))
    else:
        region = context.region
        lines.extend(wrap_block(
            f"Memory: {region.type}  {region.protect}  {region.state}  "
            f"(region VA 0x{region.base_address:016x} size 0x{region.size:x}, "
            f"File offset {file_offset_text(context.region_file_offset)})", w, 6))

    header = context.header
    outcome_text = _HEADER_OUTCOME_TEXT.get(header.outcome, header.outcome)
    if header.outcome == OUTCOME_EXCEPTION:
        lines.extend(wrap_block(f"MZ header: {outcome_text} — {header.error}", w, 6))
    else:
        lines.extend(wrap_block(
            f"MZ header: {outcome_text}  (first bytes {header_preview(header.header_bytes)}, "
            f"{len(header.header_bytes)} byte(s) read)", w, 6))

    if context.module is not None:
        module_name = context.module.basename_lower
        agreement = ("both report" if module_name == context.image_name
                     else "MISMATCH — PEB says")
        lines.extend(wrap_block(
            f"Module list: {agreement} {context.image_name!r}"
            + ("" if module_name == context.image_name
               else f", module list says {module_name!r}"), w, 6))
    elif report.coverage.modules_available:
        lines.extend(wrap_block(
            "Module list: image base is not inside any listed module — the main executable "
            "may have been unmapped", w, 6))
    else:
        lines.extend(wrap_block(
            "Module list: ModuleListStream missing/empty from this dump — the name "
            "comparison could not run", w, 6))

    lines.append("")
    return lines


# ── Verdict block / coverage impacts ──────────────────────────────────────

def _second_signal_text(report: HollowingReport) -> str:
    """Which corroborating signal earned a score-1 DETECTED, named in the
    verdict line exactly as the pre-migration renderer named it. Read off
    the correlation evidence itself rather than off a separate `mz_wiped`
    boolean the Report used to also carry."""
    correlation = report.evidence.correlations[0]
    return "MZ header wiped" if correlation.wiped_header is not None else "RWX protection"


def _render_verdict_block(report: HollowingReport, coverage_status: str,
                           findings: list) -> list:
    """The verdict-first key/value block. Reproduces the pre-migration
    verdict TEXT decisions exactly -- score 2 is all three structural
    signals correlating at one address, score 1 is MEM_PRIVATE plus
    whichever single corroborator fired.

    NOT_EVALUATED's reason is the PEB's absence and nothing else; the old
    verdict line's trailing "(N/2 — requires MEM_PRIVATE at image base
    correlated with a second structural anomaly; single signals above are
    leads only)" clause is folded onto the Score row, where the score it
    qualifies actually lives.
    """
    status, score = report.status, report.score
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "PEB stream missing from this dump")
    elif status == DETECTED:
        verdict_text = (
            RED("HIGH CONFIDENCE HOLLOWING — MEM_PRIVATE, MZ wiped, AND RWX all correlate")
            if score >= 2 else
            YELLOW("LIKELY HOLLOWING — MEM_PRIVATE at image base correlated with "
                   + _second_signal_text(report)))
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict_text = GREEN("CLEAN — no correlated hollowing indicators"
                             + leads_suffix(findings))
    else:
        verdict_text = YELLOW("INCONCLUSIVE — partial coverage" + leads_suffix(findings))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", report.confidence),
        ("Score",      f"{score}/{report.max_score}  "
                       + DIM("(requires MEM_PRIVATE at the image base correlated with a "
                             "second structural anomaly; single signals are leads only)")),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     report.review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _coverage_impacts(report: HollowingReport, coverage_status: str) -> list:
    """The score/verdict consequences the COVERAGE section spells out -- the
    new home for two notices the pre-migration renderer printed separately
    (see this module's own docstring).

    The first replaces the "[!] PEB not available — cannot run hollowing
    check." line: every check this hunter has is anchored on the image base
    the PEB reports, so without that stream nothing was examined and a score
    of 0 must not be read as a clean result.

    The second replaces the "[~] {joined coverage reasons}." line: a check
    that never ran is not a check that came back clean, and at score 0 that
    is precisely the difference between INCONCLUSIVE and a real negative.

    The third has no pre-migration counterpart at all -- a DETECTED verdict
    does not carry coverage_reasons in its own text, so a detection over
    partial coverage must not leave a red verdict standing on its own.
    """
    coverage = report.coverage
    impacts = []
    if not coverage.peb_present:
        impacts.append("Every hollowing check is anchored on the image base the PEB itself "
                       "reports — without that stream nothing was examined at all, so a "
                       "score of 0 here is not a clean result.")
    elif not coverage.complete:
        impacts.append("At least one anchor/corroborator never ran — a score of 0 over "
                       "partial coverage is not the same claim as an image base that was "
                       "checked and found intact.")
    if report.status == DETECTED and coverage_status == "partial":
        impacts.append("Coverage incomplete despite a detection — the check(s) that could "
                       "not run may hold further corroboration.")
    return impacts


def _driving_finding(ordered: list):
    """The single check that actually justified the verdict.
    `hollowing.structural_correlation` when present -- it is this hunter's
    ONLY scored check, so it drives the verdict whenever it fired,
    regardless of display order. Otherwise the highest-ranked displayed
    signal, and only when that is a DETECTION/LEAD (a lone CONTEXT
    observation explains nothing about a CLEAN/INCONCLUSIVE verdict)."""
    for finding in ordered:
        if finding.check == _STRUCTURAL_CORRELATION:
            return finding
    if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD):
        return ordered[0]
    return None


def render_console_lines(report: HollowingReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `HollowingReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value, and no `mf`. `render_console_lines(report,
    False)` and `render_console_lines(report, True)` may be called in either
    order (or repeatedly) against the SAME `report` with no effect on each
    other, on `report` itself, or on `report_legacy.project_legacy_dict`/
    `report_record.project_hunter_record`'s output for that `report`."""
    findings = [_console_finding(r, report) for r in report.results]
    coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(header_lines("Process Hollowing"))
    lines.extend(_render_verdict_block(report, coverage_status, findings))
    lines.append("")

    ordered = _ordered_for_display(findings)
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

    # WHY THIS VERDICT is suppressed for a NOT_EVALUATED result. This
    # hunter's evaluation gate is the PEB alone, and no check can fire
    # without it, so `ordered` is always empty there anyway -- but the
    # guard is kept explicit so a future change to that gate cannot quietly
    # start explaining a "nothing was looked at" verdict with a lead that
    # has nothing to do with why evaluation didn't happen (the same
    # reasoning dumpex.hunt.stomping/pipe's own renderers state).
    if not verbose and report.status != NOT_EVALUATED:
        driving = _driving_finding(ordered)
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    # The bounded hunter-specific evidence section (issue #1's approved
    # hierarchy, item 5) comes BEFORE the unified COVERAGE section (item 6).
    if verbose:
        lines.extend(_image_base_lines(report, w))

    if coverage_reasons:
        lines.extend(render_coverage(coverage_status, coverage_reasons, w,
                                      _coverage_impacts(report, coverage_status)))

    if not verbose and report.context is not None:
        lines.append(DIM("  Use --verbose for the image base's VA/file offset, memory "
                          "type/protection, header bytes, and module comparison.\n"))

    return lines


def print_console(report: HollowingReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
