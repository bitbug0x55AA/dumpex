"""`PipeReport` -> console lines pure projector -- the ONE console
renderer for the named-pipe C2 hunter, replacing the pre-migration
`dumpex.hunt.pipe.presentation.render()` (which printed five ad-hoc
`_print_check` blocks and three hand-rolled DIM detail blobs, THEN every
Finding in construction order, THEN the verdict last, and additionally
returned the legacy findings dict from the same call). This module never
prints (returns the exact lines a caller would print) and never returns a
legacy-dict projection (see `report_legacy.py` for that, an independent
pure function of the SAME `PipeReport`).

Implements the verdict-first structure approved in issue #1 (verdict block
-> KEY SIGNALS -> WHY THIS VERDICT (normal only) -> bounded evidence
detail (verbose only) -> unified COVERAGE -> verbose hint), mirroring
`dumpex.hunt.stomping.report_console`/`dumpex.hunt.injection.report_console`
/`dumpex.hunt.encoding.report_console` (the three completed reference
pilots). Legacy console byte parity is intentionally NOT preserved (see
issue #7's own console scope) -- reviewed goldens in
tests/fixtures/hunt_cli_golden/pipe_console.txt/pipe_verbose_console.txt
are the new target.

What moved, and where (issue #7's console scope, point by point):

  * the hunt header is emitted HERE, via
    `dumpex.hunt._report_console.header_lines()`, instead of by a separate
    `_print_pipe_pre_build_console()` that ran before the scan -- nothing
    prints before the Report exists any more (the same resolution
    dumpex.hunt.stomping and dumpex.hunt.encoding applied);
  * the "[·] N pipe reference(s) in system DLLs ... — expected, skipped"
    note is now `_scan_detail_lines()`, a VERBOSE-only block: it is scan
    progress, not triage output;
  * the two "[~] ... scan budget exhausted" warnings are now COVERAGE
    reasons (already carried by `project_coverage_v1`) plus a COVERAGE
    *impact*, so the same claim is made once, in the section that owns
    coverage, instead of twice ahead of the verdict;
  * the "NOT AVAILABLE — dump was not captured with MiniDumpWithHandleData"
    check line is likewise a COVERAGE reason plus an impact -- and that
    impact is where the "only unscored string leads are available" clause
    the old verdict line carried now lives;
  * the framework-attribution-on-string-leads block, the string-lead
    C2-context block, and the unbacked-thread block are now
    `_evidence_detail_lines()`, the bounded VERBOSE-only hunter-specific
    evidence section (issue #1's hierarchy, item 5). None of the three is
    a check this hunter scores or judges on; they are attribution/context
    detail, and issue #7 asks for exactly this material to live in
    "bounded evidence/verbose output". Handle correlation for each entry
    is determined HERE, at projection time (see `_has_open_handle` in
    `_evidence_detail_lines`), not at collection time -- correlation.py
    collects every string lead's C2 context/framework attribution
    regardless of whether that same canonical name also has a handle.

This is also the one place this hunter's normal/verbose CONSOLE detail
POLICY lives: `report_facts.finding_from_check_result` builds a compat
`Finding` carrying only wire-shaped `facts` (never `verbose_facts`);
`_console_finding` below is what augments it with `verbose_facts`,
entirely locally, so `report_legacy.py`/`report_record.py` never execute
this policy at all.
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
from dumpex.hunt.pipe.domain import PipeReport
from dumpex.hunt.pipe.patterns import canonical_pipe_name
from dumpex.hunt.pipe.report_facts import (
    _FACT_ITEM_RENDERERS, _file_offset_text, _proximity_text, finding_from_check_result,
    project_coverage_v1,
)


_CORROBORATION            = "pipe.corroboration"
_HANDLE_FRAMEWORK_MATCH   = "pipe.handle_framework_match"
_OPEN_HANDLES             = "pipe.open_handles"
_STRING_SCAN_LEAD         = "pipe.string_scan_lead"
_START_ADDRESS_LEAD       = "pipe.start_address_proximity_lead"


_TITLES = {
    _OPEN_HANDLES:           "Open pipe handles (HandleDataStream)",
    _HANDLE_FRAMEWORK_MATCH: "Known C2 framework pipe naming convention on an open handle",
    _STRING_SCAN_LEAD:       "Pipe name strings in non-system memory",
    _CORROBORATION:          "Handle-confirmed pipe corroborated by memory evidence",
    _START_ADDRESS_LEAD:     "Unbacked thread StartAddress near a handle-confirmed pipe",
}


# KEY SIGNALS display order, as issue #7 specifies it: handle-confirmed
# corroboration/detections, then framework matches, then open-handle
# context, then string-only leads.
#
# An explicit per-check rank rather than
# `dumpex.hunt._report_console.sorted_for_display`'s tag-rank sort,
# because this hunter needs an order that ranking by tag alone cannot
# produce: `pipe.corroboration` and `pipe.handle_framework_match` are BOTH
# DETECTION-tagged, so a stable tag sort would fall back to construction
# order -- which is fixed by the frozen `findings[]` array in --json
# (pipe_hunt_dict.json) and puts the framework match FIRST. Reordering
# aggregate.py to satisfy the console would change the wire contract;
# ordering here does not.
#
# `pipe.start_address_proximity_lead` sits ahead of
# `pipe.string_scan_lead` for the same reason the issue puts string-only
# leads last: it is still handle-ANCHORED (a lead about a pipe an open
# handle confirms), while the string-scan lead is the one signal with no
# handle behind it at all.
_DISPLAY_RANK = {
    _CORROBORATION:          0,
    _HANDLE_FRAMEWORK_MATCH: 1,
    _OPEN_HANDLES:           2,
    _START_ADDRESS_LEAD:     3,
    _STRING_SCAN_LEAD:       4,
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

def _open_handle_verbose_fact(ev, report: PipeReport) -> str:
    """The wire-shaped fact plus the CANONICALIZED name -- the exact
    string handle/string correlation matches on, and the one field an
    analyst needs to see to understand why a given handle did or did not
    line up with a `\\pipe\\` string in memory."""
    h = ev.handle
    return (f"Handle=0x{h.handle:x} ObjectName={h.object_name} "
            f"canonical={ev.canonical_name!r} "
            f"TypeName={h.type_name or '(none)'} GrantedAccess=0x{h.granted_access:x}"
            + (f"  [framework={ev.framework.framework}]" if ev.framework else ""))


def _string_lead_verbose_fact(ev, report: PipeReport) -> str:
    """The wire-shaped fact plus the fields --json consumers were never
    meant to need: the canonicalized name, the containing region's own
    identity, the full-run digest/length, and whether the retained preview
    was truncated."""
    return (f"VA=0x{ev.va:016x} File_offset={_file_offset_text(ev.file_offset)} "
            f"name={ev.name.strip()!r} canonical={canonical_pipe_name(ev.name)!r} "
            f"Region=0x{ev.region.base_address:x} size=0x{ev.region.size:x} "
            f"region_type={ev.region.type} protect={ev.region.protect} "
            f"encoding={ev.encoding} original_length={ev.original_length} "
            f"truncated={ev.truncated} sha256={ev.sha256}")


def _corroboration_verbose_facts(ev) -> list:
    """One fact line for the handle-confirmed pipe itself, then ONE MORE
    per corroborating signal: EVERY nearby C2 record (the wire fact
    carries only the first) and the live RIP/EIP hit.

    Separate list entries rather than one multi-line string, because
    `dumpex.hunt._console.wrap_text` word-wraps each fact and collapses
    whitespace -- embedded newlines in a single fact would be silently
    flattened back into one paragraph, which is exactly the unreadable
    run-together blob this expansion exists to avoid."""
    href = ev.handle.handle
    facts = [f"Handle=0x{href.handle:x} ObjectName={href.object_name} "
             f"pipe_va=0x{ev.pipe_va:016x} "
             f"File_offset={_file_offset_text(ev.string_hit.file_offset)} "
             f"Region=0x{ev.string_hit.region.base_address:x} "
             f"protect={ev.string_hit.region.protect}"]
    facts.extend(f"  ↳ c2_va=0x{rec.va:016x} c2_match={rec.match!r} "
                 f"{_proximity_text(rec.va, ev.pipe_va)} "
                 f"sha256_prefix={rec.sha256[:16]}…"
                 for rec in ev.nearby_c2)
    if ev.rip_hit is not None:
        tc = ev.rip_hit
        facts.append(f"  ↳ live_rip=TID:0x{tc.thread_id:x}@{tc.ip_reg}=0x{tc.ip:x} "
                     f"{_proximity_text(tc.ip, ev.pipe_va)}")
    return facts


_VERBOSE_ITEM_RENDERERS = {
    _OPEN_HANDLES:     _open_handle_verbose_fact,
    _STRING_SCAN_LEAD: _string_lead_verbose_fact,
}


def _verbose_facts_for(result, report: PipeReport) -> tuple:
    """Three shapes, all uncapped:

      * `pipe.corroboration` expands per SIGNAL (see
        `_corroboration_verbose_facts`), where the wire fact is one line
        per handle carrying only its first nearby C2 record;
      * `pipe.open_handles`/`pipe.string_scan_lead` get a richer
        rendering carrying the canonicalized name, the .dmp file offset,
        and the containing region's identity -- see
        `_VERBOSE_ITEM_RENDERERS`;
      * every other check renders the SAME text as its wire-shaped facts,
        since each already carries every field that check knows about its
        own evidence item -- the only delta --verbose provides there is
        completeness (`pipe.start_address_proximity_lead`'s wire facts are
        capped at 15).
    """
    if result.check == _CORROBORATION:
        return tuple(fact for item in result.evidence
                     for fact in _corroboration_verbose_facts(item))
    renderer = _VERBOSE_ITEM_RENDERERS.get(result.check) or _FACT_ITEM_RENDERERS.get(result.check)
    if renderer is None or not result.evidence:
        return ()
    return tuple(renderer(item, report) for item in result.evidence)


def _console_finding(result, report: PipeReport):
    """The compat `Finding` `report_facts.finding_from_check_result`
    builds, augmented with `verbose_facts` -- this module's own
    normal/verbose detail policy (see this module's own docstring)."""
    finding = finding_from_check_result(result, report)
    return with_verbose_facts(finding, _verbose_facts_for(result, report))


# ── Verbose-only blocks ───────────────────────────────────────────────────

def _scan_detail_lines(report: PipeReport) -> list:
    """Verbose-only scan-detail block replacing the pre-migration
    "[·] N pipe reference(s) in system DLLs (...) — expected, skipped"
    note -- this module is a pure post-hoc projection (see this module's
    own docstring), so it cannot print DURING the scan any more, and it
    does not belong ahead of the verdict in normal-mode triage output.

    Genuinely informational rather than a coverage gap: those regions WERE
    fully read, and a `\\pipe\\` reference inside Microsoft's own
    System32/SysWOW64/WinSxS code is expected, so it must not be reported
    as memory that went unexamined."""
    coverage = report.coverage
    lines = [DIM("  Scan detail:"),
             DIM("    Committed memory regions scanned for '\\pipe\\' name strings "
                 "(unscored lead only)")]
    if coverage.image_pipe_refs:
        modules = ", ".join(sorted(set(coverage.image_pipe_modules))) or "(unattributed)"
        lines.append(DIM(f"    {coverage.image_pipe_refs} pipe reference(s) in system DLLs "
                          f"({modules}) — expected, not reported as leads"))
    lines.append("")
    return lines


# How many items each EVIDENCE DETAIL list enumerates before summarizing
# the remainder, and how many C2 records one region enumerates inside it.
# The latter reproduces the pre-migration renderer's own `records[:3]`
# slice; the former is new, and exists because the pre-migration blocks
# were unbounded (see `_evidence_detail_lines`).
_DETAIL_LIMIT          = 10
_C2_RECORDS_PER_REGION = 3


def _more_lines(items, w: int) -> list:
    if len(items) <= _DETAIL_LIMIT:
        return []
    return wrap_block(f"... and {len(items) - _DETAIL_LIMIT} more", w, 6)


def _evidence_detail_lines(report: PipeReport, w: int) -> list:
    """The bounded, VERBOSE-only hunter-specific evidence section (issue
    #1's approved hierarchy, item 5) for the three kinds of evidence this
    hunter collects but does NOT turn into a check:

      * framework ATTRIBUTION on string leads -- a name-pattern match on a
        string lead, independent of whether that exact name also has an
        open handle (when it does, a note points at the scored check
        above instead of claiming there is none -- see `_has_open_handle`
        below). Deliberately not a check, and deliberately not in KEY
        SIGNALS: promoting it there would let a bare pipe string acquire
        the standing of a handle, which is precisely the distinction this
        hunter exists to preserve (see dumpex/hunt/pipe/__init__.py's
        package docstring);
      * regions holding both a pipe name and C2 artifacts, likewise
        independent of handle correlation -- context for the analyst,
        never scored;
      * unbacked threads whose StartAddress lands in a pipe-bearing region
        -- analyst visibility, never independently scored.

    Bounded: each list is capped, with the remainder summarized, so a
    pathological dump cannot turn --verbose into an unbounded dump of
    every region it touched."""
    evidence = report.evidence
    if not (evidence.framework_string_hits or evidence.c2_context
            or evidence.unbacked_threads):
        return []

    lines = [f"  {BOLD('EVIDENCE DETAIL')}", ""]

    # Whether a string lead's canonical name ALSO has an open handle: both
    # blocks below are informational, string-anchored buckets (populated
    # from every string lead that qualifies, independent of whether that
    # exact name also has a handle) -- they must not tell the analyst "no
    # corresponding open handle" for an entry whose name is, two sections
    # above, already reported as a scored pipe.open_handles/
    # pipe.handle_framework_match/pipe.corroboration detection.
    handle_names = {h.canonical_name for h in evidence.handle_pipes}

    def _has_open_handle(pipe_name: str) -> bool:
        return canonical_pipe_name(pipe_name) in handle_names

    if evidence.framework_string_hits:
        lines.append(DIM(f"  {len(evidence.framework_string_hits)} framework naming-convention "
                          f"match(es) on string leads — attribution only, never scored:"))
        # Labels carry their own colon rather than being space-aligned
        # into a column: `wrap_block` word-wraps through
        # `dumpex.hunt._console.wrap_text`, which collapses runs of
        # whitespace, so a hand-padded "Pipe     :" would lose its
        # alignment the moment it was rendered anyway.
        for ev in evidence.framework_string_hits[:_DETAIL_LIMIT]:
            handle_note = ("  (this name also has an open handle — see pipe.open_handles/"
                            "pipe.handle_framework_match/pipe.corroboration above)"
                            if _has_open_handle(ev.pipe_name) else "")
            lines.extend(wrap_block(f"Pipe: {ev.pipe_name}  "
                                     f"Region=0x{ev.region.base_address:x}{handle_note}", w, 6))
            lines.extend(wrap_block(f"Framework: {ev.framework.framework} — "
                                     f"{ev.framework.technique} "
                                     f"[{ev.framework.mitre}]", w, 8))
        lines.extend(_more_lines(evidence.framework_string_hits, w))
        lines.append("")

    if evidence.c2_context:
        lines.append(DIM(f"  {len(evidence.c2_context)} region(s) with a pipe-name string + C2 "
                          f"artifacts:"))
        for ev in evidence.c2_context[:_DETAIL_LIMIT]:
            correlation_note = ("this name also has an open handle — see pipe.open_handles/"
                                 "pipe.corroboration above"
                                 if _has_open_handle(ev.pipe_name) else
                                 "no corresponding open handle for this exact name")
            lines.extend(wrap_block(f"Region 0x{ev.region.base_address:x}  "
                                     f"pipe: {ev.pipe_name}  ({correlation_note})", w, 6))
            for rec in ev.records[:_C2_RECORDS_PER_REGION]:
                lines.extend(wrap_block(f"C2: {rec.match}  VA 0x{rec.va:016x}  "
                                         f"sha256_prefix={rec.sha256[:16]}…", w, 8))
            if len(ev.records) > _C2_RECORDS_PER_REGION:
                lines.extend(wrap_block(
                    f"... and {len(ev.records) - _C2_RECORDS_PER_REGION} more record(s)", w, 8))
        lines.extend(_more_lines(evidence.c2_context, w))
        lines.append("")

    if evidence.unbacked_threads:
        lines.append(DIM(f"  {len(evidence.unbacked_threads)} unbacked thread(s) starting in a "
                          f"pipe-name-string region — lead only, never scored:"))
        for ev in evidence.unbacked_threads[:_DETAIL_LIMIT]:
            start = ev.thread.start_address
            start_text = f"0x{start:x}" if start is not None else "(not recorded)"
            lines.extend(wrap_block(f"TID=0x{ev.thread.thread_id:x}  StartAddr={start_text}  "
                                     f"Region=0x{ev.region.base_address:x}", w, 6))
        lines.extend(_more_lines(evidence.unbacked_threads, w))
        lines.append("")

    return lines


# ── Verdict block / coverage impacts ──────────────────────────────────────

def _render_verdict_block(report: PipeReport, coverage_status: str, findings: list) -> list:
    """The verdict-first key/value block.

    Each DETECTED tier names the signal that actually earned it rather
    than a bare severity word: score 1 is a framework-named open handle
    and nothing else, score 2 adds ONE independent proximate memory
    signal, score 3 adds both. The old verdict line's trailing
    "(N/3 — handle-anchored; string leads shown above are informational
    only)" clause is folded onto the Score row, where the score it
    qualifies actually lives.

    NOT_EVALUATED's reason is deliberately short here and NOT the joined
    `coverage_reasons` list the pre-migration verdict line inlined: issue
    #7 asks for every coverage gap and its judgment impact to be rendered
    ONCE, in COVERAGE.
    """
    status, score = report.status, report.score
    if status == NOT_EVALUATED:
        verdict_text = _status_text(
            status, "neither MemoryInfoListStream nor HandleDataStream present in this dump")
    elif status == DETECTED:
        if score >= 3:
            verdict_text = RED("HIGH CONFIDENCE C2 PIPE / LATERAL MOVEMENT — handle-confirmed "
                                "pipe with BOTH nearby C2 context and live RIP/EIP execution")
        elif score == 2:
            verdict_text = YELLOW("LIKELY C2 PIPE — handle-confirmed pipe corroborated by nearby "
                                   "C2 context or live RIP/EIP execution")
        else:
            verdict_text = YELLOW("POSSIBLE C2 PIPE — an open pipe handle matches a known "
                                   "C2/lateral-movement framework naming convention, with no "
                                   "further corroboration")
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict_text = GREEN("CLEAN — no handle-confirmed C2 pipe indicators"
                             + leads_suffix(findings))
    else:
        verdict_text = YELLOW("INCONCLUSIVE — partial coverage" + leads_suffix(findings))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", report.confidence),
        ("Score",      f"{score}/{report.max_score}  "
                       + DIM("(handle-anchored; bare pipe strings are unscored leads)")),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     report.review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _coverage_impacts(report: PipeReport, coverage_status: str) -> list:
    """The score/verdict consequences the COVERAGE section spells out --
    the new home for three notices the pre-migration renderer printed
    separately (see this module's own docstring).

    The first replaces the "NOT AVAILABLE — dump was not captured with
    MiniDumpWithHandleData" check line AND the old verdict line's
    "— only unscored string leads are available above" clause: without
    HandleDataStream the scored path never ran, and a score of 0 must not
    be read as a clean result.

    The second and third replace the two "[~] ... scan budget exhausted"
    warnings and give the skipped/unreadable regions an actionable next
    step -- an analyst needs to be told which tool to point at the
    addresses named just above.
    """
    coverage = report.coverage
    impacts = []
    if not coverage.handle_data_stream:
        impacts.append("The primary, scored pipe-handle check could not run at all — any "
                       "'\\pipe\\' string this run did find stays an unscored lead (a bare "
                       "string never becomes handle evidence), so a score of 0 here is not a "
                       "clean result.")
    if coverage.skipped_oversize or coverage.read_failed or coverage.short_reads:
        impacts.append("A pipe name or C2 artifact in memory that was never read cannot be "
                       "ruled out — targeted follow-up needed on the region(s) above: "
                       "--extract / --strings that VA, or re-scan it with an external scanner.")
    if coverage.budget_exhausted:
        impacts.append("A whole-hunt scan budget stopped collection early — the pipe-name and "
                       "C2-context counts above are a floor, not a total.")
    if report.status == DETECTED and coverage_status == "partial":
        impacts.append("Coverage incomplete despite a detection — additional pipe channels may "
                       "exist beyond what could be checked.")
    return impacts


def _driving_finding(ordered: list):
    """The single check that actually justified the verdict.

    `pipe.corroboration` when present -- it is the only check that can
    take this hunter's score past 1, so it drives the verdict whenever it
    fired. Otherwise `pipe.handle_framework_match`, the only other scored
    check. Otherwise the highest-ranked displayed signal, and only when
    that is a DETECTION/LEAD (a lone CONTEXT observation explains nothing
    about a CLEAN/INCONCLUSIVE verdict).
    """
    for check in (_CORROBORATION, _HANDLE_FRAMEWORK_MATCH):
        for finding in ordered:
            if finding.check == check:
                return finding
    if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD):
        return ordered[0]
    return None


def render_console_lines(report: PipeReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `PipeReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, no
    legacy-dict return value. `render_console_lines(report, False)` and
    `render_console_lines(report, True)` may be called in either order (or
    repeatedly) against the SAME `report` with no effect on each other, on
    `report` itself, or on `report_legacy.project_legacy_dict`/
    `report_record.project_hunter_record`'s output for that `report`."""
    findings = [_console_finding(r, report) for r in report.results]
    coverage_status, coverage_reasons = project_coverage_v1(report.coverage)
    w = resolve_width(width)
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    lines = list(header_lines("Named Pipe C2 / Lateral Movement"))
    if verbose:
        lines.extend(_scan_detail_lines(report))

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

    # WHY THIS VERDICT is suppressed for a NOT_EVALUATED result even when
    # `ordered` holds a real LEAD: this hunter's evaluation gate is
    # OR-of-presence (see domain.CoverageSnapshot.evaluated), so a
    # NOT_EVALUATED run has nothing shown here anyway -- but the guard is
    # kept explicit so a future change to that gate cannot quietly start
    # explaining a "nothing was looked at" verdict with a lead that has
    # nothing to do with why evaluation didn't happen.
    if not verbose and report.status != NOT_EVALUATED:
        driving = _driving_finding(ordered)
        if driving is not None:
            lines.extend(render_why_this_verdict(driving, w))

    # The bounded hunter-specific evidence section (issue #1's approved
    # hierarchy, item 5) comes BEFORE the unified COVERAGE section (item
    # 6).
    if verbose:
        lines.extend(_evidence_detail_lines(report, w))

    if coverage_reasons:
        lines.extend(render_coverage(coverage_status, coverage_reasons, w,
                                      _coverage_impacts(report, coverage_status)))

    evidence = report.evidence
    has_expandable_evidence = bool(evidence.handle_pipes or evidence.string_leads
                                   or evidence.c2_context or evidence.framework_string_hits
                                   or evidence.unbacked_threads)
    if not verbose and has_expandable_evidence:
        lines.append(DIM("  Use --verbose for the full handle list, canonicalized pipe names, "
                          "VA/file offsets, and nearby C2 context.\n"))

    return lines


def print_console(report: PipeReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
