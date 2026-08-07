"""All console rendering for the process injection hunter -- verdict-first
layout (Step 1.5, console presentation patch): the VERDICT/Confidence/
Score/Coverage/Review block comes FIRST, then `KEY SIGNALS` (every Finding
in `report.findings_list` EXCEPT the coverage-only ones -- see
`_COVERAGE_ONLY_CHECKS` below -- sorted detection -> lead -> observation
for DISPLAY ONLY -- the underlying findings_list/JSON `findings` array
build order is never touched, and score/status/coverage are never
recomputed here), then `WHY THIS VERDICT` (normal mode only -- the single
Finding that actually drove the verdict), then one unified `COVERAGE`
section sourced from the existing `findings["coverage_reasons"]` list (the
ONE place that text already lives; this module never re-derives it from
`coverage`/`pe_read_failed`/`pe_short_reads` a second time) plus any extra
Impact caveat a coverage-only Finding's own `limitations` carries that
`coverage_reasons` doesn't already say.

A "coverage-only" check (`_COVERAGE_ONLY_CHECKS`, currently just
`injection.rip_correlation_unavailable`) exists purely to describe a
coverage gap -- its `inference` is, by construction, the same fact
`aggregate.py` already put into `coverage_reasons` for the exact same
underlying condition (`not coverage["thread_context"]`). Showing it again
as a KEY SIGNALS entry (and possibly as the WHY THIS VERDICT "driving"
finding) would print that same gap twice under two different headings --
excluded from both sections here, with only its NON-duplicate
`limitations` (e.g. "score capped below HIGH") surfaced once, under
COVERAGE, as an Impact line. This is presentation-only: the Finding is
still fully present in `report.findings_list`/`findings["findings"]`
(--json/`legacy_findings_dict()`'s return value is untouched), only
excluded from these two console groupings.

Reads only from the aggregate.Report the caller already built -- never
reads a raw hit list (report.rwx, report.suspicious_pe_hits,
report.start_threads) for --verbose detail: every Finding in
report.findings_list already carries everything this module can show for
it (see dumpex/hunt/injection/aggregate.py's _rwx_verbose_fact()/
_hidden_pe_verbose_fact()/_unbacked_thread_verbose_fact()). The three raw
lists are still read here for one thing only -- the truthiness check that
decides whether to print the closing "--verbose" hint -- never as a source
of rendered detail.

Decides nothing about the LEGACY findings-dict SHAPE it hands back to the
caller either -- that projection (Evidence dataclasses -> plain, JSON-safe
dicts) is dumpex.hunt.injection.legacy.legacy_findings_dict()'s own single
job, called once, at this function's one and only return statement, so
this module stays purely "print, then hand back the dict a caller gets"
and never re-decides what that dict's shape is.
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import _print_hunt_header, _status_text, \
    NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED
from dumpex.hunt._finding import (
    DetailLevel, leads_suffix, render_finding_lines,
    TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION,
)
from dumpex.hunt._console import resolve_width, wrap_text, render_kv_block
from dumpex.hunt.injection.legacy import legacy_findings_dict


# Human-readable titles for injection's own check ids -- an explicit,
# curated mapping, never a blind check.replace("_", " ").title() guess (a
# check id this dict doesn't (yet) know about falls back to itself, which
# stays readable on its own). Lives here, not in _finding.py, because
# check-id vocabulary is hunter-specific -- see this hunter's own
# aggregate.py for where each `check=` string is actually built.
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

_TAG_ICON  = {TAG_DETECTION: RED("[!]"), TAG_LEAD: YELLOW("[~]"), TAG_OBSERVATION: DIM("[i]")}
_TAG_LABEL = {TAG_DETECTION: "DETECTION", TAG_LEAD: "LEAD", TAG_OBSERVATION: "CONTEXT"}
_TAG_RANK  = {TAG_DETECTION: 0, TAG_LEAD: 1, TAG_OBSERVATION: 2}
_LABEL_WIDTH = max(len(label) for label in _TAG_LABEL.values())

_COVERAGE_ICON = {"complete": GREEN("[✓]"), "partial": YELLOW("[~]"), "not_evaluated": DIM("[-]")}

# Checks whose entire purpose is describing a coverage gap -- see this
# module's own docstring for why these are excluded from KEY SIGNALS/WHY
# THIS VERDICT and folded into COVERAGE instead. Adding a future check
# here is the ONLY step needed to keep it out of both sections; nothing
# else in this file needs to change per-check.
_COVERAGE_ONLY_CHECKS = frozenset({"injection.rip_correlation_unavailable"})


def _sorted_for_display(findings_list: list) -> list:
    """detection -> lead -> observation, stable within a tag (original
    construction order preserved via the enumerate index as the
    tie-break) -- a presentation-only reordering. Never mutates or
    reorders `findings_list` itself, and never changes what --json
    (which read `report.findings["findings"]`, built in construction
    order, unaffected by this function) sees. Coverage-only checks (see
    _COVERAGE_ONLY_CHECKS) are dropped here -- the ONE place both KEY
    SIGNALS and WHY THIS VERDICT's "driving finding" pick get filtered
    from, so neither can ever pick one back up independently."""
    key_signal_findings = [f for f in findings_list if f.check not in _COVERAGE_ONLY_CHECKS]
    return [f for _, f in sorted(enumerate(key_signal_findings),
                                  key=lambda pair: (_TAG_RANK.get(pair[1].tag, 3), pair[0]))]


def _coverage_only_impacts(findings_list: list, coverage_reasons: list) -> list:
    """Extra caveat text carried by a coverage-only Finding's own
    `limitations` (see _COVERAGE_ONLY_CHECKS) that ISN'T already said by
    `coverage_reasons` -- e.g. injection.rip_correlation_unavailable's
    limitation explains the SCORE-CAP consequence of the gap, a fact
    coverage_reasons itself never states. Read only from
    Finding.limitations (a structured field already built once by
    aggregate.py), never parsed out of inference/facts text; deduplicated
    against coverage_reasons and against itself so the same caveat is
    never shown twice even if a future coverage-only check repeats one."""
    seen = set(coverage_reasons)
    impacts = []
    for f in findings_list:
        if f.check not in _COVERAGE_ONLY_CHECKS:
            continue
        for limitation in f.limitations:
            if limitation not in seen:
                seen.add(limitation)
                impacts.append(limitation)
    return impacts


def _wrap_block(text: str, width: int, indent: int) -> list:
    """Every line (including the first) indented by the same `indent` --
    unlike `_finding._wrap_labeled`, there's no separate first-line
    prefix here: the label/icon already printed on its own line above."""
    pad = " " * indent
    return [pad + line for line in wrap_text(text, max(1, width - indent), hang_indent=0)]


def _render_verdict_block(status: str, score: int, max_score: int, confidence: str,
                           coverage_status: str, review_priority: str,
                           findings_list: list) -> list:
    if status == NOT_EVALUATED:
        verdict_text = _status_text(status, "no required stream present in this dump")
    else:
        verdict_text = (
            RED("HIGH CONFIDENCE INJECTION") if score >= 3 else
            YELLOW("LIKELY INJECTION") if score == 2 else
            YELLOW("POSSIBLE INJECTION") if score == 1 else
            GREEN("CLEAN" + leads_suffix(findings_list)) if status == NOT_DETECTED_IN_SCANNED_SCOPE else
            YELLOW("INCONCLUSIVE — partial stream coverage" + leads_suffix(findings_list)))
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", confidence),
        ("Score",      f"{score}/{max_score}"),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     review_priority),
    ]
    return render_kv_block(pairs, indent=2)


def _render_key_signal_compact(finding, width: int) -> list:
    title = _TITLES.get(finding.check, finding.check)
    label = _TAG_LABEL.get(finding.tag, finding.tag.upper())
    icon  = _TAG_ICON.get(finding.tag, DIM("[?]"))
    lines = [f"  {icon} {label:<{_LABEL_WIDTH}}  {title}"]
    lines.extend(_wrap_block(finding.inference, width, 6))
    return lines


def _render_why_this_verdict(driving, width: int) -> list:
    """The single Finding that actually drove the verdict -- inference/
    confidence/rationale/first limitation only, normal mode only. Skipped
    entirely in verbose mode: the full KEY SIGNALS block for this SAME
    finding already prints all of this (see render()), and printing it
    twice is exactly the duplication this redesign removes."""
    lines = [f"  {BOLD('WHY THIS VERDICT')}", ""]
    lines.append("  Inference")
    lines.extend(_wrap_block(driving.inference, width, 4))
    lines.append("")
    lines.append(f"  Confidence: {driving.confidence.upper()}")
    lines.extend(_wrap_block(driving.rationale, width, 4))
    if driving.limitations:
        lines.append("")
        lines.append("  Caveat")
        lines.extend(_wrap_block(driving.limitations[0], width, 4))
    lines.append("")
    return lines


def _render_coverage(coverage_status: str, reasons: list, impacts: list, width: int) -> list:
    icon = _COVERAGE_ICON.get(coverage_status, DIM("[?]"))
    lines = [f"  {BOLD('COVERAGE')}", "", f"  {icon} {coverage_status.replace('_', ' ').upper()}"]
    for reason in reasons:
        lines.extend(_wrap_block(reason, width, 6))
    for impact in impacts:
        lines.extend(_wrap_block(f"Impact: {impact}", width, 6))
    lines.append("")
    return lines


def render(report, verbose: bool = False) -> dict:
    """Render the full result and return the LEGACY (Evidence-free, see
    dumpex.hunt.injection.legacy's own docstring) findings dict for the
    caller to hand back."""
    findings = report.findings
    coverage_status = findings["coverage_status"]
    coverage_reasons = findings["coverage_reasons"]
    score = report.score
    status = report.status
    width = resolve_width()
    level = DetailLevel.VERBOSE if verbose else DetailLevel.NORMAL

    _print_hunt_header("Process Injection")

    for line in _render_verdict_block(status, score, findings["max_score"],
                                       findings["confidence"], coverage_status,
                                       findings["review_priority"], report.findings_list):
        print(line)
    print()

    ordered = _sorted_for_display(report.findings_list)
    if ordered:
        print(f"  {BOLD('KEY SIGNALS')}")
        print()
        for f in ordered:
            if verbose:
                title = _TITLES.get(f.check, f.check)
                for line in render_finding_lines(f, level=level, indent=2, width=width, title=title):
                    print(line)
            else:
                for line in _render_key_signal_compact(f, width):
                    print(line)
                print()

    if not verbose:
        driving = ordered[0] if ordered and ordered[0].tag in (TAG_DETECTION, TAG_LEAD) else None
        if driving is not None:
            for line in _render_why_this_verdict(driving, width):
                print(line)

    if coverage_reasons:
        impacts = _coverage_only_impacts(report.findings_list, coverage_reasons)
        for line in _render_coverage(coverage_status, coverage_reasons, impacts, width):
            print(line)

    if not verbose and (report.rwx or report.validated_pe_hits or report.start_threads):
        print(DIM("  Use --verbose for complete per-region evidence and file offsets.\n"))

    return legacy_findings_dict(findings)
