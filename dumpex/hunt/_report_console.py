"""Shared verdict-first console components for hunter reports.

Helpers render headers, key signals, rationale, and coverage from completed
reports. Display ordering and verbose expansion do not mutate evidence, rescore
findings, or alter structured output.
"""
import dataclasses

from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._console import wrap_text
from dumpex.hunt._finding import Finding, TAG_DETECTION, TAG_LEAD, TAG_OBSERVATION
from dumpex.output.coverage import format_missed_bytes_clause

# ── Signal tag -> icon/label/sort-rank, and coverage-status -> icon ──────
# Byte-identical across both pilots' report_console.py before this
# extraction: the same three-tag vocabulary (DETECTION/LEAD/CONTEXT) and
# the same three-state coverage vocabulary (complete/partial/
# not_evaluated) every hunter's KEY SIGNALS/COVERAGE sections already
# render from, via dumpex.hunt._finding.CheckResult.tag and
# dumpex.hunt._coverage.derive_coverage_status's own three return values.
TAG_ICON  = {TAG_DETECTION: RED("[!]"), TAG_LEAD: YELLOW("[~]"), TAG_OBSERVATION: DIM("[i]")}
TAG_LABEL = {TAG_DETECTION: "DETECTION", TAG_LEAD: "LEAD", TAG_OBSERVATION: "CONTEXT"}
TAG_RANK  = {TAG_DETECTION: 0, TAG_LEAD: 1, TAG_OBSERVATION: 2}
LABEL_WIDTH = max(len(label) for label in TAG_LABEL.values())

COVERAGE_ICON = {"complete": GREEN("[✓]"), "partial": YELLOW("[~]"), "not_evaluated": DIM("[-]")}


def header_lines(title: str) -> list:
    """The hunt-section header banner, as data instead of a `print()` side
    effect -- a pure projector must not print directly."""
    bar = BOLD("══════════════════════════════════════════")
    return ["", bar, BOLD(f"  HUNT: {title}"), bar, ""]


def coverage_kv_value(coverage_status: str, coverage_report) -> str:
    """The Coverage row of a hunter card's key/value block: the status
    word, plus how much captured memory the run's gaps add up to.

    The clause is what separates a `partial` that missed one unreadable
    4 KB region from one that missed gigabytes across forty oversized
    ones -- the same word, and opposite answers to whether the dump is
    worth recollecting. It is omitted entirely when no gap costs
    capturable bytes, so a `complete` scan (and a `partial` whose reasons
    are not about unread memory) reads exactly as it did before.

    `coverage_report` is REQUIRED, with no default: a renderer that
    forgot to pass it would silently drop the quantification from that
    hunter's card and nothing would fail."""
    text = coverage_status.replace("_", " ").upper()
    clause = format_missed_bytes_clause(coverage_report.missed_bytes)
    return f"{text} — {clause}" if clause else text


def wrap_block(text: str, width: int, indent: int) -> list:
    """`text`, word-wrapped to `width - indent` visible columns and
    prefixed with `indent` spaces on every line (including the first --
    unlike `dumpex.hunt._console.wrap_text`, which leaves the first line
    unindented for a caller prepending its own label)."""
    pad = " " * indent
    return [pad + line for line in wrap_text(text, max(1, width - indent), hang_indent=0)]


def sorted_for_display(findings: list, exclude_checks: frozenset = frozenset()) -> list:
    """`findings`, minus any whose `check` is in `exclude_checks` (a
    hunter's own coverage-only checks, if it has any -- see
    dumpex.hunt.injection.report_console's `_COVERAGE_ONLY_CHECKS`),
    ordered DETECTION -> LEAD -> CONTEXT with construction order preserved
    within a class (a stable sort keyed on (tag rank, original index))."""
    eligible = [f for f in findings if f.check not in exclude_checks]
    return [f for _, f in sorted(enumerate(eligible),
                                  key=lambda pair: (TAG_RANK.get(pair[1].tag, 3), pair[0]))]


def render_key_signal_compact(finding, width: int, titles: dict) -> list:
    """One KEY SIGNALS entry in normal (non-verbose) mode: an icon/label/
    title header line plus the finding's own wrapped inference -- no
    facts, no confidence/rationale (that's WHY THIS VERDICT's job for the
    single driving finding, and --verbose's job for the rest)."""
    title = titles.get(finding.check, finding.check)
    label = TAG_LABEL.get(finding.tag, finding.tag.upper())
    icon  = TAG_ICON.get(finding.tag, DIM("[?]"))
    lines = [f"  {icon} {label:<{LABEL_WIDTH}}  {title}"]
    lines.extend(wrap_block(finding.inference, width, 6))
    return lines


def render_why_this_verdict(driving, width: int) -> list:
    """The normal-mode WHY THIS VERDICT block for `driving` (the single
    check that actually justified the verdict -- see each hunter's own
    `render_console_lines` for how it picks that finding). Shows the
    finding's inference, confidence + rationale, and its first limitation
    (if any) as a caveat -- never more than one, matching every existing
    caller's own behavior."""
    lines = [f"  {BOLD('WHY THIS VERDICT')}", ""]
    lines.append("  Inference")
    lines.extend(wrap_block(driving.inference, width, 4))
    lines.append("")
    lines.append(f"  Confidence: {driving.confidence.upper()}")
    lines.extend(wrap_block(driving.rationale, width, 4))
    if driving.limitations:
        lines.append("")
        lines.append("  Caveat")
        lines.extend(wrap_block(driving.limitations[0], width, 4))
    lines.append("")
    return lines


def render_coverage(coverage_status: str, reasons: list, width: int, impacts: list = ()) -> list:
    """The unified COVERAGE section: a status icon/line, one wrapped line
    per gap reason, then one wrapped `Impact:`-prefixed line per
    score/verdict consequence a coverage-only finding attached (`impacts`
    -- empty for a hunter with no coverage-only checks, e.g. obfuscation;
    see dumpex.hunt.injection.report_console's `_coverage_only_impacts`
    for how injection builds its own)."""
    icon = COVERAGE_ICON.get(coverage_status, DIM("[?]"))
    lines = [f"  {BOLD('COVERAGE')}", "", f"  {icon} {coverage_status.replace('_', ' ').upper()}"]
    for reason in reasons:
        lines.extend(wrap_block(reason, width, 6))
    for impact in impacts:
        lines.extend(wrap_block(f"Impact: {impact}", width, 6))
    lines.append("")
    return lines


def with_verbose_facts(finding: Finding, verbose_facts: tuple) -> Finding:
    """`finding`, unchanged if `verbose_facts` is empty, else a copy
    carrying it -- the one-line pattern both pilots' own `_console_finding`
    repeated verbatim around their per-check verbose-fact renderers."""
    if not verbose_facts:
        return finding
    return dataclasses.replace(finding, verbose_facts=list(verbose_facts))
