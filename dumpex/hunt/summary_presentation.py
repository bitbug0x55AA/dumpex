"""Renderer for `--hunt all`'s closing `HUNT SUMMARY` -- Step 1.5, console
presentation patch. Reads ONLY `HunterRecord`/`build_hunt_summary()`
output (dumpex.hunt.summary's own cross-hunter reducer) plus the
already-built document-level coverage status string and (optionally) the
already-built `RegionCorrelation` list (dumpex.hunt.region_correlation's
own display-only cross-hunter co-location reducer); never touches the
legacy per-hunter `results` dict `cmd_hunt()` still builds for its own
return value and cs-beacon/yara byte-sanitization -- this function's own
signature has no parameter for it at all, so there is nothing to read
even by accident (see tests/integration/test_hunt_all_summary_source.py
for the end-to-end proof that a poisoned console-dict value cannot
influence this output).

Five sections, in order:
  REVIEW FIRST       -- DETECTED hunters, ranked by how urgently they need
                        a look: verdict_level, then review_priority, then
                        confidence, all descending; HUNTERS' own fixed
                        order is the final, deterministic tie-break.
  NEEDS ATTENTION     -- INCONCLUSIVE / NOT_EVALUATED hunters, plus any
                        NOT_DETECTED_IN_SCANNED_SCOPE hunter that still
                        carries unscored leads or partial coverage -- a
                        clean verdict there is real, but not the whole
                        story.
  OTHER HUNTERS       -- everything else: clean, complete coverage, no
                        leads.
  CORRELATED REGIONS  -- only shown when `region_correlations` is
                        non-empty: two or more different hunters whose
                        evidence resolved to the SAME normalized MemoryInfo
                        region. Co-location only -- never a causal or
                        scoring claim, see dumpex.hunt.region_correlation's
                        own module docstring.
  NEXT INVESTIGATION  -- 1-3 deterministic, structurally-derived action
                        lines, drawn only from the fields above. Never
                        names a malware family, ATT&CK technique, or any
                        other inference not already present on a
                        Finding/HunterRecord.
"""
from dumpex.ui.colors import RED, YELLOW, GREEN, DIM, BOLD
from dumpex.hunt._console import resolve_width, wrap_text, render_kv_block
from dumpex.hunt.summary import _DETECTED_VERDICT_ORDER
from dumpex.hunt.region_correlation import RegionCorrelation
from dumpex.output.records import HUNTERS, HunterRecord, _HUNT_CONFIDENCES, _HUNT_REVIEW_PRIORITIES

_DISPLAY_NAME = {
    "injection":   "Process Injection",
    "hollowing":   "Process Hollowing",
    "stomping":    "Module Stomping",
    "pipe":        "Named Pipe C2 / Lat. Move.",
    "cs-beacon":   "Cobalt Strike Beacon",
    "yara":        "YARA Rules",
    "obfuscation": "Obfuscation Detection",
}
# Fixed (not recomputed per-call from whichever subset of hunters actually
# appears) so REVIEW FIRST/OTHER HUNTERS' name column never shifts between
# runs depending on which hunters happen to be DETECTED/clean this time --
# see this module's own "long hunter name doesn't break column alignment"
# test.
_NAME_WIDTH = max(len(name) for name in _DISPLAY_NAME.values())

_VERDICT_COLOR    = {"high": RED, "likely": RED, "possible": YELLOW}
_PRIORITY_RANK    = {value: i for i, value in enumerate(_HUNT_REVIEW_PRIORITIES)}
_CONFIDENCE_RANK  = {value: i for i, value in enumerate(_HUNT_CONFIDENCES)}
_FINDING_TAG_RANK = {"detection": 0, "lead": 1, "observation": 2}


def _wrap_block(text: str, width: int, indent: int) -> list:
    pad = " " * indent
    return [pad + line for line in wrap_text(text, max(1, width - indent), hang_indent=0)]


def _numbered_item(n: int, text: str, width: int) -> list:
    prefix = f"  {n}. "
    wrapped = wrap_text(text, max(1, width - len(prefix)), hang_indent=0)
    if not wrapped:
        return [prefix.rstrip()]
    pad = " " * len(prefix)
    return [prefix + wrapped[0]] + [pad + line for line in wrapped[1:]]


def _best_finding(findings: list) -> "dict | None":
    """The single best Finding dict (Finding.to_dict() shape) out of a
    HunterRecord's own `findings` list -- tag=='detection' beats
    tag=='lead' beats anything else, ties broken by confidence rank
    (high first). None when `findings` is empty (always true for yara;
    see _headline_for()'s own yara fallback below)."""
    if not findings:
        return None
    return min(findings, key=lambda f: (
        _FINDING_TAG_RANK.get(f.get("tag"), 3),
        -_CONFIDENCE_RANK.get(f.get("confidence"), -1),
    ))


def _headline_for(record: HunterRecord) -> "str | None":
    """The one-line 'why' for a REVIEW FIRST/NEEDS ATTENTION entry --
    straight from a real Finding's own `inference`, or (yara only, whose
    HunterRecord.findings is always []) from its own structured
    `rules_hit` list. Never parsed out of free text, never fabricated."""
    best = _best_finding(record.findings)
    if best is not None:
        return best["inference"]
    if record.hunter == "yara" and getattr(record.details, "rules_hit", None):
        hits = record.details.rules_hit
        shown = ", ".join(hits[:3])
        overflow = f" (+{len(hits) - 3} more)" if len(hits) > 3 else ""
        return f"Rule(s) matched: {shown}{overflow}"
    return None


def _pivots_for(record: HunterRecord) -> "str | None":
    """A short 'Pivots: ...' line built ONLY from structured
    evidence_refs/iocs already present on the record's best Finding --
    never parsed out of facts/inference text. None (no line at all) when
    neither is set -- the case for every hunter today (see this module's
    own docstring)."""
    best = _best_finding(record.findings)
    if best is None:
        return None
    pivots = list(best.get("evidence_refs") or []) + list(best.get("iocs") or [])
    if not pivots:
        return None
    return " · ".join(pivots[:4])


def _partition(records: list) -> "tuple[list, list, list]":
    """One pass: (review_first, needs_attention, other_hunters)."""
    review_first, needs_attention, other = [], [], []
    for r in records:
        if r.status == "DETECTED":
            review_first.append(r)
        elif r.status in ("INCONCLUSIVE", "NOT_EVALUATED"):
            needs_attention.append(r)
        elif r.status == "NOT_DETECTED_IN_SCANNED_SCOPE" and (
                (r.lead_count or 0) > 0 or r.coverage.status.value != "complete"):
            needs_attention.append(r)
        else:
            other.append(r)
    return review_first, needs_attention, other


def _review_first_sort_key(record: HunterRecord):
    verdict_rank = (_DETECTED_VERDICT_ORDER.index(record.verdict_level)
                     if record.verdict_level in _DETECTED_VERDICT_ORDER else -1)
    priority_rank = _PRIORITY_RANK.get(record.review_priority, -1)
    confidence_rank = _CONFIDENCE_RANK.get(record.confidence, -1)
    # Negated ranks (descending severity/priority/confidence), HUNTERS'
    # own index ascending as the final, deterministic tie-break -- see
    # this module's own docstring.
    return (-verdict_rank, -priority_rank, -confidence_rank, HUNTERS.index(record.hunter))


def _render_header(summary: dict, doc_coverage_status: str, width: int) -> list:
    parts = []
    if summary["detected_count"]:
        parts.append(f"{summary['detected_count']} detected")
    if summary["lead_count"]:
        parts.append(f"{summary['lead_count']} lead(s)")
    if summary["inconclusive_count"]:
        parts.append(f"{summary['inconclusive_count']} inconclusive")
    if summary["not_evaluated_count"]:
        parts.append(f"{summary['not_evaluated_count']} not evaluated")
    results_text = (" · ".join(parts) if parts else
                     f"{summary['hunter_count']} hunter(s) run — none detected, no leads")
    pairs = [
        ("OVERALL",  summary["overall_status"].replace("_", " ")),
        ("Highest",  summary["highest_verdict_level"].replace("_", " ").upper()),
        ("Coverage", doc_coverage_status.replace("_", " ").upper()),
        ("Results",  results_text),
    ]
    return render_kv_block(pairs, indent=2)


def _render_review_first(ordered: list, width: int) -> list:
    lines = [f"  {BOLD('REVIEW FIRST')}", ""]
    for i, record in enumerate(ordered, 1):
        name = _DISPLAY_NAME.get(record.hunter, record.hunter)
        color = _VERDICT_COLOR.get(record.verdict_level, YELLOW)
        badge = f"{color(record.verdict_level.upper())} · {record.coverage.status.value.replace('_', ' ').upper()}"
        lines.append(f"  {i}. {name:<{_NAME_WIDTH}}  {badge}")
        headline = _headline_for(record)
        if headline:
            lines.extend(_wrap_block(headline, width, 5))
        pivots = _pivots_for(record)
        if pivots:
            lines.extend(_wrap_block(f"Pivots: {pivots}", width, 5))
        lines.append("")
    return lines


def _needs_attention_reason(record: HunterRecord) -> str:
    reasons = record.coverage.reasons
    if record.status == "NOT_EVALUATED":
        return f"Not evaluated: {reasons[0] if reasons else 'required data source unavailable'}"
    if record.status == "INCONCLUSIVE":
        return f"Inconclusive: {reasons[0] if reasons else 'coverage incomplete'}"
    # NOT_DETECTED_IN_SCANNED_SCOPE but flagged for leads and/or partial coverage
    bits = []
    if (record.lead_count or 0) > 0:
        bits.append(f"{record.lead_count} unscored lead(s)")
    if record.coverage.status.value != "complete":
        bits.append(reasons[0] if reasons else "coverage is partial")
    if not bits:
        bits.append("coverage is incomplete")
    return f"Clean verdict, but {', '.join(bits)} — review before treating this as fully clean."


def _render_needs_attention(records: list, width: int) -> list:
    lines = [f"  {BOLD('NEEDS ATTENTION')}", ""]
    for record in records:
        name = _DISPLAY_NAME.get(record.hunter, record.hunter)
        icon = DIM("[-]") if record.status == "NOT_EVALUATED" else YELLOW("[~]")
        lines.append(f"  {icon} {name}")
        lines.extend(_wrap_block(_needs_attention_reason(record), width, 6))
        lines.append("")
    return lines


def _render_other_hunters(records: list, width: int) -> list:
    lines = [f"  {BOLD('OTHER HUNTERS')}", ""]
    for record in records:
        name = _DISPLAY_NAME.get(record.hunter, record.hunter)
        lines.append(f"  {name:<{_NAME_WIDTH}}  {GREEN('CLEAN')}")
    lines.append("")
    return lines


# ── CORRELATED REGIONS ────────────────────────────────────────────────────
# Abbreviated per-hunter labels for the "Evidence" lines only -- distinct
# from _DISPLAY_NAME (used for the "Hunters" line, kept full so it reads
# consistently with REVIEW FIRST/NEEDS ATTENTION/OTHER HUNTERS above).
_EVIDENCE_HUNTER_LABEL = {
    "injection":   "Injection",
    "hollowing":   "Hollowing",
    "stomping":    "Stomping",
    "pipe":        "Pipe",
    "cs-beacon":   "CS Beacon",
    "yara":        "YARA",
    "obfuscation": "Obfuscation",
}
_MAX_EVIDENCE_LABELS = 3
_MAX_CORRELATED_REGIONS = 20   # printed entries -- see _render_correlated_regions()
_CORRELATION_LABEL_WIDTH = len("Allocation")
_CORRELATION_INDENT = 5


def _hexaddr(n: int) -> str:
    return f"0x{n:016x}"


def _correlation_badge(record: HunterRecord) -> str:
    """`[VERDICT]` badge for one hunter inside a CORRELATED REGIONS entry's
    'Hunters' line -- always the record's own real `verdict_level` (never
    re-derived), colored the same way REVIEW FIRST's own badge is for the
    three DETECTED-only levels, GREEN/YELLOW/DIM for the three a
    lead-only (status != DETECTED but lead_count > 0) record can still
    carry."""
    color = _VERDICT_COLOR.get(record.verdict_level)
    if color is None:
        color = {"clean": GREEN, "inconclusive": YELLOW, "not_evaluated": DIM}.get(
            record.verdict_level, DIM)
    return color(record.verdict_level.replace("_", " ").upper())


def _evidence_items(corr: RegionCorrelation) -> list:
    """One text item per hunter present in `corr`, `HUNTERS`' own fixed
    order, e.g. `"Injection: validated hidden PE; live RIP/EIP in
    suspicious region"` -- built ONLY from this correlation's own
    `RegionSignal.label`s (never decoded/raw bytes, never a full Beacon
    config -- see dumpex.hunt.region_correlation's own docstring for what
    each label is derived from). Labels are de-duplicated in first-seen
    order and capped at `_MAX_EVIDENCE_LABELS`, with a `(+N more)` suffix
    -- the same "bounded, deterministic overflow" shape
    `_headline_for()`'s own yara rules_hit fallback above uses."""
    items = []
    for hunter in corr.hunters:
        labels = []
        for sig in corr.signals:
            if sig.hunter == hunter and sig.label not in labels:
                labels.append(sig.label)
        shown = labels[:_MAX_EVIDENCE_LABELS]
        overflow = len(labels) - len(shown)
        text = "; ".join(shown)
        if overflow > 0:
            text += f" (+{overflow} more)"
        items.append(f"{_EVIDENCE_HUNTER_LABEL.get(hunter, hunter)}: {text}")
    return items


def _render_kv_wrapped(pairs: list, width: int) -> list:
    """`pairs` is `[(label, [value_line, ...]), ...]` -- each value_line is
    independently word-wrapped to `width`, with every physical line
    (whether from wrapping a single long value or from a second/third
    `value_line` under the same label -- CORRELATED REGIONS' own
    'Evidence' entry, one value_line per hunter) aligned under the same
    column, no label repeated. Mirrors `render_kv_block()`'s own aligned-
    label convention (`_CORRELATION_LABEL_WIDTH` = the longest label,
    'Allocation') but adds per-value wrapping, which `render_kv_block()`
    itself deliberately does not do (no existing caller needed it before
    CORRELATED REGIONS' own multi-hunter Evidence lines)."""
    lines = []
    pad = " " * _CORRELATION_INDENT
    for label, value_lines in pairs:
        prefix = f"{pad}{label:<{_CORRELATION_LABEL_WIDTH}}  "
        cont_pad = " " * len(prefix)
        avail = max(1, width - len(prefix))
        first = True
        for value_line in value_lines:
            wrapped = wrap_text(value_line, avail, hang_indent=0) or [""]
            for w in wrapped:
                lines.append((prefix if first else cont_pad) + w)
                first = False
    return lines


def _render_correlation_entry(n: int, corr: RegionCorrelation, record_by_hunter: dict,
                               width: int) -> list:
    # _numbered_item() (not a bare wrap_text() call) -- wrap_text() itself
    # rejoins on `text.split()`, which silently collapses/strips any
    # leading indent baked into the text BEFORE it reaches wrap_text(), the
    # same reason REVIEW FIRST/NEXT INVESTIGATION's own numbered lines
    # above already go through this helper instead.
    lines = _numbered_item(
        n, f"Region {_hexaddr(corr.region_base)} size=0x{corr.region_size:x}", width)

    pairs = []
    if corr.allocation_base is not None:
        pairs.append(("Allocation", [_hexaddr(corr.allocation_base)]))
    hunters_text = " · ".join(
        f"{_DISPLAY_NAME.get(h, h)} [{_correlation_badge(record_by_hunter[h])}]"
        for h in corr.hunters)
    pairs.append(("Hunters", [hunters_text]))
    pairs.append(("Evidence", _evidence_items(corr)))

    lines.extend(_render_kv_wrapped(pairs, width))
    lines.append("")
    return lines


def _render_correlated_regions(correlations: list, records: list, width: int) -> list:
    """Empty (nothing printed, no header) when `correlations` is empty --
    CORRELATED REGIONS never appears as an empty section (see
    render_hunt_summary()'s own call site). The "co-location only" caveat
    is printed exactly once for the whole section, not per region.

    `correlations` is already sorted by `build_region_correlations()`'s own
    deterministic rule (hunter count, then severity, then signal count,
    then region_base -- see that function's own docstring); this renderer
    only ever TRUNCATES that order, never re-sorts, so printing the first
    `_MAX_CORRELATED_REGIONS` entries always shows the most noteworthy
    ones. A run with more correlated regions than that cap says so
    explicitly (`N additional correlated region(s) omitted`) rather than
    silently dropping the rest -- unbounded per-hunter scan budgets (yara's
    up to ~2000 matches, obfuscation's own per-layer caps, ...) mean the
    true number of correlated regions has no small upper bound on its
    own."""
    if not correlations:
        return []
    record_by_hunter = {r.hunter: r for r in records}
    shown = correlations[:_MAX_CORRELATED_REGIONS]
    omitted = len(correlations) - len(shown)
    lines = [f"  {BOLD('CORRELATED REGIONS')}", ""]
    for i, corr in enumerate(shown, 1):
        lines.extend(_render_correlation_entry(i, corr, record_by_hunter, width))
    if omitted > 0:
        lines.extend(_wrap_block(
            f"... {omitted} additional correlated region(s) omitted from this summary.",
            width, _CORRELATION_INDENT))
        lines.append("")
    lines.extend(_wrap_block(
        "Co-location only — this relationship does not change hunter scores or verdicts.",
        width, _CORRELATION_INDENT))
    lines.append("")
    return lines


def _build_next_investigation_steps(review_first_ordered: list, records: list, summary: dict) -> list:
    steps = []
    if review_first_ordered:
        top = review_first_ordered[0]
        name = _DISPLAY_NAME.get(top.hunter, top.hunter)
        steps.append(f"Review {name}'s finding(s) and evidence refs first — it has the "
                      f"highest-priority detection in this scan.")
    partial_sources = []
    for record in records:
        if record.coverage.status.value != "complete":
            for reason in record.coverage.reasons:
                if reason not in partial_sources:
                    partial_sources.append(reason)
    if partial_sources:
        shown = "; ".join(partial_sources[:3])
        overflow = f" (+{len(partial_sources) - 3} more)" if len(partial_sources) > 3 else ""
        steps.append(f"Fill in coverage before trusting a clean result: {shown}{overflow}.")
    if summary["lead_count"]:
        steps.append(f"Review {summary['lead_count']} unscored lead(s) across the hunters "
                      f"above before closing this case.")
    if not steps:
        steps.append("No further action required — every hunter ran to completion with no findings.")
    return steps


def render_hunt_summary(records: list, summary: dict, doc_coverage_status: str, *,
                         width: "int | None" = None,
                         region_correlations: "list | None" = None) -> None:
    """Print the `--hunt all` `HUNT SUMMARY` card. `records` must be the
    same 7-element `list[HunterRecord]` (HUNTERS' own fixed order)
    `dumpex.hunt.summary.build_hunt_summary()` was called with to produce
    `summary`; `doc_coverage_status` is the document-level
    `CommandResult.coverage.status.value` cmd_hunt() already computes via
    `_hunt_coverage_report()` (see that function's own docstring for why
    it's a separate, non-per-hunter rollup). `region_correlations` is the
    optional `list[RegionCorrelation]` `dumpex.hunt.region_correlation.
    build_region_correlations()` already built from these same `records`
    plus the dump's own MemoryInfo list -- `None` or `[]` (the default)
    means CORRELATED REGIONS is omitted entirely, leaving every other
    section byte-identical to before this parameter existed."""
    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("render_hunt_summary() records must be a list of HunterRecord")
    if region_correlations is not None and (
            not isinstance(region_correlations, list)
            or any(not isinstance(c, RegionCorrelation) for c in region_correlations)):
        raise TypeError("render_hunt_summary() region_correlations must be None or a "
                         "list of RegionCorrelation")
    w = resolve_width(width)

    print(BOLD("══════════════════════════════════════════"))
    print(BOLD("  HUNT SUMMARY"))
    print(BOLD("══════════════════════════════════════════"))
    for line in _render_header(summary, doc_coverage_status, w):
        print(line)
    print()

    review_first, needs_attention, other = _partition(records)
    review_first_ordered = sorted(review_first, key=_review_first_sort_key)

    if review_first_ordered:
        for line in _render_review_first(review_first_ordered, w):
            print(line)
    if needs_attention:
        for line in _render_needs_attention(needs_attention, w):
            print(line)
    if other:
        for line in _render_other_hunters(other, w):
            print(line)

    if region_correlations:
        for line in _render_correlated_regions(region_correlations, records, w):
            print(line)

    steps = _build_next_investigation_steps(review_first_ordered, records, summary)
    lines = [f"  {BOLD('NEXT INVESTIGATION')}", ""]
    for i, step in enumerate(steps[:3], 1):
        lines.extend(_numbered_item(i, step, w))
    for line in lines:
        print(line)
    print()
