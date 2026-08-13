"""`domain.YaraReport` -> console lines pure projector -- the ONE console
renderer for the YARA hunter, replacing the pre-migration
`presentation.py` (which printed progress lines interleaved with the scan
itself, then a per-rule compact/verbose detail block in alphabetical rule-
name order, then the verdict LAST).

This module never prints (returns the exact lines a caller would print),
and never receives `mf`/a raw `modules` list: every region and string this
module renders was resolved once, at scan time, onto
`report.evidence.matches` (dumpex.hunt.yara_hunt.models.RuleMatchEvidence).

Implements the verdict-first structure approved in issue #1 (verdict block
-> KEY SIGNALS -> WHY THIS VERDICT (normal only) -> unified COVERAGE ->
verbose hint), mirroring `dumpex.hunt.cs_beacon.report_console` (and,
through it, the other completed reference pilots) -- but YARA builds its
own compact/verbose block renderers directly against `RuleMatchEvidence`
rather than `dumpex.hunt._finding.Finding` (there is no Finding here at
all -- see domain.py's own docstring on why). YARA has neither a
Confidence, a max score, nor a Review concept
(`HunterRecord.confidence`/`max_score`/`review_priority` are always
`None` for `hunter="yara"`), but the verdict card still carries those
rows, rendered as an explicit "—" -- the same card SHAPE as every other
hunter, per issue #11's own console scope.

Legacy console byte parity is intentionally NOT preserved (see issue #11's
own console scope) -- reviewed goldens are the target.

What moved, and where (issue #11's console scope, point by point):

  * the hunt header is emitted HERE, via
    `dumpex.hunt._report_console.header_lines()`, instead of a separate
    pre-scan print. The "Loaded N rule file(s)..."/"Scanning N
    segment(s)..."/"Scan complete..." progress lines are gone entirely --
    nothing prints before the Report exists any more;
  * the verdict, score, and coverage status are the FIRST thing rendered,
    as a key/value block;
  * each rule becomes ONE KEY SIGNALS entry (grouped by rule name -- every
    individual match stays in the group, undiscarded; only the REGION
    list shown is deduplicated for display, see `_distinct_regions`),
    ordered confidently-classified (DETECTION) before
    context_unverified-only (CONTEXT) -- a DISPLAY reorder only;
    `report.evidence.matches` construction order (scan order) is never
    touched;
  * WHY THIS VERDICT explains the single alphabetically-first triggered
    rule only, normal mode only;
  * suppressed-match and rule-compile-failure detail render exactly once,
    post-hoc, from the already-built Report -- never printed during
    loading/scanning (issue #11's confirmed gap: "prints rule compilation
    failures from the rule loader while the builder claims to be silent").
"""
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.hunt._ui import DETECTED, NOT_EVALUATED, INCONCLUSIVE, _status_text
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import header_lines, render_coverage, wrap_block
from dumpex.hunt.yara_hunt.domain import YaraReport
from dumpex.hunt.yara_hunt.models import RuleMatchEvidence
from dumpex.hunt.yara_hunt.report_facts import project_coverage_reasons

# Normal-mode per-rule region preview cap -- mirrors the pre-migration
# presentation.py's own "first 5 regions" summary.
MAX_DISPLAYED_REGIONS = 5

_LABEL_WIDTH = max(len("DETECTION"), len("CONTEXT"))


def _group_by_rule(report: YaraReport) -> dict:
    """`report.evidence.matches`, grouped by rule name, first-appearance
    (scan) order preserved within each group and across groups' own
    insertion order -- `_ordered_rule_groups` is what actually decides
    DISPLAY order."""
    groups = {}
    for m in report.evidence.matches:
        groups.setdefault(m.rule, []).append(m)
    return {rule: tuple(matches) for rule, matches in groups.items()}


def _ordered_rule_groups(report: YaraReport, groups: dict) -> list:
    """`(rule, matches)` pairs ordered confidently-classified rules first
    (alphabetical among themselves), then context_unverified-only rules
    (alphabetical) -- a DISPLAY-only reorder; `report.evidence.matches`
    itself is never touched."""
    triggered = set(report.triggered_rules)
    return sorted(groups.items(), key=lambda kv: (0 if kv[0] in triggered else 1, kv[0]))


def _distinct_regions(matches: tuple) -> list:
    """Sorted, DEDUPLICATED-for-display region VAs -- `matches` itself
    keeps every individual match (see scanner.py's own docstring on why
    it must not be deduplicated), but two entries sharing a `seg_va`
    (e.g. the same rule name matching from two different rule files) are
    still ONE physical region to point an analyst at."""
    return sorted({m.seg_va for m in matches})


def _distinct_sources(matches: tuple) -> list:
    """Sorted, deduplicated `(file, namespace)` pairs this group's matches
    actually came from -- shown whenever a rule name resolves to more
    than one, so a console reader can tell "two files define a rule by
    this name" from "one file, several regions"."""
    seen = sorted({(m.file, m.namespace) for m in matches})
    return [f"{file}" if ns == "default" else f"{file}@{ns}" for file, ns in seen]


def _region_preview(matches: tuple) -> str:
    regions = _distinct_regions(matches)
    shown = [f"0x{va:x}" for va in regions[:MAX_DISPLAYED_REGIONS]]
    overflow = len(regions) - len(shown)
    text = f"regions: {', '.join(shown)}"
    if overflow > 0:
        text += f"  … +{overflow} more"
    return text


def _string_preview_lines(m: RuleMatchEvidence, w: int) -> list:
    lines = []
    for s in m.strings:
        is_text = all(0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d) for b in s.data[:64])
        preview = (s.data[:64].decode("ascii", errors="replace").rstrip() if is_text
                   else s.data[:24].hex())
        lines.extend(wrap_block(f"{DIM(f'{s.var:<12}')} VA 0x{s.va:016x}  DMP 0x{s.fo:x}  "
                                 f"{preview}", w, 8))
    if m.strings_truncated:
        # issue #11's confirmed gap: a per-match string-instance cap
        # (config.max_strings_per_match) was previously invisible to both
        # console and callers -- shown explicitly, with the real total,
        # rather than silently listing only the capped subset.
        lines.extend(wrap_block(
            f"… {m.string_count - len(m.strings)} more string instance(s) not shown "
            f"({m.string_count} total)", w, 8))
    return lines


def _render_key_signal_compact(rule: str, matches: tuple, triggered: bool, w: int) -> list:
    first = matches[0]
    n_segs = len(_distinct_regions(matches))
    n_strings = sum(m.string_count for m in matches)
    icon  = RED("[!]") if triggered else DIM("[i]")
    label = "DETECTION" if triggered else "CONTEXT"
    title = f"Rule: {rule}  ({n_segs} region(s), {n_strings} string hit(s))"
    sources = _distinct_sources(matches)
    lines = [f"  {icon} {label:<{_LABEL_WIDTH}}  {title}",
             f"      {DIM(', '.join(sources))}"]
    if first.meta_get("description"):
        lines.extend(wrap_block(first.meta_get("description"), w, 6))
    meta_bits = []
    if first.meta_get("mitre"):
        meta_bits.append(str(first.meta_get("mitre")))
    if first.tags:
        meta_bits.append(", ".join(first.tags))
    if meta_bits:
        lines.extend(wrap_block("  ".join(meta_bits), w, 6))
    lines.extend(wrap_block(_region_preview(matches), w, 6))
    return lines


def _render_key_signal_verbose(rule: str, matches: tuple, triggered: bool, w: int) -> list:
    first = matches[0]
    icon  = RED("[!]") if triggered else DIM("[i]")
    label = "DETECTION" if triggered else "CONTEXT"
    sources = _distinct_sources(matches)
    lines = [f"  {icon} {label:<{_LABEL_WIDTH}}  Rule: {rule}  {DIM('(' + ', '.join(sources) + ')')}"]
    meta_lines = []
    if first.meta_get("description"):
        meta_lines.extend(wrap_block(first.meta_get("description"), w, 4))
    if first.meta_get("reference"):
        meta_lines.extend(wrap_block(f"ref: {first.meta_get('reference')}", w, 4))
    if first.meta_get("mitre"):
        meta_lines.extend(wrap_block(f"MITRE: {first.meta_get('mitre')}", w, 4))
    if first.tags:
        meta_lines.extend(wrap_block(f"tags: {', '.join(first.tags)}", w, 4))
    if meta_lines:
        lines.append("")
        lines.extend(meta_lines)
    lines.append("")
    for m in sorted(matches, key=lambda m: (m.seg_va, m.file, m.namespace)):
        backing = m.backing_module or "(private/unbacked)"
        source_note = "" if len(sources) == 1 else f"  ← {m.file}"
        lines.extend(wrap_block(
            f"Region  VA 0x{m.seg_va:016x}  size 0x{m.seg_size:x}  ← {backing}{source_note}",
            w, 6))
        lines.extend(_string_preview_lines(m, w))
        lines.append("")
    return lines


def _render_why_this_verdict(rule: str, matches: tuple, w: int) -> list:
    """Build the driving inference from the group's OWN evidence facts --
    never a blanket claim. Issue #11's confirmed P1: this used to
    unconditionally assert the match "could not be attributed to a known,
    legitimately loaded module" even when `backing_module` WAS set (a
    high-specificity, unscoped rule -- e.g. PE_In_Private_Memory is
    scoped, but a rule with no `dumpex_scope` meta is trusted regardless
    of context and can legitimately fire inside a known module)."""
    first = matches[0]
    n_segs = len(_distinct_regions(matches))
    n_strings = sum(m.string_count for m in matches)
    backing_modules = sorted({m.backing_module for m in matches if m.backing_module})
    if backing_modules:
        context_clause = f"found within module(s): {', '.join(backing_modules)}"
    else:
        contexts = sorted({m.memory_context for m in matches if m.memory_context})
        context_clause = (f"resolved to {'/'.join(contexts)} memory, not a known loaded module"
                           if contexts else
                           "module/region context could not be resolved for this address")
    lines = [f"  {BOLD('WHY THIS VERDICT')}", "", "  Inference"]
    lines.extend(wrap_block(
        f"Rule {rule!r} matched {n_segs} region(s) ({n_strings} string hit(s)) -- {context_clause}.",
        w, 4))
    if first.meta_get("description"):
        lines.append("")
        lines.extend(wrap_block(first.meta_get("description"), w, 4))
    lines.append("")
    return lines


def _render_verdict_block(report: YaraReport, coverage_status: str, reasons: list) -> list:
    status, score = report.status, report.score
    if status == NOT_EVALUATED:
        verdict_text = _status_text(NOT_EVALUATED, reasons[0] if reasons else "")
    elif status == DETECTED:
        verdict_text = (RED(f"HIGH — {score} distinct rule(s) matched") if score >= 3 else
                         YELLOW(f"MEDIUM — {score} distinct rule(s) matched"))
    elif status == INCONCLUSIVE:
        if report.has_hits and not report.triggered_rules:
            verdict_text = YELLOW(f"INCONCLUSIVE — {len(report.unverified_rules)} rule(s) "
                                   f"matched but could not be classified (context_unverified)")
        else:
            verdict_text = YELLOW("INCONCLUSIVE — coverage was incomplete")
    else:
        verdict_text = GREEN("CLEAN — no rules matched")
    # Max score/Confidence/Review are explicit "—" placeholders, not
    # omitted rows -- issue #11's own console scope: "unsupported max-
    # score/confidence/review fields use explicit —". YARA genuinely has
    # none of these three (HunterRecord.max_score/confidence/
    # review_priority are always None for hunter="yara"; score itself has
    # no fixed ceiling, unlike every Finding-model hunter's 0..max_score),
    # but the verdict-first CARD SHAPE stays the same across every
    # hunter -- an analyst scanning several hunters' output should see
    # the same rows, not a differently-shaped card for this one.
    pairs = [
        ("VERDICT",    verdict_text),
        ("Confidence", "—"),
        ("Score",      f"{score}/—"),
        ("Coverage",   coverage_status.replace("_", " ").upper()),
        ("Review",     "—"),
    ]
    return render_kv_block(pairs, indent=2)


def _suppression_note(report: YaraReport) -> list:
    """One DIM line per suppression reason -- kept as two INDEPENDENT
    lines (rather than merged into one) so each carries its own exact,
    greppable wording ("PE_In_Private_Memory match(es) suppressed" /
    "scoped rule match(es) suppressed"), and renders from the Report
    exactly ONCE regardless of mode -- the pre-migration bug this guards
    against printed the same two lines a second time from
    `presentation.render_result()` whenever `has_hits` was True."""
    scan = report.coverage.scan
    lines = []
    if scan.suppressed_module_pe:
        lines.append(DIM(f"  [i] {scan.suppressed_module_pe} PE_In_Private_Memory match(es) "
                          f"suppressed — MZ/PE header belonged to a known, legitimately loaded "
                          f"module."))
    if scan.suppressed_scoped:
        lines.append(DIM(f"  [i] {scan.suppressed_scoped} scoped rule match(es) suppressed — "
                          f"resolved to a known module or a MEM_IMAGE region."))
    if lines:
        lines.append("")
    return lines


def _compile_failure_lines(report: YaraReport, w: int, verbose: bool) -> list:
    provenance = report.coverage.rules.provenance
    if provenance is None or provenance.compile_failed == 0 or not verbose:
        return []
    lines = [f"  {BOLD('RULE COMPILE FAILURES')}", ""]
    for f in provenance.files:
        if not f.compiled:
            lines.extend(wrap_block(f"{f.name}: {f.error}", w, 4))
    lines.append("")
    return lines


def render_console_lines(report: YaraReport, verbose: bool = False,
                          width: "int | None" = None) -> list:
    """Pure `YaraReport -> list[str]` projection -- one line per list
    element, no trailing newline characters, no `print()` calls, and no
    `mf`/raw `modules`."""
    w = resolve_width(width)
    coverage_status, reasons = project_coverage_reasons(report)

    lines = list(header_lines("YARA Memory Scan"))
    lines.extend(_render_verdict_block(report, coverage_status, reasons))
    lines.append("")

    if report.status == NOT_EVALUATED:
        # The VERDICT line above already carries the one reason that
        # applies (see `_render_verdict_block`) -- no separate COVERAGE
        # section here. This also sidesteps a real reproducibility trap: a
        # "no rules directory"/"no usable files" reason embeds the
        # resolved rules_dir's OWN absolute path, whose length varies
        # per-run/per-machine (`tmp_path`, a packaged-install path, ...);
        # routing it through `render_coverage`'s word-wrap would make the
        # wrap POINT itself depend on that length, so two runs with a
        # differently-sized path could wrap identical reason text onto a
        # different number of lines -- unlike the VERDICT line (an
        # unwrapped key/value row), which stays byte-stable regardless.
        return lines

    lines.extend(_suppression_note(report))

    groups = _group_by_rule(report)
    ordered = _ordered_rule_groups(report, groups)
    if ordered:
        lines.append(f"  {BOLD('KEY SIGNALS')}")
        lines.append("")
        for rule, matches in ordered:
            triggered = rule in report.triggered_rules
            if verbose:
                lines.extend(_render_key_signal_verbose(rule, matches, triggered, w))
            else:
                lines.extend(_render_key_signal_compact(rule, matches, triggered, w))
                lines.append("")

    if not verbose and report.triggered_rules:
        driving_rule = report.triggered_rules[0]
        lines.extend(_render_why_this_verdict(driving_rule, groups[driving_rule], w))

    if reasons:
        lines.extend(render_coverage(coverage_status, reasons, w))
    lines.extend(_compile_failure_lines(report, w, verbose))

    if not verbose and report.has_hits:
        lines.append(DIM("  Use --verbose for the complete region and string match detail.\n"))

    return lines


def print_console(report: YaraReport, verbose: bool = False) -> None:
    """Thin, side-effecting convenience wrapper -- prints exactly what
    `render_console_lines` returns."""
    for line in render_console_lines(report, verbose):
        print(line)
