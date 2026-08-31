"""Console rendering for one targeted (``--hunt-addr``) rescan.

A targeted rescan answers a narrower question than a full hunt -- "what does
this one analyzer find in exactly these bytes" -- and its console output says
so at every level. One card is rendered, from the already-built
:class:`~dumpex.output.records.HunterRecord` and the invocation's own
:class:`~dumpex.hunt._observation.ObservationResult`:

* the requested range, normalized, with its end and size, so the scope of
  every statement below is fixed before any of them is read;
* one row per closure, in the adapter's fixed order, with capture and
  evaluation kept in separate columns -- a complete capture can still evaluate
  partially, and a partial capture can be not-evaluated, so collapsing them
  into one "coverage" word would hide the difference an investigator acts on;
* each closure's own diagnostics;
* the findings the analyzer's own scoring produced (or, for YARA, the rule
  matches it reports instead -- YARA deliberately stays off the shared Finding
  model, and a card showing a verdict with nothing behind it would be the one
  analyzer whose evidence never reached the analyst);
* the coverage gaps in what it DID, rendered by the shared limitation
  renderer;
* the analyzer's other coverage sources, named once as what this result is not
  about -- kept out of the COVERAGE block, where five wrapped sentences under a
  "COMPLETE" heading would read as if the scan were broken rather than bounded;
* and a closing scope statement.

The scope statement is the one line that is never omitted: a clean targeted
result is a statement about a range an investigator named, never about the
dump. A negative is stated as covering the requested range only when every
closure completed; otherwise the same line says the range was not fully
evaluated, so no clean banner can be read off a partial rescan.

This module is a pure projection: it returns lines and prints nothing except
through :func:`print_targeted_console`.
"""
from dumpex.hunt._console import resolve_width, render_kv_block
from dumpex.hunt._report_console import (
    COVERAGE_ICON, TAG_ICON, TAG_LABEL, LABEL_WIDTH, header_lines, wrap_block,
)
from dumpex.hunt._ui import (
    DETECTED, INCONCLUSIVE, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, _status_text,
)
from dumpex.hunt._targeted_record import TARGETED_COVERAGE_SOURCE
from dumpex.output.coverage import (
    LimitationCode, display_source_name, render_limitation,
)
from dumpex.ui.colors import BOLD, DIM

__all__ = ["render_targeted_console_lines", "print_targeted_console"]

_CAPTURE_TEXT = {
    "complete": "the whole requested range is captured in this dump",
    "partial":  "only part of the requested range is captured in this dump",
    "none":     "none of the requested range is captured in this dump",
}

_VERDICT_REASON = {
    DETECTED:                      "in the requested range",
    NOT_DETECTED_IN_SCANNED_SCOPE: "in the requested range",
    INCONCLUSIVE:                  "the requested range was not fully evaluated",
    NOT_EVALUATED:                 "the requested range was never evaluated",
}


def _range_rows(request) -> list:
    target = request.target_range
    return [
        ("Hunter", request.selected),
        ("Source", request.targeted_source),
        ("Start",  f"{target.base_address:#018x}"),
        ("End",    f"{target.end_address:#018x}  (exclusive)"),
        ("Size",   f"{target.size:#x}  ({target.size} bytes)"),
    ]


def _verdict_rows(record) -> list:
    """The same verdict-card rows every hunter prints, so an analyst reads a
    targeted result in the shape they already know. ``—`` marks a field the
    analyzer genuinely does not have (YARA's confidence/review/max score), never
    a value that was merely not computed here."""
    max_score = "—" if record.max_score is None else str(record.max_score)
    return [
        ("VERDICT",    _status_text(record.status, _VERDICT_REASON.get(record.status, ""))),
        ("Confidence", record.confidence or "—"),
        ("Score",      f"{record.score}/{max_score}"),
        ("Coverage",   record.coverage.status.value.replace("_", " ").upper()),
        ("Review",     record.review_priority or "—"),
    ]


def _closure_lines(result, width: int) -> list:
    """One block per closure: what the dump held, how far the algorithm got,
    and whatever that closure itself recorded about the difference."""
    lines = [f"  {BOLD('REQUESTED RANGE')}", ""]
    for closure in result.closures:
        icon = COVERAGE_ICON.get(closure.coverage_status, DIM("[?]"))
        name = closure.source if closure.scope is None else f"{closure.source} / {closure.scope}"
        lines.append(f"  {icon} {name}")
        capture = closure.capture_state.value
        # An aligned key/value pair, not wrapped text: word wrapping collapses
        # runs of spaces, so a column built inside a wrapped line would not
        # survive to the terminal.
        # The byte count rides on the capture row, not only the prose: it is
        # what an analyst sizes a re-collection or the next chunk from.
        measured = ("" if closure.captured_bytes is None
                    else f" ({closure.captured_bytes} byte(s) available)")
        lines.extend(render_kv_block(
            [("capture", f"{capture}{measured}"),
             ("evaluation", closure.coverage_status.replace("_", " "))],
            indent=6))
        lines.extend(wrap_block(_CAPTURE_TEXT.get(capture, capture), width, 6))
        for note in closure.diagnostics:
            lines.extend(wrap_block(note, width, 6))
        lines.append("")
    return lines


def _yara_signal_lines(record, width: int, verbose: bool) -> list:
    """YARA's own evidence model. It deliberately stays off the shared Finding
    model -- a rule hit is a structural pattern match, not a
    check/facts/inference judgment -- so its matches live in
    ``details.matches``/``details.rules_hit`` and would otherwise be the one
    analyzer whose targeted card showed a verdict with nothing behind it.

    A rule appears here once, with the hits behind it counted. ``rules_hit``
    is the confidently-classified set that drives the score; a rule that
    matched but could not be classified is shown as such rather than silently
    dropped or silently counted."""
    matches = record.details.matches
    if not matches:
        return []
    triggered = list(record.details.rules_hit)
    by_rule = {}
    for match in matches:
        by_rule.setdefault(match["rule"], []).append(match)
    lines = [f"  {BOLD('KEY SIGNALS')}", ""]
    for rule, hits in by_rule.items():
        icon = TAG_ICON["detection"] if rule in triggered else DIM("[?]")
        label = "DETECTION" if rule in triggered else "UNVERIFIED"
        lines.append(f"  {icon} {label:<{LABEL_WIDTH}}  Rule: {rule}  ({len(hits)} hit(s))")
        files = sorted({hit["file"] for hit in hits})
        lines.extend(wrap_block(", ".join(files), width, 6))
        if verbose:
            for hit in hits:
                lines.extend(wrap_block(
                    f"{hit['seg_va']} ({hit['seg_size']} bytes)", width, 6))
        lines.append("")
    return lines


def _finding_lines(record, width: int, verbose: bool) -> list:
    """The analyzer's own findings for this range. Rendered from the record's
    findings rather than re-derived, so console and JSON cannot disagree about
    what the rescan concluded."""
    if record.hunter == "yara":
        return _yara_signal_lines(record, width, verbose)
    if not record.findings:
        return []
    lines = [f"  {BOLD('KEY SIGNALS')}", ""]
    for finding in record.findings:
        tag = finding["tag"]
        icon = TAG_ICON.get(tag, DIM("[?]"))
        label = TAG_LABEL.get(tag, tag.upper())
        lines.append(f"  {icon} {label:<{LABEL_WIDTH}}  {finding['check']}")
        lines.extend(wrap_block(finding["inference"], width, 6))
        if verbose:
            for fact in finding["facts"]:
                lines.extend(wrap_block(fact, width, 6))
        lines.append("")
    return lines


def _is_out_of_scope(limitation) -> bool:
    """A limitation that bounds what this result is ABOUT rather than reporting
    a gap in what it did -- one of the analyzer's sources outside the single
    grant this invocation covers."""
    return (limitation.code == LimitationCode.TARGETED_SOURCE_NOT_EVALUATED
            and limitation.source != TARGETED_COVERAGE_SOURCE)


def _coverage_lines(record, width: int) -> list:
    """COVERAGE reports gaps in what this rescan DID: the granted closures'
    own. The out-of-scope sources are deliberately not listed here -- five
    wrapped sentences under a "COMPLETE" heading read as if the scan were
    broken, when they are its boundary."""
    gaps = [limitation for limitation in record.coverage.limitations
            if not _is_out_of_scope(limitation)]
    if not gaps:
        return []
    status = record.coverage.status.value
    icon = COVERAGE_ICON.get(status, DIM("[?]"))
    lines = [f"  {BOLD('COVERAGE')}", "", f"  {icon} {status.replace('_', ' ').upper()}"]
    for limitation in gaps:
        lines.extend(wrap_block(render_limitation(limitation), width, 6))
    lines.append("")
    return lines


def _out_of_scope_lines(record, width: int) -> list:
    """The analyzer's other coverage sources, named once and compactly. A
    rescan closes its granted source only, so an analyst reading a clean result
    has to see -- without going to the JSON -- which of that hunter's sources
    this run says nothing about."""
    # Through the same display-name mapping the JSON reasons use: an analyst
    # correlating this card against the document must not meet two vocabularies
    # for one fact.
    sources = sorted(display_source_name(limitation.source)
                     for limitation in record.coverage.limitations
                     if _is_out_of_scope(limitation))
    if not sources:
        return []
    lines = [f"  {BOLD('NOT COVERED BY THIS RESCAN')}", ""]
    lines.extend(wrap_block(
        f"{record.hunter} also reports on {', '.join(sources)}. This rescan covers "
        f"its granted source only, so it neither measures nor closes their coverage.",
        width, 2))
    lines.append("")
    return lines


def _scope_note(record, request, width: int) -> list:
    """The closing statement, always printed. A targeted rescan supplements an
    investigation; it never closes another result's gap, and it never speaks
    for a byte outside the range it was given."""
    target = request.target_range
    span = f"[{target.base_address:#018x}, {target.end_address:#018x})"
    if record.coverage.status.value == "complete":
        body = (f"Every conclusion above applies to {span} only. {request.selected} "
                f"evaluated that range completely through {request.targeted_source}; "
                f"nothing here is a statement about any other address, about any other "
                f"source, or about a coverage gap recorded by an earlier run.")
    else:
        body = (f"Every conclusion above applies to {span} only, and that range was NOT "
                f"fully evaluated -- see the closure rows above for what was and was not "
                f"reached. A negative here is not a clean result for the range, for any "
                f"other address, or for any other source.")
    return [f"  {BOLD('SCOPE')}", ""] + wrap_block(body, width, 2) + [""]


def render_targeted_console_lines(record, result, request, verbose: bool = False,
                                  width: "int | None" = None) -> list:
    """Pure ``(HunterRecord, ObservationResult, HuntRequest) -> list[str]``
    projection -- one line per element, no trailing newlines, no printing."""
    w = resolve_width(width)
    lines = list(header_lines(f"TARGETED RESCAN — {request.selected}"))
    lines.extend(render_kv_block(_range_rows(request)))
    lines.append("")
    lines.extend(render_kv_block(_verdict_rows(record)))
    lines.append("")
    lines.extend(_closure_lines(result, w))
    lines.extend(_finding_lines(record, w, verbose))
    lines.extend(_coverage_lines(record, w))
    lines.extend(_out_of_scope_lines(record, w))
    lines.extend(_scope_note(record, request, w))
    return lines


def print_targeted_console(record, result, request, verbose: bool = False) -> None:
    """Thin, side-effecting wrapper -- prints exactly what
    :func:`render_targeted_console_lines` returns."""
    for line in render_targeted_console_lines(record, result, request, verbose):
        print(line)
