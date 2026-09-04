"""What a hunter card's Coverage row claims, and what bounds it.

The row carries a status word and up to two clauses, and the clauses grade
two different things:

  * the BYTE clause grades the scanning workload -- how much captured
    memory this hunter had in front of it and how much of that it got
    through;
  * the EVIDENCE clause grades everything else -- the streams, reference
    files and per-thread CONTEXT a hunter needs and a dump may not carry.

`partial` is the status word neither clause settles on its own: a run can
finish every eligible byte and still be `partial` for a stream it never
got. These tests pin that the row states both dimensions, that a gap the
byte figure only COUNTS is named rather than left to that count, and that
the row stays inside the terminal it is drawn on.
"""
import ast
import pathlib

import pytest

from dumpex.hunt._report_console import (
    COVERAGE_ROW_MAX_LINES, VERDICT_VALUE_COLUMN, coverage_kv_value,
)
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, LimitationCode, ScanTarget, ScanTargetKind,
    format_evidence_gap_clause, render_limitation, summarize_limitation, unstated_gaps,
)

_KB = 1 << 10
_MB = 1 << 20
_BASE = 0x10000000
_WIDTH = 100


def _target(*, size, captured=None, examined=None, base=_BASE, limit=None):
    captured = size if captured is None else captured
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base, size=size,
                       size_limit=limit, file_offset=0x1000 if captured else None,
                       captured_size=captured, examined_size=examined)


def _no_thread_context():
    return CoverageLimitation(code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE,
                               source="thread_context")


def _oversized(size=16 * _MB, base=_BASE):
    return CoverageLimitation(
        code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="pipe_name_scan",
        affected_count=1,
        targets=[_target(size=size, examined=0, base=base, limit=size // 2)])


def _report(limitations, eligible_bytes=None, status="partial"):
    return CoverageReport(status=status, limitations=list(limitations),
                           eligible_bytes=eligible_bytes)


def _lines(report, width=_WIDTH):
    return coverage_kv_value(report.status.value, report, width)


def _row(report, width=_WIDTH):
    """The row's value as one string, for the cases pinning the wording
    rather than where it breaks."""
    return " ".join(_lines(report, width))


# ── the two dimensions ──────────────────────────────────────────────────

def test_a_finished_byte_scan_reads_as_finished_work_not_as_a_count_of_zero():
    """The scale is the strength of the clean half of this result: every
    one of 1.1 KB eligible bytes was examined. Beside a status word that
    grades all evidence, a zero would read as a contradiction of it."""
    assert _row(_report([_no_thread_context()], eligible_bytes=1100)).startswith(
        "PARTIAL — byte scan 100% complete (1.1 KB eligible)")


def test_a_partial_over_a_finished_byte_scan_names_what_was_missing():
    """The whole point of the second clause: an investigator reading the
    card learns which evidence the verdict is short of, without opening
    the COVERAGE section below it."""
    assert (_row(_report([_no_thread_context()], eligible_bytes=1100))
            == "PARTIAL — byte scan 100% complete (1.1 KB eligible); "
               "per-thread CONTEXT unavailable")


def test_byte_gaps_and_evidence_gaps_both_stay_on_the_row():
    """Neither dimension displaces the other. The bytes say what a
    re-collection would recover; the reason says what a re-collection
    would not fix."""
    row = _row(_report(
        [CoverageLimitation(code=LimitationCode.SOURCE_ABSENT, source="handle_data",
                            scope="dump"),
         _oversized()],
        eligible_bytes=16 * _MB))
    assert "16 MB unscanned across 1 range(s) (100% of 16 MB eligible)" in row
    assert row.endswith("; handle_data not present")


def test_a_gap_the_byte_figure_states_is_not_stated_twice():
    """`16 MB unscanned across 1 range(s)` IS the oversized skip. Naming
    it again as a reason would report one gap as two."""
    report = _report([_oversized()], eligible_bytes=16 * _MB)
    assert unstated_gaps(report.limitations) == []
    assert _row(report) == ("PARTIAL — 16 MB unscanned across 1 range(s) "
                             "(100% of 16 MB eligible)")


# ── a gap the byte figure only COUNTS is not a gap it states ────────────

def test_a_gap_of_unmeasurable_extent_is_named_not_left_to_its_count():
    """`unscanned extent unmeasured across 3 gap(s)` says how little the
    run could measure and nothing at all about what went uncovered -- as
    little as the status word beside it. The reason is stated too."""
    report = _report([CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                                          source="pipe_name_scan", affected_count=3)])
    assert _row(report) == ("PARTIAL — unscanned extent unmeasured across 3 gap(s); "
                             "3 item(s) with no confirmed outcome")


def test_a_target_that_recorded_no_extent_is_named_too():
    """The scan read this region and kept no returned length, so the gap
    reaches the aggregate as a count. A count is not a reason."""
    report = _report([CoverageLimitation(
        code=LimitationCode.SCAN_REGION_SHORT_READ, source="pipe_name_scan",
        affected_count=1, targets=[_target(size=4 * _KB)])])
    assert _row(report).endswith("; 1 region(s) short-read")


def test_a_byte_gap_over_memory_the_dump_never_captured_is_still_named():
    """A short read of a region the dump captured nothing for missed a
    measured zero bytes -- an honest figure, and one that leaves the byte
    clause with nothing to print. The gap is real, so the reason clause
    carries it rather than letting the status word stand alone."""
    limitation = CoverageLimitation(
        code=LimitationCode.SCAN_REGION_SHORT_READ, source="pipe_name_scan",
        affected_count=1, targets=[_target(size=4 * _KB, captured=0, examined=0)])
    report = _report([limitation], eligible_bytes=0)

    assert report.missed_bytes.known_bytes == 0
    assert _row(report) == "PARTIAL — 1 region(s) short-read"


def test_bytes_the_figure_really_does_state_keep_it_to_themselves():
    """The other side of the same rule: a gap that put real bytes into
    `known_bytes` IS what the byte clause is describing."""
    stated = _oversized()
    counted = CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                                  source="pipe_name_scan", affected_count=2)
    assert unstated_gaps([stated, counted]) == [counted]


# ── bounded to the terminal it is drawn on ──────────────────────────────

def _long_gaps():
    """Three gaps that cost no capturable bytes, so what the row does with
    them is decided by the width alone."""
    return [
        CoverageLimitation(code=LimitationCode.STOMPING_REFERENCE_MISMATCH,
                            source="reference_files", affected_count=3),
        CoverageLimitation(code=LimitationCode.STOMPING_REFERENCE_MISSING,
                            source="reference_files", affected_count=2),
        CoverageLimitation(code=LimitationCode.MODULE_HEADER_PARSE_FAILED,
                            source="module_headers", affected_count=1),
    ]


@pytest.mark.parametrize("width", [80, 100, 120])
def test_the_row_never_runs_past_the_width_it_was_given(width):
    report = _report([_oversized()] + _long_gaps(), eligible_bytes=16 * _MB)
    columns = width - VERDICT_VALUE_COLUMN
    assert all(len(line) <= columns for line in _lines(report, width))


def test_a_second_reason_is_named_only_while_the_row_still_fits():
    """Two reasons beside a measured byte clause do not fit the lines this
    row gets, so the second is counted instead of named -- the COVERAGE
    section below carries it in full either way."""
    report = _report([_oversized()] + _long_gaps(), eligible_bytes=16 * _MB)
    lines = _lines(report)

    assert len(lines) <= COVERAGE_ROW_MAX_LINES
    assert " ".join(lines) == ("PARTIAL — 16 MB unscanned across 1 range(s) "
                                "(100% of 16 MB eligible); "
                                "3 section(s) with a mismatched reference build; "
                                "+2 more (see COVERAGE)")


def test_naming_the_first_reason_can_cost_the_row_a_third_line():
    """The line budget bounds how many reasons are NAMED, never whether
    one is. A byte clause wide enough to fill the row on its own still
    leaves a `partial` with its concrete reason attached."""
    lines = _lines(_report([_oversized()] + _long_gaps(), eligible_bytes=16 * _MB),
                    width=80)
    assert len(lines) > COVERAGE_ROW_MAX_LINES
    assert "3 section(s) with a mismatched reference build" in " ".join(lines)


def test_a_second_reason_is_named_when_there_is_room_for_it():
    """The same reasons with no byte clause to share the row with."""
    lines = _lines(_report(_long_gaps()))
    assert len(lines) <= COVERAGE_ROW_MAX_LINES
    assert " ".join(lines) == (
        "PARTIAL — 3 section(s) with a mismatched reference build; "
        "2 section(s) without a reference file; +1 more (see COVERAGE)")


def test_continuation_lines_sit_in_the_value_column_on_every_card():
    """The row wraps against `VERDICT_VALUE_COLUMN`, so that constant and
    the cards' own key/value geometry have to agree -- read off the
    rendered fixtures rather than restated here."""
    golden = (pathlib.Path(__file__).resolve().parent.parent
              / "fixtures" / "hunt_cli_golden")
    rows = []
    for path in sorted(golden.glob("*_console.txt")):
        lines = path.read_text(encoding="utf-8").splitlines()
        # The verdict card's own row, found by the row above it -- the HUNT
        # SUMMARY block carries a "Coverage" label of its own, over a
        # narrower set of labels and a column of its own.
        rows.extend(line for previous, line in zip(lines, lines[1:])
                    if line.startswith("  Coverage ") and previous.startswith("  Score "))

    assert rows, "no rendered Coverage row to check the value column against"
    for row in rows:
        assert row[:VERDICT_VALUE_COLUMN].endswith("  ")
        assert not row[VERDICT_VALUE_COLUMN].isspace()


def test_a_wrapped_row_keeps_its_continuation_under_the_value():
    lines = _lines(_report([_oversized(), _no_thread_context()], eligible_bytes=16 * _MB))
    assert len(lines) == 2
    assert lines[1] and not lines[1].startswith(" ")


# ── the other two status words ──────────────────────────────────────────

def test_a_complete_run_states_the_scale_it_stands_on_and_nothing_else():
    assert (_row(_report([], eligible_bytes=550, status="complete"))
            == "COMPLETE — byte scan 100% complete (550 bytes eligible)")


def test_a_not_evaluated_run_keeps_the_bare_status_word():
    """Nothing ran, so there is no coverage to explain: the prerequisite
    this run lacked is the verdict's own text, one row above."""
    report = _report([CoverageLimitation(code=LimitationCode.SOURCE_ABSENT,
                                          source="memory64_list", scope="dump")],
                      status="not_evaluated")
    assert _row(report) == "NOT EVALUATED"


def test_a_producer_that_measures_no_eligibility_still_names_its_reason():
    """No scale, so no byte clause at all -- the row would otherwise be a
    status word on its own, which is exactly the shape that tells an
    investigator nothing."""
    assert _row(_report([_no_thread_context()])) == "PARTIAL — per-thread CONTEXT unavailable"


# ── the summary vocabulary ──────────────────────────────────────────────

def test_a_summary_and_its_full_sentence_are_the_same_fact():
    limitation = CoverageLimitation(code=LimitationCode.THREAD_CONTEXT_PARTIAL,
                                     source="thread_context", affected_count=3)
    assert summarize_limitation(limitation) == "3 thread(s) without CONTEXT"
    assert render_limitation(limitation).startswith("3 thread(s) had no parsed CONTEXT")


def test_a_code_with_no_summary_falls_back_to_its_own_full_sentence():
    """The fallback is long, never generic: a card that reads "other
    evidence incomplete" leaves the investigator exactly where the bare
    status word already left them."""
    limitation = CoverageLimitation(code=LimitationCode.PROFILE_DIRECTORY_UNAVAILABLE,
                                     source="profile_directory", scope="dump")
    assert summarize_limitation(limitation) == render_limitation(limitation)


def test_at_least_one_gap_is_named_whatever_the_caller_asks_for():
    assert (format_evidence_gap_clause(_long_gaps(), 0)
            == "3 section(s) with a mismatched reference build; +2 more (see COVERAGE)")
    assert format_evidence_gap_clause([], 2) is None


def _codes_named_by_hunters():
    """Every `LimitationCode.X` the hunt package mentions, read out of the
    source itself so a hunter that starts reporting a new gap cannot leave
    the card's own vocabulary behind."""
    root = pathlib.Path(__file__).resolve().parent.parent.parent / "dumpex" / "hunt"
    named = set()
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "LimitationCode"):
                named.add(node.attr)
    # Derived from source state by build_coverage_report rather than named
    # in any hunter's own source -- every hunter reaching a SourceRequirement
    # or EvaluationRequirement can publish these three.
    return named | {"SOURCE_ABSENT", "SOURCE_FAILED", "SOURCE_GROUP_ABSENT"}


@pytest.mark.parametrize("code_name", sorted(_codes_named_by_hunters()))
def test_every_gap_a_hunter_can_report_has_a_card_summary(code_name):
    from dumpex.output.coverage import _CODE_SPECS

    assert _CODE_SPECS[LimitationCode[code_name]].summary is not None, (
        f"{code_name} can reach a hunter's Coverage row and has no summary, so the row "
        f"would carry its whole COVERAGE-section sentence")
