"""
Cross-hunter `result.summary` reducer for `result.kind == "hunt"`.

The single function JSON, CSV, and console rendering must all call for
the same set of `HunterRecord`s -- see docs/hunt_migration_field_matrix.md's
own "summary rules" section and the v2.4 migration plan's requirement
that this reducer never be re-derived independently by more than one
output surface. Pure aggregation over already-computed per-hunter
judgments: this never re-derives a HunterRecord's own score/verdict/
coverage, it only combines the 7 (or 1) already-final records into one
result.summary dict.

Wired into the CLI as of PR4: `dumpex.hunt.collect_hunt()` calls this
for the silent, JSON-only `CommandResult` path; `dumpex.hunt.cmd_hunt()`
calls it too (always, regardless of its own `collect_records` flag) and
uses `summary["overall_status"]` to drive the `--hunt all` console
summary card's own "Overall: ..." line -- the per-hunter DISPLAY
formatting in that same card (name/verdict color/score suffix) still
reads each hunter's own v1.1-shaped dict, since that's presentation, not
a cross-hunter reduction, but the one cross-hunter judgment (DETECTED/
INCONCLUSIVE/NOT_EVALUATED/NOT_DETECTED_IN_SCANNED_SCOPE) now has exactly
one implementation, this one, for JSON, CSV, AND console alike -- see
`cmd_hunt()`'s own docstring for the exact split. Exercised directly by
tests/unit/test_hunt_summary.py plus indirectly by every schema/CSV test
that calls it via tests/fixtures/hunt_records.hunt_summary_for(), and by
tests/integration/test_hunt_cli_compat_freeze.py's byte-exact console
fixtures (which pin that this reduction produces the same console text
the old, now-removed independent any_hit/any_not_evaluated/
any_inconclusive computation did).
"""
from dumpex.output.records import HUNTERS, HunterRecord

# Relative severity among the three verdict levels a DETECTED hunter can
# report -- deliberately its own tuple, not reused from
# dumpex.output.records._HUNT_VERDICT_LEVELS (whose ordering also
# includes "clean"/"inconclusive"/"not_evaluated" interleaved for an
# unrelated reason and must not be assumed to double as a severity rank).
_DETECTED_VERDICT_ORDER = ("possible", "likely", "high")


def build_hunt_summary(records: "list[HunterRecord]", selected: str) -> dict:
    """
    `selected` is the `--hunt` argument: `"all"` or one of `HUNTERS`.

    `records` must be exactly:
      - one `HunterRecord` per hunter in `HUNTERS`' own fixed order, when
        `selected == "all"`; or
      - exactly one `HunterRecord` whose `.hunter == selected`, otherwise.

    Raises `ValueError`/`TypeError` on any shape violation -- the same
    "fail loudly on a shape the caller got wrong" precedent every other
    cross-record reducer in this codebase follows (see e.g.
    dumpex.output.csv_export.build_tables' comparison/hunt partition
    checks, or dumpex.output.coverage.combine_coverage_reports).

    Status-to-overall-status reduction (see the migration plan's own
    "整体 Summary 规则" section):

        any hunter DETECTED                                  -> DETECTED
        no DETECTED, any INCONCLUSIVE or some-but-not-all
            NOT_EVALUATED                                     -> INCONCLUSIVE
        no DETECTED, no INCONCLUSIVE, ALL NOT_EVALUATED       -> NOT_EVALUATED
        no DETECTED, no INCONCLUSIVE, none NOT_EVALUATED      -> NOT_DETECTED_IN_SCANNED_SCOPE

    "some-but-not-all NOT_EVALUATED" (e.g. 3 of 7 hunters never got the
    data source they needed, the other 4 ran clean) is deliberately
    INCONCLUSIVE, not NOT_DETECTED_IN_SCANNED_SCOPE -- a scope that was
    only PARTLY looked at has not earned "clean", the same reasoning
    dumpex.hunt._finding.verdict_level()'s own docstring gives for why
    NOT_EVALUATED/INCONCLUSIVE take priority over a score<=0 "clean"
    default at the single-hunter level.

    `highest_verdict_level` is picked from the DETECTED hunters' own
    verdict_level values (never re-derived from score) when any exist;
    otherwise it's "inconclusive"/"not_evaluated"/"clean" matching
    `overall_status` exactly.
    """
    if selected == "all":
        expected_hunters = tuple(HUNTERS)
    elif selected in HUNTERS:
        expected_hunters = (selected,)
    else:
        raise ValueError(
            f"build_hunt_summary() got unknown selected={selected!r} -- must be 'all' or "
            f"one of {HUNTERS}")

    if not isinstance(records, list) or any(not isinstance(r, HunterRecord) for r in records):
        raise TypeError("build_hunt_summary() records must be a list of HunterRecord")

    actual_hunters = tuple(r.hunter for r in records)
    if actual_hunters != expected_hunters:
        raise ValueError(
            f"build_hunt_summary(selected={selected!r}) expected records for hunters "
            f"{expected_hunters!r} in that exact order, got {actual_hunters!r}")

    detected = [r for r in records if r.status == "DETECTED"]
    inconclusive = [r for r in records if r.status == "INCONCLUSIVE"]
    not_evaluated = [r for r in records if r.status == "NOT_EVALUATED"]
    lead_count = sum((r.lead_count or 0) for r in records)

    if detected:
        overall_status = "DETECTED"
        highest_verdict_level = max(
            (r.verdict_level for r in detected), key=_DETECTED_VERDICT_ORDER.index)
    elif inconclusive or (not_evaluated and len(not_evaluated) < len(records)):
        overall_status = "INCONCLUSIVE"
        highest_verdict_level = "inconclusive"
    elif len(not_evaluated) == len(records):
        overall_status = "NOT_EVALUATED"
        highest_verdict_level = "not_evaluated"
    else:
        overall_status = "NOT_DETECTED_IN_SCANNED_SCOPE"
        highest_verdict_level = "clean"

    return {
        "selected": selected,
        "hunter_count": len(records),
        "detected_count": len(detected),
        "inconclusive_count": len(inconclusive),
        "not_evaluated_count": len(not_evaluated),
        "overall_status": overall_status,
        "highest_verdict_level": highest_verdict_level,
        "lead_count": lead_count,
    }
