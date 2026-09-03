"""Unscanned scanning work as a proportion of the work a hunt had to do.

`coverage.missed_bytes.bytes` ranks two runs against each other and says
nothing about either on its own: 3.2 MB unscanned is a rounding error out
of 11.4 GB eligible and almost the whole hunt out of 3.4 MB.
`unscanned_fraction` supplies the scale, and these tests pin what it is
measured on and every shape where it must NOT be stated.

Both sides of the ratio count PER SCAN PASS:

  * `eligible_bytes` sums what each pass had in front of it, so a region
    three passes each accepted is three passes' worth of scope;
  * `unscanned_pass_bytes` sums what each pass left unexamined, unioning
    within a pass (one pass can name the same bytes under two codes) and
    never across them.

That pairing is the only one right in both directions. Measuring both as
memory would report a region only one of three passes skipped as wholly
unscanned; measuring only the denominator per pass -- dividing the
memory-basis `bytes` by it -- would report a region EVERY pass skipped as
two-thirds scanned, which is the direction this figure must never be wrong
in. `bytes` keeps its own memory basis and is deliberately not the
numerator here.
"""
import pathlib

import pytest

from dumpex.hunt._coverage import CoverageTracker, merge_eligible_bytes, region_scan_target
from dumpex.output.coverage import (
    CoverageLimitation, CoverageReport, CoverageStatus, LimitationCode, MissedBytes,
    MissedBytesState, ScanTarget, ScanTargetKind, combine_coverage_reports,
    format_missed_bytes_clause, format_unscanned_percent, summarize_missed_bytes,
)

from tests.fixtures.fakes import FakeMF, FakeReader, FakeStream, Region, Segment

_KB = 1 << 10
_MB = 1 << 20
_BASE = 0x10000000


def _target(base, captured, examined=0):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=captured, size_limit=None, file_offset=0x1000,
                       captured_size=captured, examined_size=examined)


def _gap(*targets, code=LimitationCode.SCAN_REGION_READ_FAILED,
          source="pipe_name_scan", scope=None):
    return CoverageLimitation(code=code, source=source, scope=scope,
                               affected_count=len(targets), targets=tuple(targets))


def _unmeasured_gap(count=1):
    """A gap that costs real work whose extent nothing established."""
    return CoverageLimitation(code=LimitationCode.SCAN_ITEMS_UNACCOUNTED,
                               source="pipe_name_scan", affected_count=count)


def _region_mf(base=_BASE, size=8 * _KB, captured=None):
    mf = FakeMF()
    mf.memory_info = FakeStream([Region(base, base, size, "MEM_COMMIT",
                                         "PAGE_READWRITE", "MEM_PRIVATE")], "infos")
    mf.memory_segments_64 = FakeStream(
        [Segment(base, 0x1000, size if captured is None else captured)], "memory_segments")
    mf.modules = FakeStream([], "modules")
    mf._reader = FakeReader({base: bytes(size if captured is None else captured)})
    return mf


# ── both sides count per pass ───────────────────────────────────────────

def test_a_passs_scope_is_its_own_work_not_the_memory_it_shares():
    tracker = CoverageTracker()
    for _ in range(3):
        tracker.note_eligible(4 * _KB)
        tracker.note_scanned()
    assert tracker.eligible_bytes == 3 * 4 * _KB


def test_a_hunters_passes_sum_their_scopes():
    """Each pass had the region in front of it, so each contributes it.
    Unioning them instead would divide a per-pass numerator by a memory
    denominator and report work that did not happen as work that did."""
    assert merge_eligible_bytes(8 * _KB, 8 * _KB, 8 * _KB) == 24 * _KB
    assert merge_eligible_bytes(8 * _KB, None) is None


def test_one_pass_naming_the_same_bytes_twice_counts_them_once():
    """Within a pass the ranges are unioned: one segment can be short-read
    AND stopped inside, and one run of segments can be left by both a hit
    cap and a budget. That is one pass's work missed once, not twice."""
    missed = summarize_missed_bytes(
        [_gap(_target(_BASE, 4 * _KB), code=LimitationCode.SCAN_REGION_SHORT_READ),
         _gap(_target(_BASE, 4 * _KB), code=LimitationCode.SCAN_REGION_READ_FAILED)],
        eligible_bytes=8 * _KB)
    assert missed.unscanned_pass_bytes == 4 * _KB
    assert missed.unscanned_fraction == 0.5


def _yara_budget_gaps(size):
    """yara's real shape: ONE run of unreached segments, reported under
    both the hit cap and the deadline, each carrying its own `scope`
    because `scope` names the BUDGET there, not a pass."""
    target = ScanTarget(kind=ScanTargetKind.MEMORY_SEGMENT, base_address=_BASE, size=size,
                        file_offset=0x1000, captured_size=size, examined_size=0)
    return [
        CoverageLimitation(code=LimitationCode.YARA_HIT_CAP_REACHED, source="segment_scan",
                            affected_count=1, targets=[target], scope="max_total_hits",
                            budget_limit=10, budget_consumed=10),
        CoverageLimitation(code=LimitationCode.YARA_SCAN_BUDGET_EXHAUSTED,
                            source="segment_scan", affected_count=1, targets=[target],
                            scope="scan_deadline_seconds", budget_limit=5, budget_consumed=5),
    ]


def test_a_scope_the_producer_did_not_declare_is_not_a_pass():
    """`scope` is a budget kind for every producer but obfuscation, so it
    must not be read as a pass identity. Splitting yara's one segment run
    across its two budget codes would count that pass's work twice, and
    the numerator would exceed a scope that counts the segment once."""
    missed = summarize_missed_bytes(_yara_budget_gaps(4 * _KB), eligible_bytes=4 * _KB)

    assert missed.unscanned_pass_bytes == 4 * _KB
    assert missed.eligible_bytes == 4 * _KB
    assert missed.unscanned_fraction == 1.0


def test_two_declared_passes_missing_the_same_bytes_count_them_twice():
    """Across passes they are summed: the same region skipped by two
    passes cost two passes' work, and a rescan has two passes to redo.
    The producer declares which scopes those are -- see
    `test_a_scope_the_producer_did_not_declare_is_not_a_pass` for what
    happens to one that does not."""
    limitations = [_gap(_target(_BASE, 4 * _KB), source="encoding_scan", scope="entropy"),
                    _gap(_target(_BASE, 4 * _KB), source="encoding_scan", scope="decode")]
    missed = summarize_missed_bytes(limitations, eligible_bytes=8 * _KB,
                                     pass_scopes=("entropy", "decode"))
    assert missed.unscanned_pass_bytes == 8 * _KB
    assert missed.unscanned_fraction == 1.0
    # ... while `bytes` keeps measuring MEMORY, and counts it once.
    assert missed.known_bytes == 4 * _KB
    assert missed.distinct_ranges == 1 and missed.quantified_gaps == 2

    # Undeclared, the same two gaps are one pass naming its work twice.
    assert summarize_missed_bytes(limitations,
                                   eligible_bytes=8 * _KB).unscanned_pass_bytes == 4 * _KB


def test_a_mismatched_basis_withdraws_the_scale_instead_of_raising():
    """A producer that declared the wrong passes, or published a scope
    that does not cover its own gaps, produces a ratio that is not a fact.
    The gaps and the byte figure ARE facts this run established and stay
    on the wire; only the derived proportion is withdrawn -- a hunt that
    found something must not be lost to an accounting error in the figure
    that grades it."""
    missed = summarize_missed_bytes(
        [_gap(_target(_BASE, 4 * _KB), source="encoding_scan", scope="entropy"),
         _gap(_target(_BASE, 4 * _KB), source="encoding_scan", scope="decode")],
        eligible_bytes=4 * _KB, pass_scopes=("entropy", "decode"))

    assert missed.unscanned_pass_bytes == 8 * _KB
    assert missed.known_bytes == 4 * _KB
    assert missed.eligible_bytes is None
    assert missed.unscanned_fraction is None


# ── the two cases that decide the basis ─────────────────────────────────

def _encoding_coverage_for(monkeypatch, size, protect):
    import dumpex.hunt.encoding as encoding
    from dumpex.hunt.encoding.report_facts import project_coverage_report
    from tests.fixtures.fakes import mem_reader

    mf = FakeMF()
    mf.memory_info = FakeStream(
        [Region(_BASE, _BASE, size, "MEM_COMMIT", protect, "MEM_PRIVATE")], "infos")
    mf.memory_segments_64 = FakeStream([Segment(_BASE, 0x1000, size)], "memory_segments")
    mf.modules = FakeStream([], "modules")
    monkeypatch.setattr(encoding, "read_region", mem_reader({_BASE: bytes(size)}))
    return project_coverage_report(encoding._build_encoding_report(mf).coverage)


def test_a_region_every_pass_skipped_reports_all_the_work_undone(monkeypatch):
    """16 MB is over every one of obfuscation's three caps, so not one
    byte of it was examined by anything. Dividing the memory-basis `bytes`
    by a per-pass scope would report this as 33% unscanned -- claiming two
    thirds was scanned when none of it was."""
    coverage = _encoding_coverage_for(monkeypatch, 16 * _MB, "PAGE_READWRITE")
    missed = coverage.missed_bytes

    assert missed.eligible_bytes == 3 * 16 * _MB
    assert missed.unscanned_pass_bytes == 3 * 16 * _MB
    assert missed.unscanned_fraction == 1.0
    # The memory figure counts the one region once, and is NOT the numerator.
    assert missed.known_bytes == 16 * _MB


def test_a_region_one_pass_skipped_reports_only_that_passs_share(monkeypatch):
    """The decode pass caps at 2 MB and entropy at 10 MB, so a 3 MB region
    is read in full by entropy and skipped by decode alone. Half this
    hunt's work over that region happened; measuring both sides as memory
    would report it as wholly unscanned."""
    coverage = _encoding_coverage_for(monkeypatch, 3 * _MB, "PAGE_EXECUTE_READWRITE")
    missed = coverage.missed_bytes

    assert missed.eligible_bytes == 2 * 3 * _MB     # entropy and decode took it in
    assert missed.unscanned_pass_bytes == 3 * _MB   # decode alone left it
    assert missed.unscanned_fraction == 0.5
    assert missed.known_bytes == 3 * _MB

    # Which pass, for a consumer that needs the remedy rather than the size.
    scan_gaps = [(l.code.value, l.scope) for l in coverage.limitations if l.targets]
    assert scan_gaps == [("SCAN_REGION_OVERSIZED_SKIPPED", "decode")]


# ── the numerator is always inside the denominator ──────────────────────

def test_work_a_budget_never_reached_joins_the_scope_it_is_measured_against():
    """A whole-scan budget ends the walk before the remaining items are
    taken into scope, so a pass's gaps are not always a subset of what its
    ledger counted. The producer counts them into the same pass's scope,
    which is what keeps the ratio at or below 1."""
    tracker = CoverageTracker()
    tracker.note_eligible(4 * _KB)
    tracker.note_scanned()
    tracker.note_unreached_extent(4 * _KB)

    missed = summarize_missed_bytes([_gap(_target(_BASE + 0x10000, 4 * _KB))],
                                     eligible_bytes=tracker.eligible_bytes)
    assert missed.eligible_bytes == 8 * _KB
    assert missed.unscanned_fraction == 0.5


def test_a_deadline_before_the_first_segment_still_reports_a_real_share(monkeypatch):
    """End to end for the same rule: cs-beacon's budget checks run before
    any segment is read, so every segment the stop names is unexamined and
    none of them was ever eligible."""
    import dumpex.hunt.cs_beacon as cs_beacon
    from dumpex.hunt.cs_beacon.report_facts import project_coverage_report

    seg_size = 0x1000
    segments, reads = [], {}
    for index in range(2):
        va = 0x73000000 + index * 0x100000
        segments.append(Segment(va, va, seg_size))
        reads[va] = bytes(seg_size)

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segments, "memory_segments")
        memory_info = FakeStream([], "infos")
        _reader = FakeReader(reads)

    ticks = {"n": 0}
    monkeypatch.setattr(
        cs_beacon.time, "monotonic",
        lambda: ticks.__setitem__("n", ticks["n"] + 1)
        or ticks["n"] * (cs_beacon.CS_SCAN_DEADLINE_SECONDS * 2))

    report = cs_beacon._build_cs_beacon_report(MF())
    missed = project_coverage_report(report.coverage).missed_bytes
    assert missed.eligible_bytes == 2 * seg_size
    assert missed.unscanned_pass_bytes == 2 * seg_size
    assert missed.unscanned_fraction == 1.0


def test_pass_bytes_belonging_to_no_gap_are_refused():
    """The same rule `known_bytes` follows, on the other basis: work
    reported as unexamined has to belong to a gap that says where it
    was."""
    with pytest.raises(ValueError, match="unscanned_pass_bytes"):
        MissedBytes(unscanned_pass_bytes=4096, eligible_bytes=8192)


def test_a_numerator_above_its_denominator_is_refused():
    """Both sides count per pass and a pass's scope covers the items it
    never reached as well as the ones it walked, so this cannot happen by
    construction. A pair that is not a ratio is an accounting bug, not a
    150% coverage gap to render."""
    with pytest.raises(ValueError, match="cannot leave more bytes unexamined"):
        MissedBytes(known_bytes=8192, quantified_gaps=1, distinct_ranges=1,
                     unscanned_pass_bytes=8192, eligible_bytes=4096)


# ── when a proportion may be stated ─────────────────────────────────────

def test_the_two_quantities_are_arithmetically_consistent():
    missed = summarize_missed_bytes(
        [_gap(_target(_BASE, 3 * _KB), _target(_BASE + 0x10000, 5 * _KB))],
        eligible_bytes=100 * _KB)

    assert missed.unscanned_pass_bytes == 8 * _KB
    assert missed.unscanned_fraction == missed.unscanned_pass_bytes / missed.eligible_bytes


def test_an_unmeasured_gap_makes_the_proportion_a_labelled_floor():
    """The byte figure is already a floor in this state; the proportion
    derived from it is the same floor, and the clause says so rather than
    letting an exact-looking percentage stand beside an unmeasured gap."""
    missed = summarize_missed_bytes(
        [_gap(_target(_BASE, 4 * _KB)), _unmeasured_gap()], eligible_bytes=64 * _KB)

    assert missed.state is MissedBytesState.LOWER_BOUND
    assert missed.unscanned_fraction == pytest.approx(4 / 64)
    assert "at least 6.2% of 64 KB eligible" in format_missed_bytes_clause(missed)


def test_a_budget_gap_of_unknown_extent_never_becomes_zero_percent():
    """Nothing about this run's missed work is established. Reporting `0`
    -- the one value that means "nothing was missed" -- would invert the
    finding for every consumer thresholding on it."""
    missed = summarize_missed_bytes([_unmeasured_gap(count=2)], eligible_bytes=64 * _KB)

    assert missed.state is MissedBytesState.UNKNOWN
    assert missed.eligible_bytes == 64 * _KB
    assert missed.unscanned_fraction is None
    assert "%" not in format_missed_bytes_clause(missed)


def test_a_producer_that_measures_no_eligibility_reports_no_proportion():
    """Every recon command is in this shape: it reports coverage gaps and
    runs no eligibility ledger. A denominator taken from the gaps alone
    would report each of them as exactly 100% unscanned."""
    report = CoverageReport(status="partial", limitations=[_gap(_target(_BASE, 4 * _KB))])

    assert report.eligible_bytes is None
    assert report.missed_bytes.eligible_bytes is None
    assert report.missed_bytes.unscanned_fraction is None


def test_a_scan_that_never_measured_its_scope_reports_no_scale():
    """The fail-open this closes: a loop that walks a hundred regions,
    scans ninety-nine and skips one, but records no sizes. Reporting the
    measured total of 0 would leave the gap as its own denominator."""
    tracker = CoverageTracker()
    for _ in range(100):
        tracker.note_eligible()
        tracker.note_scanned()

    assert tracker.total == 100 and tracker.eligible_bytes is None
    report = CoverageReport(status="partial",
                             limitations=[_gap(_target(_BASE, 1 * _MB))],
                             eligible_bytes=tracker.eligible_bytes)
    assert report.missed_bytes.unscanned_pass_bytes == 1 * _MB
    assert report.missed_bytes.eligible_bytes is None
    assert report.missed_bytes.unscanned_fraction is None


def test_one_unmeasured_scan_pass_withdraws_a_hunters_whole_scale():
    """A hunter sums its passes' scopes, and one pass that measured none
    makes the total unpublishable -- not quietly the sum of the passes
    that did measure, which would be short by whatever the silent one had
    in front of it."""
    assert merge_eligible_bytes(4 * _KB, 4 * _KB) == 8 * _KB
    assert merge_eligible_bytes(4 * _KB, None) is None
    assert merge_eligible_bytes(None, None) is None


def test_a_hunter_that_evaluated_nothing_reports_no_proportion():
    """`not_evaluated` means the scan never ran, so there is no work for a
    gap to be a proportion of -- not 0%, and not 100%, both of which read
    as findings about a run that reached no verdict."""
    report = CoverageReport(status="not_evaluated",
                             limitations=[_gap(_target(_BASE, 4 * _KB))],
                             eligible_bytes=4 * _KB)

    assert report.missed_bytes.known_bytes == 4 * _KB
    assert report.missed_bytes.eligible_bytes is None
    assert report.missed_bytes.unscanned_fraction is None


def test_a_complete_scan_reports_zero_percent_of_a_real_scale():
    """The other end of the same rule: a run that missed nothing has a
    proportion, and it is 0. That is a measurement, not the absence of one
    -- which is why an unmeasured gap must not share it."""
    report = CoverageReport(status="complete", eligible_bytes=64 * _KB)
    assert report.missed_bytes.eligible_bytes == 64 * _KB
    assert report.missed_bytes.unscanned_fraction == 0.0


def test_a_scan_whose_scope_holds_no_captured_bytes_reports_zero_scale():
    """In scope, and worth nothing to a rescan. A denominator of 0 says
    the ledger ran and found no capturable memory, which is a different
    fact from the null a producer that measures no eligibility reports --
    and neither can produce a proportion."""
    tracker = CoverageTracker()
    tracker.note_eligible(0)
    tracker.note_scanned()
    report = CoverageReport(status="complete", eligible_bytes=tracker.eligible_bytes)

    assert report.missed_bytes.eligible_bytes == 0
    assert report.missed_bytes.unscanned_fraction is None


# ── rendering ───────────────────────────────────────────────────────────

def test_the_console_renders_both_quantities_for_an_exact_gap():
    """The absolute figure alone leaves an analyst to source the scale
    from somewhere else -- the dump's file size, `--list`, prior knowledge
    of the process -- none of which is the work this hunter actually had
    in front of it."""
    tiny = summarize_missed_bytes([_gap(_target(_BASE, 3355443))],
                                   eligible_bytes=12241512530)
    assert (format_missed_bytes_clause(tiny)
            == "3.2 MB unscanned across 1 range(s) (0.03% of 11.4 GB eligible)")

    whole = summarize_missed_bytes([_gap(_target(_BASE, 3355443))],
                                    eligible_bytes=3565158)
    assert (format_missed_bytes_clause(whole)
            == "3.2 MB unscanned across 1 range(s) (94% of 3.4 MB eligible)")


@pytest.mark.parametrize(
    "fraction,rendered",
    [
        (0.0,      "0%"),
        (1 / 3e9,  "<0.01%"),     # real work, far below the smallest step
        (0.0003,   "0.03%"),
        (0.0123,   "1.2%"),
        (0.0999,   "10%"),        # the band boundary renders one way, not two
        (0.1,      "10%"),
        (0.94,     "94%"),
        (0.999,    "99.9%"),      # would round to the reserved 100 at .0f
        (0.9996,   "99.96%"),     # ... and at .1f
        (0.99996,  ">99.99%"),    # nothing left that is not 100
        (1.0,      "100%"),
    ],
)
def test_both_saturating_percentages_are_reserved_for_what_they_mean(fraction, rendered):
    """`0%` means a run missed nothing and `100%` means none of its work
    happened -- so neither may be reached by rounding. A gap shown as `0%`
    says the opposite of what it means, and a run that got through all but
    a sliver shown as `100%` says the same thing pointed the other way."""
    assert format_unscanned_percent(fraction) == rendered


def test_a_run_with_no_scale_renders_exactly_as_it_did_without_one():
    """The clause is additive: a producer that measures no eligibility
    keeps the line it already had."""
    missed = summarize_missed_bytes([_gap(_target(_BASE, 4 * _KB))])
    assert format_missed_bytes_clause(missed) == "4 KB unscanned across 1 range(s)"


def test_a_clean_result_states_how_much_work_it_stands_on():
    """A `complete` scan reports 0% -- on the console as well as in the
    structured output. The scale is the whole strength of a clean result:
    the same two words cover a negative over 11.4 GB and a negative over
    8 KB, and only one of them is worth anything."""
    strong = summarize_missed_bytes([], eligible_bytes=12241512530)
    assert strong.unscanned_fraction == 0.0
    assert format_missed_bytes_clause(strong) == "0 bytes unscanned (0% of 11.4 GB eligible)"

    weak = summarize_missed_bytes([], eligible_bytes=8 * _KB)
    assert format_missed_bytes_clause(weak) == "0 bytes unscanned (0% of 8 KB eligible)"

    # No scale, nothing missed: the bare status word, exactly as before.
    assert format_missed_bytes_clause(summarize_missed_bytes([])) is None


# ── the scale belongs to the hunter, not the dump ───────────────────────

@pytest.mark.parametrize("measured", [0, 4096], ids=["scope measured zero", "scope measured"])
def test_a_zero_scope_is_a_measurement_and_never_falls_through(measured):
    """`0` is falsy and means the opposite of what falsy would imply: a
    scan measured its scope and had no capturable memory in front of it.
    Every guard that asks "did this report measure eligibility" must
    therefore ask `is not None` -- a truthiness check lets the zero through
    and the merge then drops it, turning a denominator of 0 into a null."""
    report = CoverageReport(status="complete", eligible_bytes=measured)
    assert report.missed_bytes.eligible_bytes == measured

    with pytest.raises(ValueError, match="eligible_bytes"):
        combine_coverage_reports([report, CoverageReport(status="complete")])
    with pytest.raises(ValueError, match="mutually exclusive"):
        CoverageReport(status="partial", missed_bytes_rollup=MissedBytes(),
                        eligible_bytes=measured)


def test_the_document_rollup_states_no_scale_of_its_own():
    """Eligibility is per hunter and reflects that hunter's own filters,
    and not every hunter publishes one -- a combined denominator would be
    short by whatever the silent ones had in front of them while the
    numerator already counts their gaps. The per-hunter fractions
    underneath are the answer; there is no dump-wide scope to roll up
    into."""
    from dumpex.hunt import collect_hunt

    result = collect_hunt(_region_mf(size=64 * _MB), selected="all")
    assert result.coverage.limitations == []
    assert result.coverage.missed_bytes.known_bytes == 64 * _MB
    assert result.coverage.missed_bytes.eligible_bytes is None
    assert result.coverage.missed_bytes.unscanned_fraction is None


def test_reports_over_different_evidence_files_refuse_to_share_a_scale():
    """`--diff` combines reports built over TWO dumps. Their scan passes
    are not one run's, so a merged denominator would name work no single
    run had in front of it."""
    with pytest.raises(ValueError, match="eligible_bytes"):
        combine_coverage_reports([
            CoverageReport(status="complete", eligible_bytes=4096),
            CoverageReport(status="complete"),
        ])


def test_every_hunter_that_can_report_missed_bytes_states_a_scale():
    """A byte figure nobody can scale is the gap this closes, and it must
    not reopen one hunter at a time. Every hunter whose limitation codes
    can describe unexamined dump bytes publishes a denominator.

    `hollowing` is the one exception and not a gap: no code it can emit
    describes unexamined bytes at all, so its byte figure is always 0 and
    a denominator would have nothing to scale. That is derived here, not
    asserted -- a code it gains that DOES describe them makes this fail."""
    from dumpex.output.coverage import _CODE_SPECS
    from dumpex.output.records import HUNTERS

    publishes_a_scale = {"obfuscation", "pipe", "stomping", "cs-beacon", "yara", "injection"}
    reports_no_memory_gap = {"hollowing"}
    assert publishes_a_scale | reports_no_memory_gap == set(HUNTERS), (
        f"the hunter roster moved: {sorted(HUNTERS)}")

    for code in (LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE,
                 LimitationCode.PEB_UNAVAILABLE):
        assert _CODE_SPECS[code].memory_gap is None

    doc = (pathlib.Path(__file__).resolve().parents[2]
           / "docs" / "user" / "OUTPUT_SCHEMA.md").read_text(encoding="utf-8")
    assert "`hollowing` is a different case" in doc


def test_only_the_producer_whose_scope_names_a_pass_declares_one():
    """`pass_scopes` is a declaration, and the whole point is that it is
    not inferable -- so the set of producers making one is pinned here
    against the source. obfuscation is the only hunter whose `scope` names
    a scan pass; every other producer uses it for a budget kind or a
    signal, and declaring one there would split a single pass's work
    across the codes that described it."""
    import re

    from dumpex.hunt.encoding.domain import OVERSIZE_SCAN_LAYERS
    from dumpex.hunt.encoding.report_facts import project_coverage_report

    root = pathlib.Path(__file__).resolve().parents[2] / "dumpex"
    declaring = {path.parent.name for path in root.rglob("*.py")
                 if re.search(r"pass_scopes=(?!\(\))", path.read_text(encoding="utf-8"))
                 and path.parent.name not in ("output",)}
    assert declaring == {"encoding"}, f"undeclared or unexpected pass declaration: {declaring}"

    # And what it declares is exactly the vocabulary its own limitations
    # put in `scope`, read from the same constant rather than restated.
    assert set(OVERSIZE_SCAN_LAYERS) == {"sleep_mask", "entropy", "decode"}
    src = (root / "hunt" / "encoding" / "report_facts.py").read_text(encoding="utf-8")
    assert "pass_scopes=OVERSIZE_SCAN_LAYERS" in src
    assert project_coverage_report.__module__ == "dumpex.hunt.encoding.report_facts"


def test_the_two_hunters_without_a_ledger_still_state_a_scale():
    """`yara` and `injection` declare their scope from the segment/region
    list their loop already walks rather than through a CoverageTracker,
    so they publish a denominator without a disposition ledger. Pinned
    because the two paths are easy to conflate: a hunter here that grows a
    tracker belongs in the ledger set, not in a second scope declaration
    beside it."""
    source = pathlib.Path(__file__).resolve().parents[2] / "dumpex" / "hunt"
    with_ledger = {path.parent.name for path in source.rglob("*.py")
                   if "note_eligible(" in path.read_text(encoding="utf-8")
                   and path.parent.name != "hunt"}
    assert with_ledger == {"cs_beacon", "encoding", "pipe", "stomping"}


# ── every memory-scanning hunter publishes its scale ────────────────────

def _pipe_coverage(mf):
    import dumpex.hunt.pipe as pipe
    from dumpex.hunt.pipe.report_facts import project_coverage_report
    return project_coverage_report(pipe._build_pipe_report(mf).coverage)


def _stomping_coverage(mf):
    import dumpex.hunt.stomping as stomping
    from dumpex.hunt.stomping.report_facts import project_coverage_report
    return project_coverage_report(stomping._build_stomping_report(mf).coverage)


def _stomping_mf(size=8 * _KB):
    """This hunter's IOC scan takes executable MEM_IMAGE regions into
    scope, and its module/section walk needs a module list to evaluate at
    all -- so its eligible set is genuinely a different subset of the same
    dump from the one a private-memory walk reports."""
    from tests.fixtures.fakes import Module

    mf = FakeMF()
    mf.memory_info = FakeStream([Region(_BASE, _BASE, size, "MEM_COMMIT",
                                         "PAGE_EXECUTE_READ", "MEM_IMAGE")], "infos")
    mf.memory_segments_64 = FakeStream([Segment(_BASE, 0x1000, size)], "memory_segments")
    mf.modules = FakeStream(
        [Module(_BASE, size, r"C:\Windows\System32\legit.dll")], "modules")
    mf._reader = FakeReader({_BASE: bytes(size)})
    return mf


@pytest.mark.parametrize(
    "project,build_mf",
    [(_pipe_coverage, _region_mf), (_stomping_coverage, _stomping_mf)],
    ids=["pipe", "stomping"])
def test_every_region_scanning_hunter_publishes_what_it_took_into_scope(project, build_mf):
    """A hunter whose scan loop runs an eligibility ledger and does not
    publish it reports a byte figure nobody can scale -- the exact gap
    this closes, reopened one hunter at a time."""
    assert project(build_mf(size=8 * _KB)).missed_bytes.eligible_bytes == 8 * _KB


def test_the_obfuscation_hunter_publishes_the_sum_of_its_three_passes(monkeypatch):
    """One region, three passes that each accept it, three passes' worth
    of scope."""
    coverage = _encoding_coverage_for(monkeypatch, 8 * _KB, "PAGE_READWRITE")
    assert coverage.missed_bytes.eligible_bytes == 3 * 8 * _KB


def test_the_segment_scanning_hunter_publishes_what_it_took_into_scope():
    """cs-beacon walks the segment table rather than MemoryInfo, so its
    scope is stated in segment sizes -- the dump's own claim about how
    many bytes sit at each file offset."""
    from dumpex.hunt.cs_beacon.collect import collect_cs_beacon_record

    mf = FakeMF()
    mf.memory_segments_64 = FakeStream([Segment(_BASE, 0x1000, 4 * _KB)], "memory_segments")
    mf.memory_info = FakeStream([], "infos")
    mf._reader = FakeReader({_BASE: bytes(4 * _KB)})

    assert collect_cs_beacon_record(mf).coverage.missed_bytes.eligible_bytes == 4 * _KB


def test_two_hunters_over_one_dump_may_report_different_scales():
    """Eligibility is each hunter's own filters. cs-beacon's segment walk
    and the pipe hunter's region walk see the same dump and legitimately
    take different amounts of it into scope; the number is attributed to
    the hunter, never presented as a property of the dump."""
    from dumpex.hunt.cs_beacon.collect import collect_cs_beacon_record

    mf = _region_mf(size=8 * _KB)
    mf.memory_segments_64 = FakeStream(
        [Segment(_BASE, 0x1000, 8 * _KB), Segment(_BASE + 0x100000, 0x3000, 16 * _KB)],
        "memory_segments")

    assert _pipe_coverage(mf).missed_bytes.eligible_bytes == 8 * _KB
    assert collect_cs_beacon_record(mf).coverage.missed_bytes.eligible_bytes == 24 * _KB


def test_a_scan_targets_gap_stays_inside_the_scope_that_named_it():
    """The gap's own extent is the suffix of the captured range the scan
    did not reach, so it is bounded by the item's captured size -- which
    is the same number that item contributed to its pass's scope."""
    mf = _region_mf(size=8 * _KB)
    tracker = CoverageTracker()
    tracker.note_eligible(8 * _KB)
    tracker.note_short_read(region_scan_target(mf, mf.memory_info.infos[0]), got=2 * _KB)
    tracker.note_scanned()

    missed = summarize_missed_bytes([_gap(*tracker.short_read_targets)],
                                     eligible_bytes=tracker.eligible_bytes)
    assert missed.unscanned_pass_bytes == 6 * _KB
    assert missed.eligible_bytes == 8 * _KB
    assert missed.unscanned_fraction == 0.75


# ── nothing else moves ──────────────────────────────────────────────────

def test_the_scale_decides_no_status_and_no_exit_code():
    """A denominator grades a `partial`; it never decides whether one is
    reported. The same limitations reduce to the same status with and
    without one."""
    limitations = [_gap(_target(_BASE, 4 * _KB))]
    scaled = CoverageReport(status="partial", limitations=limitations,
                             eligible_bytes=64 * _KB)
    bare = CoverageReport(status="partial", limitations=limitations)

    assert scaled.status is bare.status is CoverageStatus.PARTIAL
    assert scaled.reasons == bare.reasons
    assert scaled.missed_bytes.known_bytes == bare.missed_bytes.known_bytes
