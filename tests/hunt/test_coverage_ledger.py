"""Per-scan-loop reconciliation tests for the shared coverage ledger.

Every loop that drives a `dumpex.hunt._coverage.CoverageTracker` must, for
EVERY branch out of an iteration, record exactly one disposition against
exactly one `note_eligible()`. `tests/unit/test_coverage.py` pins the
tracker's own arithmetic; this module pins the six shipped loops against
it, branch by branch:

    oversize / read raises / short read (non-empty) / empty read /
    not-applicable / full scan

A loop that drops an item through a bare `continue` shows up here as
`accounted != total`; one that reports coverage from a tracker it never
called `note_eligible()` on shows up as `eligible_total == 0` with
dispositions recorded against it.
"""
import ast
import pathlib
import re
import time
from collections import Counter

import pytest

from tests.fixtures.fakes import FakeMF, FakeReader, FakeStream, Region, Segment

from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._coverage import (
    CoverageTracker, UNACCOUNTED_LABEL, OVER_ACCOUNTED_LABEL, UNBALANCED_LABEL,
)
from dumpex.hunt.cs_beacon.config import CSBeaconConfig
from dumpex.hunt.cs_beacon.scanner import scan_segments
from dumpex.hunt.encoding.config import EncodingConfig
from dumpex.hunt.encoding.decoding import scan_decode_layers
from dumpex.hunt.encoding.entropy import _scan_entropy
from dumpex.hunt.encoding.models import LayerCoverage
from dumpex.hunt.encoding.sleep_mask import _scan_sleep_mask
from dumpex.hunt.pipe.memory_scan import scan_pipe_names
from dumpex.hunt.pipe.models import PipeScanCoverage
from dumpex.hunt.stomping.memory_scan import scan_ioc_strings
from dumpex.hunt.stomping.models import IocCoverage
from dumpex.output.coverage import (
    CoverageStatus, LimitationCode, ScanTarget, ScanTargetKind, render_limitation,
)
import dumpex.hunt.cs_beacon.domain as cs_domain
import dumpex.hunt.cs_beacon.report_facts as cs_facts
import dumpex.hunt.encoding.domain as encoding_domain
import dumpex.hunt.encoding.report_facts as encoding_facts
import dumpex.hunt.pipe.domain as pipe_domain
import dumpex.hunt.pipe.report_facts as pipe_facts
import dumpex.hunt.stomping.domain as stomping_domain
import dumpex.hunt.stomping.report_facts as stomping_facts


BASE = 0x30000000


def _mf(regions=(), modules=(), captured=()):
    """`captured` is the dump's own segment table: what these VAs are
    actually backed by on disk, which is what the ledger's byte total
    counts. Defaults to empty -- a region whose bytes were never written
    to the .dmp at all."""
    class MF(FakeMF):
        memory_info = FakeStream(list(regions), "infos")
    MF.modules = FakeStream(list(modules), "modules")
    MF.memory_segments_64 = FakeStream(list(captured), "memory_segments")
    return MF()


def _captured(base=BASE, size=0x2000, file_offset=0x1000):
    return Segment(base, file_offset, size)


def _private_region(base=BASE, size=0x2000):
    """Eligible for entropy/decode/sleep_mask: committed, private, not
    module-backed, PAGE_READWRITE (sleep_mask's own extra filter)."""
    return Region(base, base, size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")


def _image_region(base=BASE, size=0x2000):
    """Eligible for stomping's IOC scan: committed, MEM_IMAGE, executable."""
    return Region(base, base, size, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_IMAGE")


def _oversize_target(base=BASE, size=32 * 1024, limit=16 * 1024):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=size, size_limit=limit)


def _failure_target(base=BASE, size=4096):
    return ScanTarget(kind=ScanTargetKind.MEMORY_REGION, base_address=base,
                       size=size, size_limit=None)


def _raising_reader(_mf_arg, _addr, _size):
    raise OSError("simulated read failure")


def _fixed_reader(data):
    def _read(_mf_arg, _addr, _size):
        return data
    return _read


def _encoding_config(**overrides):
    base = dict(
        entropy_private_threshold=7.0, entropy_rwx_threshold=6.5,
        entropy_scan_max=0x10000,
        decode_scan_max=0x10000, xor_scan_max=0x10000,
        sleep_mask_key_size=16, sleep_mask_min_repeat=4, sleep_mask_max_byte_freq=0.5,
        sleep_mask_min_acbd=0.0, sleep_mask_max_candidates=4, sleep_mask_region_max=0x10000,
        sleep_mask_validate_sample=64, sleep_mask_validation_marker=b"MZ",
        sleep_mask_max_windows=4,
    )
    base.update(overrides)
    return EncodingConfig(**base)


def _budget():
    return ScanBudget(max_bytes_read=10**9, max_attempts=10**9,
                       max_retained_bytes=10**9, max_hits=10**9,
                       deadline=time.monotonic() + 60)


def _accounted(coverage) -> int:
    """The four dispositions, summed HERE rather than read off a property
    the snapshot provides: an independently computed total is what makes
    `accounted == eligible_total` an actual check."""
    return (coverage.scanned + coverage.not_applicable + coverage.read_failed
            + getattr(coverage, "budget_skipped", 0)
            + len(coverage.skipped_oversize_targets))


def _gap_free(coverage) -> bool:
    """The gap half of `CoverageTracker.complete`, read off whichever
    frozen snapshot a scan returned. Spelled out here rather than through
    a `complete` property on each transport: the hunters' own domain
    snapshots are what production reduces to a status, so a transport-level
    `complete` would be a second, unread definition of the same thing."""
    return not (coverage.skipped_oversize_targets or coverage.read_failed
                or coverage.short_reads or coverage.unaccounted
                or coverage.over_accounted)


def _assert_reconciled(coverage, *, expect_total, note=""):
    """The ledger invariant every branch of every loop must hold."""
    assert coverage.eligible_total == expect_total, note
    assert _accounted(coverage) == coverage.eligible_total, (
        f"{note}: {_accounted(coverage)} disposition(s) recorded for "
        f"{coverage.eligible_total} eligible item(s)")
    assert coverage.unaccounted == 0, note
    assert coverage.over_accounted == 0, note


# ── The region scanners, branch by branch ─────────────────────────────────
#
# Each entry drives ONE scan function over one region (or a whole list of
# them) and returns its frozen coverage snapshot, so the branch matrix
# below can be shared.

def _as_items(region):
    return region if isinstance(region, list) else [region]


def _run_entropy(region, reader, config=None, captured=()):
    regions = _as_items(region)
    result = _scan_entropy(regions, [], _mf(captured=captured), (), reader,
                            config or _encoding_config())
    return result.coverage


def _run_decode(region, reader, config=None, captured=()):
    regions = _as_items(region)
    result = scan_decode_layers(regions, [], _mf(captured=captured), reader,
                                 config or _encoding_config(), _budget())
    return result.coverage


def _run_sleep_mask(region, reader, config=None, captured=()):
    regions = _as_items(region)
    result = _scan_sleep_mask(regions, [], _mf(captured=captured), reader,
                               config or _encoding_config(), _budget())
    return result.coverage


def _run_pipe(region, reader, config=None, captured=()):
    regions = _as_items(region)
    result = scan_pipe_names(_mf(captured=captured), reader, regions, [], CoverageTracker(),
                             _budget(), _budget(), re.compile(r"nothing-matches-this"))
    return result.coverage


def _run_ioc(region, reader, config=None, captured=()):
    regions = _as_items(region)
    result = scan_ioc_strings(_mf(captured=captured), reader, regions, [], frozenset(),
                              re.compile(r"VirtualAlloc"), re.compile(r"https?://"))
    return result.coverage


def _cs_config(**overrides):
    base = dict(max_seg_scan=0x10000, config_decode_max=0x1000, max_candidates=1000,
                max_decoded_bytes=10**6, max_hits=10, scan_deadline_seconds=60,
                max_total_scanned_bytes=10**7)
    base.update(overrides)
    return CSBeaconConfig(**base)


def _cs_scan(segment, read_map, config=None):
    class MF(FakeMF):
        pass
    MF.get_reader = lambda self: FakeReader(read_map)
    segments = segment if isinstance(segment, list) else [segment]
    _hits, diagnostics = scan_segments(MF(), segments, config or _cs_config(), [])
    return diagnostics


def _run_cs_beacon(region, reader, config=None, captured=()):
    """The segment scan behind the cs_beacon construction site, driven the
    same way the region runners are so the matrix and the registry can
    treat all six alike. Each Region fixture names a VA and a size; a
    segment carries its own file offset."""
    segments = [Segment(item.BaseAddress, 0x400 + index * 0x2000, item.RegionSize)
                for index, item in enumerate(_as_items(region))]
    read_map = {}
    for seg in segments:
        try:
            read_map[seg.start_virtual_address] = reader(None, seg.start_virtual_address,
                                                          seg.size)
        except Exception:
            pass    # an unmapped VA is how FakeReader reports a failed read
    return _cs_scan(segments, read_map)


REGION_SCANS = {
    "entropy":    (_run_entropy,    _private_region, "entropy_scan_max"),
    "decode":     (_run_decode,     _private_region, "decode_scan_max"),
    "sleep_mask": (_run_sleep_mask, _private_region, "sleep_mask_region_max"),
    "pipe":       (_run_pipe,       _private_region, None),
    "ioc":        (_run_ioc,        _image_region,   None),
}


# Every loop, including cs_beacon's segment scan, for the branches that do
# not depend on being a MemoryInfo region: `_run_cs_beacon` (defined with
# the construction-site registry below) turns the same Region fixture into
# the one-segment scan its own loop walks.
def _all_scans():
    scans = {name: (run, make_region)
             for name, (run, make_region, _cap) in REGION_SCANS.items()}
    scans["cs_beacon"] = (_run_cs_beacon, _private_region)
    return scans


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_a_fully_scanned_region_reconciles(scan_name):
    run, make_region, _cap = REGION_SCANS[scan_name]
    region = make_region()
    coverage = run(region, _fixed_reader(b"\x00" * region.RegionSize),
                   captured=[_captured(size=region.RegionSize)])

    _assert_reconciled(coverage, expect_total=1, note=scan_name)
    assert coverage.scanned == 1, (
        f"{scan_name} recorded no `scanned` disposition for a region it read in full")
    assert coverage.eligible_bytes == region.RegionSize
    assert _gap_free(coverage) is True


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_the_byte_ledger_counts_captured_bytes_not_declared_region_size(scan_name):
    """A region can declare more address space than the dump ever wrote.
    The byte total is the denominator for a fraction-of-eligible-memory
    reading of partial coverage, so it counts what the .dmp actually
    holds -- here a 0x2000 region backed by only 0x800 captured bytes."""
    run, make_region, _cap = REGION_SCANS[scan_name]
    region = make_region(size=0x2000)
    coverage = run(region, _fixed_reader(b"\x00" * 0x800),
                   captured=[_captured(size=0x800)])

    assert coverage.eligible_total == 1
    assert coverage.eligible_bytes == 0x800


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_a_region_the_dump_never_captured_contributes_no_bytes(scan_name):
    run, make_region, _cap = REGION_SCANS[scan_name]
    region = make_region()
    coverage = run(region, _fixed_reader(b"\x00" * region.RegionSize), captured=[])

    assert coverage.eligible_total == 1
    assert coverage.eligible_bytes == 0


@pytest.mark.parametrize("scan_name", sorted(_all_scans()))
def test_a_read_failure_reconciles(scan_name):
    run, make_region = _all_scans()[scan_name]
    coverage = run(make_region(), _raising_reader)

    _assert_reconciled(coverage, expect_total=1, note=scan_name)
    assert coverage.read_failed == 1
    assert _gap_free(coverage) is False


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_a_non_empty_short_read_is_scanned_and_annotated(scan_name):
    """The item is BOTH scanned (its readable prefix was) and short-read
    (the remainder never was) -- one disposition, one annotation, and it
    must not be counted against `total` twice."""
    run, make_region, _cap = REGION_SCANS[scan_name]
    region = make_region()
    coverage = run(region, _fixed_reader(b"\x41" * (region.RegionSize // 2)))

    _assert_reconciled(coverage, expect_total=1, note=scan_name)
    assert (coverage.short_reads, coverage.scanned) == (1, 1)
    assert _gap_free(coverage) is False


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_an_empty_read_reconciles_as_a_read_failure(scan_name):
    """Nothing came back at all: there is no readable prefix to scan, so
    the item takes the read-failed disposition rather than being annotated
    as a short read and then dropped with no disposition at all."""
    run, make_region, _cap = REGION_SCANS[scan_name]
    coverage = run(make_region(), _fixed_reader(b""))

    _assert_reconciled(coverage, expect_total=1, note=scan_name)
    assert coverage.read_failed == 1
    assert coverage.scanned == 0
    assert _gap_free(coverage) is False


@pytest.mark.parametrize("scan_name", ["entropy", "decode", "sleep_mask"])
def test_an_oversized_skip_reconciles(scan_name):
    run, make_region, cap_field = REGION_SCANS[scan_name]
    region = make_region(size=0x8000)
    coverage = run(region, _fixed_reader(b"\x00" * region.RegionSize),
                   _encoding_config(**{cap_field: 0x1000}))

    _assert_reconciled(coverage, expect_total=1, note=scan_name)
    assert len(coverage.skipped_oversize_targets) == 1
    assert _gap_free(coverage) is False


def test_pipe_oversized_skip_reconciles(monkeypatch):
    import dumpex.hunt.pipe.memory_scan as pipe_scan
    monkeypatch.setattr(pipe_scan, "PIPE_SCAN_MAX", 0x1000)
    region = _private_region(size=0x8000)
    result = scan_pipe_names(_mf(), _fixed_reader(b"\x00" * region.RegionSize), [region], [],
                             CoverageTracker(), _budget(), _budget(),
                             re.compile(r"nothing-matches-this"))

    _assert_reconciled(result.coverage, expect_total=1, note="pipe")
    assert len(result.coverage.skipped_oversize_targets) == 1
    assert _gap_free(result.coverage) is False


def test_ioc_oversized_skip_reconciles(monkeypatch):
    import dumpex.hunt.stomping.memory_scan as ioc_scan
    monkeypatch.setattr(ioc_scan, "IOC_SCAN_MAX", 0x1000)
    region = _image_region(size=0x8000)
    result = scan_ioc_strings(_mf(), _fixed_reader(b"\x00" * region.RegionSize), [region], [],
                              frozenset(), re.compile(r"VirtualAlloc"), re.compile(r"https?://"))

    _assert_reconciled(result.coverage, expect_total=1, note="ioc")
    assert len(result.coverage.skipped_oversize_targets) == 1
    assert _gap_free(result.coverage) is False


def test_entropy_records_a_not_applicable_disposition_for_an_unscoreable_region():
    """`len(data) < 256` reads fine but cannot be scored -- an OUTCOME, not
    a gap: it reconciles, and it does not make coverage partial."""
    region = _private_region(size=0x80)
    coverage = _run_entropy(region, _fixed_reader(b"\x00" * region.RegionSize))

    _assert_reconciled(coverage, expect_total=1, note="entropy")
    assert (coverage.not_applicable, coverage.scanned) == (1, 0)
    assert _gap_free(coverage) is True


@pytest.mark.parametrize("scan_name", sorted(REGION_SCANS))
def test_filtered_out_regions_are_never_counted_as_eligible(scan_name):
    """`note_eligible()` goes AFTER the filter block: a region this scan
    was never supposed to look at is not a coverage gap, and counting it
    would put a permanent caveat on every run."""
    run, _make_region, _cap = REGION_SCANS[scan_name]
    reserved = Region(BASE, BASE, 0x2000, "MEM_RESERVE", "PAGE_NOACCESS", "MEM_PRIVATE")
    coverage = run(reserved, _fixed_reader(b"\x00" * 0x2000))

    assert coverage.eligible_total == 0
    assert _accounted(coverage) == 0
    assert _gap_free(coverage) is True


@pytest.mark.parametrize("scan_name", sorted(_all_scans()))
def test_a_zero_length_item_is_filtered_not_dispositioned(scan_name):
    """An item that declares no bytes has nothing to read and no bytes
    anyone could miss. It is filtered before eligibility -- and never
    turned into a ScanTarget, which has an extent by definition and
    rejects a zero-length one."""
    run, make_region = _all_scans()[scan_name]
    coverage = run(make_region(size=0), _fixed_reader(b""))

    assert coverage.eligible_total == 0, scan_name
    assert _accounted(coverage) == 0, scan_name
    assert _gap_free(coverage) is True, scan_name


@pytest.mark.parametrize("scan_name", sorted(_all_scans()))
def test_each_eligible_item_is_counted_exactly_once(scan_name):
    """No double-count across a multi-item walk, and `eligible_bytes`
    sums the same set of items `eligible_total` counts."""
    run, make_region = _all_scans()[scan_name]
    items = [make_region(base=BASE + i * 0x10000, size=0x2000) for i in range(4)]
    captured = [_captured(base=item.BaseAddress, size=0x2000) for item in items]
    coverage = run(items, _fixed_reader(b"\x00" * 0x2000), captured=captured)

    assert coverage.eligible_total == 4, scan_name
    assert coverage.eligible_bytes == 4 * 0x2000, scan_name
    _assert_reconciled(coverage, expect_total=4, note=f"{scan_name} multi-item")


# ── cs_beacon's segment scan ──────────────────────────────────────────────

def test_cs_beacon_counts_a_segments_own_size_as_captured_bytes():
    """Unlike a MemoryInfo region, a segment-table entry IS the dump's own
    claim that exactly this many bytes are captured at this file offset,
    so the byte ledger takes `seg.size` directly."""
    seg = Segment(BASE, 0x400, 0x2000)
    diagnostics = _cs_scan(seg, {BASE: b"\x00" * seg.size})

    assert diagnostics.eligible_bytes == seg.size


def test_cs_beacon_full_segment_scan_reconciles():
    seg = Segment(BASE, 0x400, 0x2000)
    diagnostics = _cs_scan(seg, {BASE: b"\x00" * seg.size})

    _assert_reconciled(diagnostics, expect_total=1, note="cs_beacon")
    assert diagnostics.scanned == 1, (
        "cs_beacon recorded no `scanned` disposition for a segment it read in full")
    assert diagnostics.eligible_bytes == seg.size
    assert diagnostics.scan_complete is True


def test_cs_beacon_short_read_is_scanned_and_annotated():
    seg = Segment(BASE, 0x400, 0x2000)
    diagnostics = _cs_scan(seg, {BASE: b"\x41" * (seg.size // 2)})

    _assert_reconciled(diagnostics, expect_total=1, note="cs_beacon")
    assert (diagnostics.short_reads, diagnostics.scanned) == (1, 1)
    assert diagnostics.scan_complete is False


def test_cs_beacon_empty_read_reconciles_as_a_read_failure():
    seg = Segment(BASE, 0x400, 0x2000)
    diagnostics = _cs_scan(seg, {})     # FakeReader returns b'' for an unmapped VA

    _assert_reconciled(diagnostics, expect_total=1, note="cs_beacon")
    assert (diagnostics.read_failed, diagnostics.scanned) == (1, 0)
    assert diagnostics.scan_complete is False


def test_cs_beacon_oversized_segment_reconciles():
    seg = Segment(BASE, 0x400, 0x8000)
    diagnostics = _cs_scan(seg, {BASE: b"\x00" * seg.size}, _cs_config(max_seg_scan=0x1000))

    _assert_reconciled(diagnostics, expect_total=1, note="cs_beacon")
    assert diagnostics.skipped_oversize == 1
    assert diagnostics.scan_complete is False


def test_cs_beacon_segments_never_reached_are_not_eligible():
    """A whole-scan budget stops the walk BEFORE later segments are taken
    into scope, so they are not unaccounted items -- `budget_exhausted_
    targets` is what accounts for those, and the ledger must not
    double-report them as a loop bug."""
    segs = [Segment(BASE + i * 0x10000, 0x400 + i * 0x2000, 0x2000) for i in range(3)]
    read_map = {s.start_virtual_address: b"\x00" * s.size for s in segs}

    class MF(FakeMF):
        pass
    MF.get_reader = lambda self: FakeReader(read_map)
    # Room for one segment's bytes only -- the walk stops at the second.
    _hits, diagnostics = scan_segments(MF(), segs, _cs_config(max_total_scanned_bytes=0x2000), [])

    assert diagnostics.eligible_total == 1
    assert _accounted(diagnostics) == 1
    assert diagnostics.unaccounted == 0
    assert diagnostics.budget_exhausted is True
    assert diagnostics.scan_complete is False   # via the budget gap, not the ledger


# ── The gap reaches every output surface ──────────────────────────────────
#
# The whole path for each hunter: the domain snapshot's own `complete`, the
# v1.1 coverage_status/coverage_reasons pair, and the structured
# CoverageReport's status plus its SCAN_ITEMS_UNACCOUNTED limitation. A
# shortfall visible only in a boolean would reach no reader.


def _unaccounted_limitation(report):
    matches = [lim for lim in report.limitations
               if lim.code == LimitationCode.SCAN_ITEMS_UNACCOUNTED]
    assert len(matches) == 1, [lim.code for lim in report.limitations]
    return matches[0]


def test_pipe_surfaces_an_unaccounted_region_as_partial_coverage():
    coverage = pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, unaccounted=1)

    assert coverage.region_scan_complete is False
    assert coverage.complete is False
    assert coverage.status == "partial"
    assert coverage.region_gap_reasons() == (f"1 region(s) {UNACCOUNTED_LABEL}",)

    status, reasons = pipe_facts.project_coverage_v1(coverage)
    assert status == "partial"
    assert f"1 region(s) {UNACCOUNTED_LABEL}" in reasons

    report = pipe_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 1


def test_stomping_surfaces_an_unaccounted_ioc_region_as_partial_coverage():
    coverage = stomping_domain.CoverageSnapshot(
        memory_info_stream=True, module_list_stream=True, ref_dir_supplied=True,
        ioc_unaccounted=2)

    assert coverage.ioc_complete is False
    assert coverage.complete is False
    assert coverage.ioc_gap_reasons() == (f"2 region(s) {UNACCOUNTED_LABEL}",)

    report = stomping_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 2


def test_encoding_surfaces_unaccounted_regions_as_partial_coverage():
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=3, any_region_scanned=True,
        entropy_unaccounted=1)

    assert coverage.complete is False
    _dict, status, reasons = encoding_facts.project_coverage_v1(coverage)
    assert status == "partial"
    assert f"1 region(s) in the entropy scan {UNACCOUNTED_LABEL}" in reasons

    report = encoding_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    limitation = _unaccounted_limitation(report)
    assert (limitation.scope, limitation.affected_count) == ("entropy", 1)


def test_encoding_attributes_an_unreconciled_ledger_to_the_layer_that_lost_it():
    """The three layer scans run their own loops over the same regions, so
    a summed count would say a region went unaccounted without saying
    which scan lost it -- the same reason the oversized/read-failed/
    short-read gaps above are never summed either."""
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=8, any_region_scanned=True,
        sleep_mask_unaccounted=2, decode_over_accounted=3)

    assert coverage.unaccounted == 2 and coverage.over_accounted == 3
    assert coverage.unaccounted_by_layer() == (("sleep_mask", 2),)
    assert coverage.over_accounted_by_layer() == (("decode", 3),)
    assert coverage.unreconciled_by_layer() == (("sleep_mask", 2), ("decode", 3))

    _dict, _status, reasons = encoding_facts.project_coverage_v1(coverage)
    assert f"2 region(s) in the sleep_mask scan {UNACCOUNTED_LABEL}" in reasons
    assert f"3 region(s) in the decode scan {OVER_ACCOUNTED_LABEL}" in reasons

    report = encoding_facts.project_coverage_report(coverage)
    by_scope = {lim.scope: lim.affected_count for lim in report.limitations
                if lim.code == LimitationCode.SCAN_ITEMS_UNACCOUNTED}
    assert by_scope == {"sleep_mask": 2, "decode": 3}


def test_encoding_counts_both_ledger_directions_of_one_layer_together():
    """One limitation per layer, not per direction: `affected_count` is
    how many of that layer's regions have no trustworthy outcome."""
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=8, any_region_scanned=True,
        entropy_unaccounted=1, entropy_over_accounted=2)

    assert coverage.unreconciled_by_layer() == (("entropy", 3),)
    limitation = _unaccounted_limitation(encoding_facts.project_coverage_report(coverage))
    assert (limitation.scope, limitation.affected_count) == ("entropy", 3)


def test_cs_beacon_surfaces_an_unaccounted_segment_as_partial_coverage():
    scan = cs_domain.ScanDiagnostics(segment_count=1, eligible_total=1, unaccounted=1)
    coverage = cs_domain.CoverageSnapshot(scan=scan, mem_info_available=True)

    assert scan.unaccounted == 1
    assert scan.scan_complete is False
    assert coverage.complete(has_hits=False, any_corroborated=False) is False

    status, reasons = cs_facts.project_coverage_v1(coverage, has_hits=False,
                                                   any_corroborated=False)
    assert status == "partial"
    assert f"1 segment(s) {UNACCOUNTED_LABEL}" in reasons

    report = cs_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 1


def test_the_unaccounted_limitation_validates_against_the_current_schema():
    """`SCAN_ITEMS_UNACCOUNTED` rides the OPEN `code` field the v2.13
    `coverageLimitation` $def allows, carrying only affected_count (never
    `targets` -- see LimitationCode.SCAN_ITEMS_UNACCOUNTED). Pinned here so
    this gap cannot be emitted in a shape --json would reject at the very
    moment it fires."""
    jsonschema = pytest.importorskip("jsonschema")
    import json
    from dumpex.schemas import CURRENT_SCHEMA, schema_path

    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(
        {"$schema": schema["$schema"], "$ref": "#/$defs/coverageLimitation",
         "$defs": schema["$defs"]})

    report = pipe_facts.project_coverage_report(pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, unaccounted=1))
    payload = _unaccounted_limitation(report).to_dict()

    validator.validate(payload)
    assert payload["targets"] == []
    assert payload["affected_count"] == 1


def _run_pipe_builder(region, reader, config=None, captured=()):
    """Drives `pipe._build_pipe_report`, the function that CONSTRUCTS the
    tracker, and reports the ledger of the tracker it actually handed to
    `scan_pipe_names` -- so a builder that stopped passing its own tracker
    through (or built a second one elsewhere) fails here rather than
    passing on a tracker the test supplied itself."""
    import dumpex.hunt.pipe as pipe_pkg
    import dumpex.hunt.pipe.memory_scan as pipe_memory_scan

    seen = []
    real_scan = pipe_memory_scan.scan_pipe_names

    def capturing_scan(mf, read_region, regions, modules, coverage_counts, *args, **kwargs):
        seen.append(coverage_counts)
        return real_scan(mf, read_region, regions, modules, coverage_counts, *args, **kwargs)

    mf = _mf(regions=[region], captured=captured)
    original_scan, original_read = pipe_memory_scan.scan_pipe_names, pipe_pkg.read_region
    pipe_pkg.memory_scan.scan_pipe_names = capturing_scan
    pipe_pkg.read_region = reader
    try:
        pipe_pkg._build_pipe_report(mf)
    finally:
        pipe_pkg.memory_scan.scan_pipe_names = original_scan
        pipe_pkg.read_region = original_read

    assert len(seen) == 1, "pipe built its report without driving exactly one tracker"
    # Frozen into the same transport shape the other runners return; the
    # budget fields are not what this drives, so fresh ones are fine.
    return PipeScanCoverage.from_scan(seen[0], _budget(), _budget())


# Every `CoverageTracker(...)` construction site in dumpex/hunt, paired
# with the scan entry point that drives it. Each pairing is checked twice
# below: the set of sites has to match what the tree actually contains
# (so a new tracker anywhere -- including inside a package that already
# has one -- lands here rather than inheriting a sibling's coverage), and
# each entry point has to open eligible items when it runs.
TRACKER_CONSTRUCTION_SITES = {
    "cs_beacon/scanner.py::scan_segments":          (_run_cs_beacon,  _private_region),
    "encoding/decoding.py::scan_decode_layers":     (_run_decode,     _private_region),
    "encoding/entropy.py::_scan_entropy":           (_run_entropy,    _private_region),
    "encoding/sleep_mask.py::_scan_sleep_mask":     (_run_sleep_mask, _private_region),
    "pipe/__init__.py::_build_pipe_report":  (_run_pipe_builder, _private_region),
    "stomping/memory_scan.py::scan_ioc_strings":    (_run_ioc,        _image_region),
}


class _TrackerConstructionVisitor(ast.NodeVisitor):
    """Every `CoverageTracker(...)` call, keyed by the function that makes
    it. Located by AST rather than substring (the name in a docstring or a
    comment is not a construction site) and counted rather than
    de-duplicated, so a SECOND tracker built in an already-registered
    function is a change this sees."""

    def __init__(self):
        self.enclosing = []
        self.sites = []

    def visit_FunctionDef(self, node):
        self.enclosing.append(node.name)
        self.generic_visit(node)
        self.enclosing.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        # Both spellings: `CoverageTracker(...)` and, via a module alias,
        # `cov.CoverageTracker(...)`.
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name == "CoverageTracker":
            self.sites.append("::".join(self.enclosing) or "<module>")
        self.generic_visit(node)


def _tracker_construction_sites():
    """`{"package/module.py::function": how many trackers it builds}`."""
    hunt_root = pathlib.Path(__file__).resolve().parents[2] / "dumpex" / "hunt"
    found = Counter()
    for path in sorted(hunt_root.rglob("*.py")):
        visitor = _TrackerConstructionVisitor()
        visitor.visit(ast.parse(path.read_text(encoding="utf-8")))
        for function in visitor.sites:
            found[f"{path.relative_to(hunt_root).as_posix()}::{function}"] += 1
    return found


def test_the_construction_site_registry_matches_the_tree():
    """A tracker built anywhere in dumpex/hunt has to be registered above
    against the scan entry point that drives it, one entry per tracker.
    Pinning the exact multiset of sites -- rather than asking whether the
    surrounding package calls note_eligible somewhere -- is what stops a
    second tracker, in a new module OR alongside an existing one, from
    inheriting a sibling's ledger coverage."""
    expected = Counter(TRACKER_CONSTRUCTION_SITES.keys())   # one tracker per entry
    assert _tracker_construction_sites() == expected, (
        "a CoverageTracker is built at a site this module does not pin -- add it to "
        "TRACKER_CONSTRUCTION_SITES together with the scan entry point that drives "
        "it, so its ledger is exercised the way the other six are")


@pytest.mark.parametrize("site", sorted(TRACKER_CONSTRUCTION_SITES))
def test_every_construction_site_opens_eligible_items(site):
    """The runtime half: each registered entry point, given one item that
    passes its own filters, actually takes that item into scope. A tracker
    that is never told about its items reports `total == 0` while its
    dispositions pile up as `over_accounted` -- a permanent "partial" that
    says nothing useful."""
    run, make_region = TRACKER_CONSTRUCTION_SITES[site]
    region = make_region()
    coverage = run(region, _fixed_reader(b"\x00" * region.RegionSize),
                   captured=[_captured(size=region.RegionSize)])

    assert coverage.eligible_total == 1, (
        f"{site}'s scan recorded {_accounted(coverage)} disposition(s) against "
        f"{coverage.eligible_total} eligible item(s) -- its loop never calls "
        f"note_eligible()")
    assert (coverage.unaccounted, coverage.over_accounted) == (0, 0)


# ── Both ledger directions survive the projection ─────────────────────────
#
# A scan loop that never takes items into scope records outcomes that
# belong to no item. That is the opposite direction from a missed
# disposition, and it has to reach the same output surfaces -- a
# projection that kept only the shortfall would let this one render as a
# clean, complete scan.

def _tracker_with_stray_dispositions(count=2):
    tracker = CoverageTracker()
    for _ in range(count):
        tracker.note_scanned()      # no note_eligible() anywhere
    return tracker


def test_a_scan_that_never_takes_items_into_scope_is_not_complete():
    tracker = _tracker_with_stray_dispositions()
    assert (tracker.total, tracker.over_accounted) == (0, 2)
    assert tracker.complete is False

    for coverage in (LayerCoverage.from_tracker(tracker),
                     IocCoverage.from_tracker(tracker),
                     PipeScanCoverage.from_scan(tracker, _budget(), _budget())):
        assert coverage.over_accounted == 2, type(coverage).__name__
        assert _accounted(coverage) != coverage.eligible_total, type(coverage).__name__


def test_pipe_surfaces_over_accounted_regions_as_partial_coverage():
    coverage = pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, over_accounted=2)

    assert coverage.region_scan_complete is False
    assert coverage.status == "partial"
    assert coverage.region_gap_reasons() == (f"2 region(s) {OVER_ACCOUNTED_LABEL}",)
    report = pipe_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 2


def test_stomping_surfaces_over_accounted_ioc_regions_as_partial_coverage():
    coverage = stomping_domain.CoverageSnapshot(
        memory_info_stream=True, module_list_stream=True, ref_dir_supplied=True,
        ioc_over_accounted=1)

    assert coverage.ioc_complete is False
    assert coverage.ioc_gap_reasons() == (f"1 region(s) {OVER_ACCOUNTED_LABEL}",)
    report = stomping_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 1


def test_encoding_surfaces_over_accounted_regions_as_partial_coverage():
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=3, any_region_scanned=True,
        decode_over_accounted=1)

    assert coverage.complete is False
    _dict, status, reasons = encoding_facts.project_coverage_v1(coverage)
    assert status == "partial"
    assert f"1 region(s) in the decode scan {OVER_ACCOUNTED_LABEL}" in reasons
    report = encoding_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    limitation = _unaccounted_limitation(report)
    assert (limitation.scope, limitation.affected_count) == ("decode", 1)


def test_cs_beacon_surfaces_over_accounted_segments_as_partial_coverage():
    scan = cs_domain.ScanDiagnostics(segment_count=1, scanned=1, over_accounted=1)
    coverage = cs_domain.CoverageSnapshot(scan=scan, mem_info_available=True)

    assert scan.scan_complete is False
    assert coverage.complete(has_hits=False, any_corroborated=False) is False
    status, reasons = cs_facts.project_coverage_v1(coverage, has_hits=False,
                                                   any_corroborated=False)
    assert status == "partial"
    assert f"1 segment(s) {OVER_ACCOUNTED_LABEL}" in reasons
    report = cs_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 1


def test_pipe_records_no_scan_for_a_region_its_budget_left_unexamined():
    """`scanned` says a pattern actually ran over the region's bytes. With
    the pipe-name budget already spent nothing runs -- no pattern, and no
    C2 pass either, since those are gated on this region yielding a NEW
    pipe name -- so the region takes the budget-skipped disposition rather
    than inflating the scanned count. It stays out of `not_applicable`
    too: a bigger budget would reach these regions."""
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(5)]
    spent = ScanBudget(max_bytes_read=10**9, max_attempts=10**9, max_retained_bytes=10**9,
                        max_hits=10**9, deadline=time.monotonic() - 1)
    result = scan_pipe_names(_mf(captured=[_captured(base=r.BaseAddress, size=0x1000)
                                            for r in regions]),
                             _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100),
                             regions, [], CoverageTracker(), spent, _budget(),
                             re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert coverage.eligible_total == 5
    assert (coverage.scanned, coverage.budget_skipped) == (0, 5)
    assert coverage.not_applicable == 0
    assert result.string_leads == ()
    _assert_reconciled(coverage, expect_total=5, note="pipe budget spent")


def test_pipe_records_a_scan_once_a_pattern_actually_runs():
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(5)]
    result = scan_pipe_names(_mf(), _fixed_reader(b"\x00" * 0x1000), regions, [],
                             CoverageTracker(), _budget(), _budget(),
                             re.compile(r"nothing-matches-this"))

    assert (result.coverage.scanned, result.coverage.budget_skipped) == (5, 0)
    _assert_reconciled(result.coverage, expect_total=5, note="pipe budgets live")


def _expired_budget():
    return ScanBudget(max_bytes_read=10**9, max_attempts=10**9, max_retained_bytes=10**9,
                       max_hits=10**9, deadline=time.monotonic() - 1)


def test_pipe_name_budget_names_every_eligible_region_it_left_unscanned():
    """A spent pipe-name budget does not just flip a flag: the eligible
    regions it never scanned are retained as targets so an analyst can go
    rescan the exact addresses."""
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(5)]
    result = scan_pipe_names(
        _mf(captured=[_captured(base=r.BaseAddress, size=0x1000) for r in regions]),
        _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100), regions, [],
        CoverageTracker(), _expired_budget(), _budget(),
        re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert [t.base_address for t in coverage.pipe_name_budget_exhausted_targets] == \
        [r.BaseAddress for r in regions]
    assert all(t.size_limit is None for t in coverage.pipe_name_budget_exhausted_targets)
    assert coverage.c2_budget_exhausted_targets == ()
    _assert_reconciled(coverage, expect_total=5, note="pipe-name budget spent")


def test_pipe_name_budget_targets_begin_at_the_region_it_ran_out_on():
    """A region whose pipe-name matching finished within budget is never a
    target; attribution begins at the region the budget was first unable to
    fully serve and runs to the end of the eligible walk."""
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(4)]
    one_hit = ScanBudget(max_bytes_read=10**9, max_attempts=10**9,
                          max_retained_bytes=10**9, max_hits=1)
    result = scan_pipe_names(
        _mf(captured=[_captured(base=r.BaseAddress, size=0x1000) for r in regions]),
        _fixed_reader(rb"\pipe\a" + b"\x00" * 0x100), regions, [],
        CoverageTracker(), one_hit, _budget(), re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert [t.base_address for t in coverage.pipe_name_budget_exhausted_targets] == \
        [r.BaseAddress for r in regions[1:]]
    _assert_reconciled(coverage, expect_total=4, note="pipe-name budget one hit")


def test_c2_budget_names_the_lead_bearing_regions_it_could_not_contextualize():
    """C2-context exhaustion keeps its OWN target set: the regions that
    yielded a new private pipe-name lead the c2_budget could not gather
    context for -- independent of the still-live pipe-name budget."""
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(3)]
    result = scan_pipe_names(
        _mf(captured=[_captured(base=r.BaseAddress, size=0x1000) for r in regions]),
        _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100), regions, [],
        CoverageTracker(), _budget(), _expired_budget(),
        re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert [t.base_address for t in coverage.c2_budget_exhausted_targets] == \
        [r.BaseAddress for r in regions]
    assert coverage.pipe_name_budget_exhausted_targets == ()
    _assert_reconciled(coverage, expect_total=3, note="c2 budget spent")


class _C2BudgetSpentBetweenPasses:
    """A c2_budget stand-in that stays healthy until pass 1 retains one
    record, then reports exhausted forever -- placing the deadline
    transition precisely in the gap between pass 1 finishing and the
    pass-2 guard, which no real clock lets a test hit deterministically."""

    def __init__(self):
        self._hits = 0
        self.exhausted_reason = ""

    def exhausted(self):
        if self._hits >= 1 and not self.exhausted_reason:
            self.exhausted_reason = "deadline"
        return bool(self.exhausted_reason)

    def poll(self):
        return not self.exhausted()

    def take_hit(self, retained_bytes=0):
        if self.exhausted():
            return False
        self._hits += 1
        return True


def test_c2_budget_spent_between_the_two_passes_still_names_the_region():
    """Pass 1 finishes cleanly, then the c2_budget is found spent at the
    pass-2 guard: this region's context-only C2 evidence was never
    gathered, so it is still a c2-scope target -- not silently dropped
    because pass 1 happened to complete."""
    region = _private_region(base=BASE, size=0x1000)
    # `\pipe\x` at offset 0 and an `http://` C2 token right after it, within
    # PIPE_CONTEXT_DISTANCE -- one proximity record for pass 1 to retain.
    data = rb"\pipe\x" + b"\x00" + b"http://c2" + b"\x00" + b"\x00" * 0x40
    c2_budget = _C2BudgetSpentBetweenPasses()
    result = scan_pipe_names(
        _mf(captured=[_captured(base=BASE, size=0x1000)]),
        _fixed_reader(data), [region], [], CoverageTracker(),
        _budget(), c2_budget, re.compile(r"https?://"))
    coverage = result.coverage

    assert coverage.c2_budget_exhausted is True
    assert [t.base_address for t in coverage.c2_budget_exhausted_targets] == [BASE]
    _assert_reconciled(coverage, expect_total=1, note="c2 budget spent between passes")


def test_both_budgets_spent_attributes_the_abandoned_walk_to_both_scopes():
    """With both budgets spent no scan work runs, but the walk still
    enumerates every remaining region: each reconciles as budget-skipped
    and is attributed to BOTH scopes -- neither signal can make a complete
    claim for those ranges."""
    regions = [_private_region(base=BASE + i * 0x10000, size=0x1000) for i in range(5)]
    result = scan_pipe_names(
        _mf(captured=[_captured(base=r.BaseAddress, size=0x1000) for r in regions]),
        _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100), regions, [],
        CoverageTracker(), _expired_budget(), _expired_budget(),
        re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    bases = [r.BaseAddress for r in regions]
    assert [t.base_address for t in coverage.pipe_name_budget_exhausted_targets] == bases
    assert [t.base_address for t in coverage.c2_budget_exhausted_targets] == bases
    assert (coverage.scanned, coverage.budget_skipped) == (0, 5)
    _assert_reconciled(coverage, expect_total=5, note="both budgets spent")


def test_oversized_region_in_the_abandoned_walk_keeps_its_oversized_skip():
    """An oversized region the walk reaches with both budgets spent is
    still recorded as an oversized skip with its own target -- a spent
    budget never relabels it or makes it vanish."""
    regions = [_private_region(base=BASE, size=0x1000),
               _private_region(base=BASE + 0x1000000, size=9 * 1024 * 1024)]
    result = scan_pipe_names(
        _mf(captured=[_captured(base=r.BaseAddress, size=r.RegionSize) for r in regions]),
        _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100), regions, [],
        CoverageTracker(), _expired_budget(), _expired_budget(),
        re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert [t.base_address for t in coverage.skipped_oversize_targets] == [BASE + 0x1000000]
    budget_targets = (coverage.pipe_name_budget_exhausted_targets
                      + coverage.c2_budget_exhausted_targets)
    assert all(t.base_address == BASE for t in budget_targets)
    _assert_reconciled(coverage, expect_total=2, note="oversized in abandoned walk")


def test_budget_targets_dedupe_a_duplicate_memoryinfo_entry():
    """A region list carrying the same physical entry twice must not
    inflate a scope's target tuple or its affected_count."""
    region = _private_region(base=BASE, size=0x1000)
    result = scan_pipe_names(
        _mf(captured=[_captured(base=BASE, size=0x1000)]),
        _fixed_reader(rb"\pipe\demo" + b"\x00" * 0x100), [region, region], [],
        CoverageTracker(), _expired_budget(), _expired_budget(),
        re.compile(r"nothing-matches-this"))
    coverage = result.coverage

    assert [t.base_address for t in coverage.pipe_name_budget_exhausted_targets] == [BASE]
    assert [t.base_address for t in coverage.c2_budget_exhausted_targets] == [BASE]


def test_the_unaccounted_limitation_reads_the_same_for_both_ledger_directions():
    """The code carries both directions, so its rendered text cannot claim
    the items were walked -- half of what it reports never was."""
    walked_past = pipe_facts.project_coverage_report(pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, unaccounted=2))
    never_in_scope = pipe_facts.project_coverage_report(pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, over_accounted=2))

    rendered = {render_limitation(_unaccounted_limitation(report))
                for report in (walked_past, never_in_scope)}
    assert rendered == {
        "2 item(s) the scan's own accounting cannot vouch for -- coverage cannot "
        "be confirmed for them"}


def test_an_attribute_form_tracker_construction_is_discoverable(tmp_path, monkeypatch):
    """`import ... as cov; cov.CoverageTracker()` is the same construction
    site spelled differently, and the registry above is only as strong as
    the scan that feeds it."""
    package = tmp_path / "dumpex" / "hunt" / "newhunter"
    package.mkdir(parents=True)
    (package / "scanner.py").write_text(
        "import dumpex.hunt._coverage as cov\n\n\n"
        "def scan(mf):\n    return cov.CoverageTracker()\n", encoding="utf-8")
    monkeypatch.setattr(pathlib.Path, "resolve", lambda self: tmp_path / "tests" / "hunt" / "x.py")

    assert _tracker_construction_sites() == Counter({"newhunter/scanner.py::scan": 1})


# ── The ledger survives its own projection ────────────────────────────────
#
# Each frozen snapshot copies the tracker's counters across one assignment
# at a time. A dropped assignment leaves both direction counts at zero --
# the only thing that can show it is the dispositions no longer adding up
# to the eligible count they were taken from.

def test_a_projection_that_drops_a_disposition_count_is_not_reconciled():
    for coverage in (LayerCoverage(scanned=1, eligible_total=5),
                     IocCoverage(scanned=1, eligible_total=5),
                     PipeScanCoverage(scanned=1, eligible_total=5),
                     cs_domain.ScanDiagnostics(segment_count=5, scanned=1, eligible_total=5)):
        assert (coverage.unaccounted, coverage.over_accounted) == (0, 0), type(coverage).__name__
        assert coverage.reconciled is False, type(coverage).__name__


def test_pipe_reports_an_unbalanced_ledger_as_partial_coverage():
    coverage = pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True, ledger_imbalance=2)

    assert coverage.region_scan_complete is False
    assert coverage.status == "partial"
    assert f"2 region(s) {UNBALANCED_LABEL}" in coverage.region_gap_reasons()
    report = pipe_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 2


def test_pipe_counts_a_recorded_gap_and_a_missing_count_together():
    """An imbalance beside a gap the scan DID record: the reasons keep the
    two apart, and the limitation reports every region without a
    trustworthy outcome rather than only the one the scan noticed."""
    coverage = pipe_domain.CoverageSnapshot(
        memory_info_stream=True, handle_data_stream=True,
        unaccounted=1, ledger_imbalance=2)

    assert coverage.unreconciled == 3
    assert coverage.region_gap_reasons() == (
        f"1 region(s) {UNACCOUNTED_LABEL}", f"2 region(s) {UNBALANCED_LABEL}")
    assert _unaccounted_limitation(
        pipe_facts.project_coverage_report(coverage)).affected_count == 3


def test_stomping_reports_an_unbalanced_ioc_ledger_as_partial_coverage():
    coverage = stomping_domain.CoverageSnapshot(
        memory_info_stream=True, module_list_stream=True, ref_dir_supplied=True,
        ioc_unaccounted=1, ioc_ledger_imbalance=2)

    assert coverage.ioc_complete is False
    assert coverage.ioc_unreconciled == 3
    assert coverage.ioc_gap_reasons() == (
        f"1 region(s) {UNACCOUNTED_LABEL}", f"2 region(s) {UNBALANCED_LABEL}")
    report = stomping_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 3


def test_encoding_reports_an_unbalanced_ledger_as_partial_coverage():
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=3, any_region_scanned=True,
        decode_imbalance=2)

    assert coverage.complete is False
    _dict, status, reasons = encoding_facts.project_coverage_v1(coverage)
    assert status == "partial"
    assert f"2 region(s) in the decode scan {UNBALANCED_LABEL}" in reasons
    report = encoding_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    limitation = _unaccounted_limitation(report)
    assert (limitation.scope, limitation.affected_count) == ("decode", 2)


def test_cs_beacon_reports_an_unbalanced_ledger_as_partial_coverage():
    scan = cs_domain.ScanDiagnostics(segment_count=5, scanned=1, eligible_total=5)
    coverage = cs_domain.CoverageSnapshot(scan=scan, mem_info_available=True)

    assert scan.ledger_imbalance == 4
    assert scan.scan_complete is False
    status, reasons = cs_facts.project_coverage_v1(coverage, has_hits=False,
                                                   any_corroborated=False)
    assert status == "partial"
    assert f"4 segment(s) {UNBALANCED_LABEL}" in reasons
    report = cs_facts.project_coverage_report(coverage)
    assert report.status == CoverageStatus.PARTIAL
    assert _unaccounted_limitation(report).affected_count == 4


# ── Zero-length items on the budget and truncation paths ──────────────────

def test_cs_beacon_budget_targets_never_name_a_zero_length_segment():
    """The budget slice turns every segment from the stopping point on into
    a ScanTarget. A zero-length segment cannot be one, so it is dropped
    before the walk rather than at each place the walk is sliced."""
    segments = [Segment(BASE, 0x1000, 0x2000), Segment(BASE + 0x10000, 0x3000, 0)]
    diagnostics = _cs_scan(segments, {BASE: b"\x00" * 0x2000},
                            _cs_config(max_total_scanned_bytes=0x1000))

    assert diagnostics.budget_exhausted is True
    assert diagnostics.budget_exhausted_targets, "the budget abandoned the walk"
    assert all(target.size > 0 for target in diagnostics.budget_exhausted_targets)
    assert diagnostics.segment_count == 2   # both, filter or no
    # The budget trips at the top of the iteration, before the segment is
    # taken into scope, so nothing was eligible and the ledger balances.
    assert diagnostics.eligible_total == 0
    assert diagnostics.reconciled is True


def test_yara_truncation_targets_never_name_a_zero_length_segment():
    yara = pytest.importorskip("yara")
    from dumpex.hunt.yara_hunt.scanner import scan_segments as yara_scan_segments
    from dumpex.hunt.yara_hunt.config import YaraConfig

    compiled = yara.compile(source='rule r { strings: $a = "zzzz" condition: $a }')
    segments = [Segment(BASE, 0x1000, 0x2000), Segment(BASE + 0x10000, 0x3000, 0)]

    class MF(FakeMF):
        pass
    MF.get_reader = lambda self: FakeReader({BASE: b"\x00" * 0x2000})

    outcome = yara_scan_segments(MF(), segments, [("r.yar", compiled)], modules=[], regions=[],
                                  modules_available=False, mem_info_available=False,
                                  config=YaraConfig(max_total_bytes_scanned=0x1000)).diagnostics
    targets = [target for name in ("skipped_oversize_targets", "read_failed_targets",
                                    "short_read_targets", "timed_out_targets",
                                    "match_failed_targets", "truncated_targets",
                                    "budget_exhausted_targets")
               for target in getattr(outcome, name)]
    assert targets, "the budget should have abandoned the remaining segment"
    assert all(target.size > 0 for target in targets)


# ── cs_beacon's own read-failure branch ───────────────────────────────────

class _RaisingReader:
    """A reader whose `read()` RAISES. FakeReader reports an unmapped VA by
    returning no bytes, which is the empty-read branch -- cs_beacon's
    `except Exception` path is reachable only through this."""

    def read(self, addr, size):
        raise OSError("simulated read failure")


def test_cs_beacon_read_that_raises_reconciles_as_a_read_failure():
    class MF(FakeMF):
        pass
    MF.get_reader = lambda self: _RaisingReader()
    _hits, diagnostics = scan_segments(MF(), [Segment(BASE, 0x400, 0x2000)], _cs_config(), [])

    assert diagnostics.read_failed == 1
    assert len(diagnostics.read_failed_targets) == 1
    assert diagnostics.scanned == 0
    _assert_reconciled(diagnostics, expect_total=1, note="cs_beacon read raises")


# ── Structural guards on the ledger's own contract ────────────────────────

def test_no_class_in_dumpex_defines_a_member_twice():
    """A member defined twice keeps only the last one, silently: the first
    copy stops being the code that runs, and nothing about the behaviour
    changes to say so."""
    root = pathlib.Path(__file__).resolve().parents[2] / "dumpex"
    duplicates = []
    for path in sorted(root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.ClassDef):
                continue
            names = Counter(child.name for child in node.body
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)))
            duplicates += [f"{path.name}::{node.name}.{name}"
                           for name, count in names.items() if count > 1]

    assert not duplicates, f"defined more than once, so only the last one runs: {duplicates}"


def test_no_shipped_scan_turns_on_strict_ledger_rejection():
    """`strict` turns an accounting bug into a raised exception, and the
    hunters run unguarded -- one raise costs every hunter's output, not
    just the coverage of the region that tripped it."""
    hunt_root = pathlib.Path(__file__).resolve().parents[2] / "dumpex" / "hunt"
    strict_sites = []
    for path in sorted(hunt_root.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "CoverageTracker":
                continue
            for keyword in node.keywords:
                if keyword.arg == "strict" and not (
                        isinstance(keyword.value, ast.Constant)
                        and keyword.value.value is False):
                    strict_sites.append(f"{path.name}:{node.lineno}")

    assert not strict_sites, (
        f"{strict_sites} build a CoverageTracker with strict rejection on -- a ledger "
        f"bug there aborts the whole hunt instead of degrading that hunter's coverage")


def test_pipe_reconciles_a_region_that_drives_both_the_name_and_c2_passes():
    """The C2 passes only run for a region that yielded a NEW pipe name, so
    a region has to produce one to reach them at all. It is still exactly
    one eligible item and exactly one `scanned` disposition, however much
    the two passes retain from it.

    The pattern is a str: `_iter_c2_matches` decodes each printable run
    before matching, so a bytes pattern cannot be applied to it.
    """
    region = _private_region(size=0x1000)
    data = rb"\pipe\demo-channel" + b"\x00" * 32 + b"http://example.test/gate" + b"\x00" * 64
    result = scan_pipe_names(_mf(captured=[_captured(size=0x1000)]), _fixed_reader(data),
                             [region], [], CoverageTracker(), _budget(), _budget(),
                             re.compile(r"https?://"))
    coverage = result.coverage

    assert result.string_leads, "the region has to yield a pipe name to reach the C2 passes"
    assert result.c2_regions, "the C2 passes never ran"
    assert (coverage.scanned, coverage.budget_skipped) == (1, 0)
    _assert_reconciled(coverage, expect_total=1, note="pipe name + C2")


# ── Every disposition survives every projection ───────────────────────────
#
# A disposition the tracker records and a snapshot does not carry is worse
# than a miscount: the snapshot reports a scan that reconciled perfectly as
# one whose books do not balance, which is the same false caveat this
# ledger exists to prevent, pointed the other way.

TRANSPORTS = {
    "LayerCoverage": lambda tracker: LayerCoverage.from_tracker(tracker),
    "IocCoverage": lambda tracker: IocCoverage.from_tracker(tracker),
    "PipeScanCoverage": lambda tracker: PipeScanCoverage.from_scan(
        tracker, _budget(), _budget()),
    "ScanDiagnostics": lambda tracker: cs_domain.ScanDiagnostics(
        segment_count=tracker.total, scanned=tracker.scanned,
        eligible_total=tracker.total, eligible_bytes=tracker.eligible_bytes,
        not_applicable=tracker.not_applicable, budget_skipped=tracker.budget_skipped,
        read_failed_targets=tuple(tracker.read_failed_targets),
        skipped_oversize_targets=tuple(tracker.skipped_oversize_targets),
        unaccounted=tracker.unaccounted, over_accounted=tracker.over_accounted),
}


@pytest.mark.parametrize("transport", sorted(TRANSPORTS))
def test_every_transport_carries_every_disposition_counter(transport):
    """The set is `CoverageTracker.DISPOSITION_COUNTERS`, read here rather
    than restated, so a tracker that gains a disposition fails until every
    snapshot carries it."""
    tracker = CoverageTracker()
    for index, name in enumerate(CoverageTracker.DISPOSITION_COUNTERS, start=1):
        tracker.note_eligible(size_bytes=index)
        if name == "read_failed":
            # ScanDiagnostics derives this count from its retained
            # targets, so the failure has to name what it failed on for
            # the two shapes to agree.
            tracker.note_read_failed(_failure_target())
        else:
            getattr(tracker, f"note_{name}")()
    tracker.note_eligible(size_bytes=99)
    tracker.note_skipped_oversize(_oversize_target())

    coverage = TRANSPORTS[transport](tracker)
    missing = [name for name in CoverageTracker.DISPOSITION_COUNTERS
               if not hasattr(coverage, name)]
    assert not missing, f"{transport} does not carry {missing}"

    carried = {name: getattr(coverage, name) for name in CoverageTracker.DISPOSITION_COUNTERS}
    assert carried == {name: 1 for name in CoverageTracker.DISPOSITION_COUNTERS}
    assert coverage.accounted == tracker.accounted == len(carried) + 1
    assert coverage.reconciled is True


@pytest.mark.parametrize("transport", sorted(TRANSPORTS))
def test_a_budget_skipped_region_still_reconciles_after_projection(transport):
    tracker = CoverageTracker()
    tracker.note_eligible()
    tracker.note_scanned()
    tracker.note_eligible()
    tracker.note_budget_skipped()

    coverage = TRANSPORTS[transport](tracker)
    assert coverage.budget_skipped == 1
    assert coverage.reconciled is True, (
        f"{transport} reports an unbalanced ledger for a scan that reconciled")


def test_encoding_reports_an_unbalanced_layer_alongside_a_layer_with_a_gap():
    """One layer's recorded gap does not account for another layer's
    missing count: the structured report carries an entry per layer, and
    a layer with both reports their sum."""
    coverage = encoding_domain.CoverageSnapshot(
        memory_info_stream=True, region_count=8, any_region_scanned=True,
        entropy_unaccounted=1, decode_imbalance=2, sleep_mask_unaccounted=1,
        sleep_mask_imbalance=3)

    report = encoding_facts.project_coverage_report(coverage)
    entries = [(lim.scope, lim.affected_count) for lim in report.limitations
               if lim.code == LimitationCode.SCAN_ITEMS_UNACCOUNTED]
    assert entries == [("sleep_mask", 4), ("entropy", 1), ("decode", 2)]

    _dict, _status, reasons = encoding_facts.project_coverage_v1(coverage)
    assert f"1 region(s) in the entropy scan {UNACCOUNTED_LABEL}" in reasons
    assert f"3 region(s) in the sleep_mask scan {UNBALANCED_LABEL}" in reasons
    assert f"2 region(s) in the decode scan {UNBALANCED_LABEL}" in reasons


def test_a_dump_of_only_zero_length_segments_still_counts_them_as_present():
    """`segment_count` is what the dump declares, so filtering unscannable
    segments out of the walk cannot flip this hunter to NOT_EVALUATED. The
    scan reconciles with nothing in scope."""
    segments = [Segment(BASE, 0x1000, 0), Segment(BASE + 0x10000, 0x2000, 0)]
    diagnostics = _cs_scan(segments, {})
    coverage = cs_domain.CoverageSnapshot(scan=diagnostics, mem_info_available=True)

    assert diagnostics.segment_count == 2
    assert diagnostics.eligible_total == 0
    assert coverage.evaluated is True
    assert diagnostics.scan_complete is True
