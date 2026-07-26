"""
Lightweight performance/resource-budget regression tests.

These aren't meant to be precise benchmarks (no dedicated hardware, no
statistical repeat runs) -- they exist to catch a REGRESSION in the
resource budgets each hunter enforces (CS Beacon's candidate/decoded-
byte/hit/deadline caps, Pipe's/Encoding's ScanBudget) turning back into
unbounded work against an adversarial or merely large input. Time
thresholds are set generously (seconds, not milliseconds) to avoid
flakiness on a slow CI runner while still catching an actual O(n) ->
O(n^2) regression or a budget that silently stopped being enforced.
"""
import time
import tracemalloc

from tests.fixtures.fakes import Region, Segment, FakeReader, FakeStream, FakeMF, mem_reader

import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.pipe as pipemod
import dumpex.hunt.encoding as encoding


# ── CS Beacon: mass duplicate candidate markers must not scale unbounded ──
# see P1 #7 (candidate/decoded-byte/hit/deadline budget) and P1 #8 (only
# decode the minimum necessary length per candidate, discard immediately,
# O(1) hit dedup via a set) -- both fixes exist specifically so a segment
# stuffed with decoy markers can't make this hunter run unbounded time or
# retain unbounded memory.

def _mass_duplicate_marker_segment(n_repeats=100_000):
    seg_va, seg_fo = 0x10000000, 0x1000000
    data = cs_beacon.CS_SIG_XOR69 * n_repeats   # ~100k candidate marker occurrences
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})
    return MF()


def test_cs_beacon_mass_duplicate_markers_completes_within_time_budget():
    start = time.perf_counter()
    f = cs_beacon._hunt_cs_beacon(_mass_duplicate_marker_segment(), verbose=False)
    elapsed = time.perf_counter() - start

    assert elapsed < 5.0, f"CS Beacon scan took {elapsed:.2f}s against ~100k decoy markers"
    assert f["coverage_status"] == "partial"
    assert any("budget" in r for r in f["coverage_reasons"])


def test_cs_beacon_mass_duplicate_markers_peak_memory_stays_bounded():
    tracemalloc.start()
    try:
        cs_beacon._hunt_cs_beacon(_mass_duplicate_marker_segment(), verbose=False)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # Each candidate decodes at most CS_CONFIG_DECODE_MAX (8 KB) and the
    # decoded bytes are discarded immediately after parsing (see P1 #8)
    # -- if a regression brought back retaining a large fixed-size
    # decoded chunk per candidate (the old behavior decoded and kept up
    # to 64 KB PER candidate), peak memory would scale with candidate
    # count (up to CS_MAX_CANDIDATES) instead of staying flat.
    assert peak < 50 * 1024 * 1024, f"peak traced memory {peak / 1024 / 1024:.1f} MB"


def test_cs_beacon_many_segments_completes_within_time_budget():
    n_segs = 30
    seg_size = 1 * 1024 * 1024   # 1 MB each, well under CS_MAX_SEG_SCAN
    # No beacon markers at all -- pure "scanned, nothing here" work. A
    # tiled non-trivial pattern (not all-zero) so `.find()` still has to
    # do real work rather than fast-pathing on a degenerate input.
    filler = bytes(range(256)) * ((seg_size // 256) + 1)
    segs = []
    read_map = {}
    for i in range(n_segs):
        va = 0x40000000 + i * 0x2000000
        segs.append(Segment(va, va, seg_size))
        read_map[va] = filler[:seg_size]
    regions = [Region(va, va, seg_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")
               for va in (s.start_virtual_address for s in segs)]

    class MF(FakeMF):
        memory_segments_64 = FakeStream(segs, "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader(read_map)

    start = time.perf_counter()
    f = cs_beacon._hunt_cs_beacon(MF(), verbose=False)
    elapsed = time.perf_counter() - start

    assert elapsed < 10.0, f"CS Beacon scan of {n_segs}x1MB segments took {elapsed:.2f}s"
    assert f["coverage_status"] == "complete"


# ── Pipe: many regions must not scale unbounded ────────────────────────

def test_pipe_many_regions_completes_within_time_budget():
    n = 2000
    region_size = 0x1000
    base = 0x50000000
    pipe_name = b"\\\\.\\pipe\\my_custom_ipc_channel"
    regions = []
    read_map = {}
    for i in range(n):
        va = base + i * 0x10000
        regions.append(Region(va, va, region_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"))
        data = bytearray(region_size)
        if i % 250 == 0:
            data[0x10: 0x10 + len(pipe_name)] = pipe_name
        read_map[va] = bytes(data)

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream([], "infos")
        handles        = FakeStream([], "handles")
    pipemod.read_region = mem_reader(read_map)

    start = time.perf_counter()
    f = pipemod._hunt_pipe(MF(), verbose=False)
    elapsed = time.perf_counter() - start

    assert elapsed < 10.0, f"Pipe scan of {n} regions took {elapsed:.2f}s"
    assert f["coverage_status"] == "complete"


# ── Encoding: many regions across all three layers must not scale ──────
# unbounded

def test_encoding_many_regions_completes_within_time_budget():
    n = 250
    region_size = 0x2000
    base = 0x60000000
    # Pseudo-random-looking, non-repeating-within-a-region bytes --
    # plausible input for the entropy/decode layers to actually spend
    # work on, not a trivial all-zero region every layer's own filters
    # would fast-path. Built once and sliced per region for speed.
    import os
    filler_pool = os.urandom(region_size + n)
    regions = []
    read_map = {}
    for i in range(n):
        va = base + i * 0x10000
        regions.append(Region(va, va, region_size, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"))
        read_map[va] = filler_pool[i:i + region_size]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader(read_map)

    start = time.perf_counter()
    f = encoding._hunt_encoding(MF(), verbose=False)
    elapsed = time.perf_counter() - start

    # Generous threshold: coverage instrumentation (pytest --cov, which CI
    # always runs with) roughly doubles wall time for this scan compared
    # to an uninstrumented run.
    assert elapsed < 20.0, f"Encoding scan of {n} regions took {elapsed:.2f}s"
    assert f["coverage_status"] == "complete"
