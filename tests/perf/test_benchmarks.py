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
import struct
import time
import tracemalloc

from tests.fixtures.fakes import (Region, Segment, FakeReader, FakeStream, FakeMF, mem_reader,
                                   build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ)

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


# ── XOR structural scan: a single, MAXIMALLY candidate-heavy region must ──
# still complete quickly -- see dumpex issue #27's own acceptance criteria
# ("Performance benchmarks cover worst-case candidate-heavy regions").
# _scan_xor_structural's derivation generators (decoding.py's
# _xor_derive_pe_candidates/_xor_derive_shellcode_candidates) walk the
# WHOLE region in a single offset-ordered pass with no per-region
# candidate-count cap (an earlier, removed cap turned out to be capable of
# silently starving a genuine candidate -- see
# tests/hunt/test_encoding_decoders.py's own regression test for that) --
# so the only thing standing between a region packed with pre-filter-
# passing decoys and unbounded work is the shared ScanBudget's
# note_attempt() gate. This packs a full XOR_SCAN_MAX-sized (512 KB)
# region almost entirely with decoys that pass the cheap MZ+e_lfanew+
# PE\0\0 pre-filter but fail full structural validation (so EVERY one of
# them reaches, and spends, a real decode+parse_pe_header attempt) to
# exercise that path at its worst plausible case.

def _decoy_pe_bytes(salt: int):
    """A structurally INVALID PE that still passes the cheap MZ+e_lfanew+
    PE\\0\\0 pre-filter (correct signature, corrupted Machine field) --
    the maximally expensive kind of non-candidate, since it always
    reaches a full decode + parse_pe_header call before being rejected.
    `salt` is stamped into the trailing padding (unused by both the
    pre-filter and parse_pe_header's early Machine-field rejection) so
    each decoy's PLAINTEXT is distinct -- defeating ScanBudget's own
    content dedup, which would otherwise let every decoy past the first
    skip straight to a cheap hash-dedup instead of genuinely re-running
    _classify_decoded/parse_pe_header, understating the worst case."""
    decoy = bytearray(build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300))
    struct.pack_into('<H', decoy, 0x80 + 4, 0xDEAD)   # coff Machine field -> unrecognized
    struct.pack_into('<I', decoy, len(decoy) - 4, salt)
    return bytes(decoy)


def test_xor_structural_candidate_heavy_region_completes_within_time_budget():
    region_base = 0x680000000
    decoy_len = len(_decoy_pe_bytes(0))

    real_pe = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)

    region_size = 512 * 1024   # == XOR_SCAN_MAX -- the largest region this layer scans
    budget_room = region_size - len(real_pe)
    n_decoys = budget_room // decoy_len

    chunks = []
    for i in range(n_decoys):
        key = (i % 254) + 1   # cycle through keys 1..254, never 0
        chunks.append(bytes(b ^ key for b in _decoy_pe_bytes(i)))
    data = b''.join(chunks)
    data += bytes(b ^ 0xFE for b in real_pe)   # one genuine PE, past every decoy
    data = data.ljust(region_size, b'\x00')

    regions = [Region(region_base, region_base, len(data), "MEM_COMMIT",
                       "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    encoding.read_region = mem_reader({region_base: data})

    start = time.perf_counter()
    f = encoding._hunt_encoding(MF(), verbose=False)
    elapsed = time.perf_counter() - start

    assert elapsed < 20.0, (f"XOR structural scan of a {region_size // 1024}KB "
                             f"candidate-heavy region ({n_decoys} decoys) took {elapsed:.2f}s")
    # Whether the real PE is reached depends on the shared attempt budget
    # (2000, whole-hunt) vs. how many decoys preceded it here -- either
    # outcome is fine for a PERFORMANCE test, but if the budget WAS
    # exhausted that must be visible, never a silent clean/complete miss.
    if f["score"] == 0:
        assert f["coverage_status"] == "partial"


# ── --handles: the type summary must stay linear in distinct type names ──
# MAX_HANDLE_DESCRIPTORS (65,536) is a frozen budget, and every descriptor
# may carry its own type name, so summarize_handles_by_type() is handed up
# to 65,536 distinct buckets. A per-bucket uniqueness scan over the labels
# already assigned (the shape the first collision fix used) is quadratic:
# ~0.3s at 8k names, and minutes at the real cap. collect + render each
# call it once, so the cost is paid twice per invocation.

def test_handle_type_summary_stays_linear_at_the_descriptor_cap():
    from dumpex.commands.handles import summarize_handles_by_type
    from dumpex.core.memory import MAX_HANDLE_DESCRIPTORS
    from dumpex.output.records import HandleRecord

    records = [
        HandleRecord(handle=f"0x{i:016x}", type_name=f"Type{i}", type_name_status="ok",
                      object_name=None, object_name_status="unnamed", attributes=0,
                      granted_access=1, handle_count=1, pointer_count=1)
        for i in range(MAX_HANDLE_DESCRIPTORS)
    ]

    start = time.perf_counter()
    summary = summarize_handles_by_type(records)
    elapsed = time.perf_counter() - start

    assert len(summary) == MAX_HANDLE_DESCRIPTORS
    # Generous by two orders of magnitude against the linear timing, but
    # far under the quadratic one (which does not finish in minutes here).
    assert elapsed < 5.0, (
        f"summarizing {MAX_HANDLE_DESCRIPTORS} distinct handle type names took "
        f"{elapsed:.2f}s -- the per-bucket label scan is back")


# ── Targeted rescan: the largest range the CLI accepts stays bounded ──────
# `--hunt-addr` lets an analyst name a range the full-scope walk refused as
# oversized, so the request ceiling in the analyzer registry is the only size
# bound left. Obfuscation carries the lowest ceiling (32 MiB) precisely because
# its sleep-mask and decode layers retain buffers, so a rescan at exactly that
# ceiling is the worst case for both time and retained memory. The input is a
# mostly-empty range with high-entropy sub-ranges: the shape that makes the
# window pass do real work while the whole-range statistic stays low.

_TARGETED_BASE = 0x30000000


def _ceiling(identity):
    from dumpex.hunt import _registry
    return _registry.REGISTRY.get(identity).targeted_capability.request_ceiling


def _mostly_empty_with_entropy_islands(size, island_size=1 << 20, islands=4):
    """Deterministic synthetic bytes: zeros with `islands` high-entropy runs
    spaced evenly through the range. Seeded, so the same buffer every run."""
    import random
    data = bytearray(size)
    rng = random.Random(0xDEC0DE)
    stride = size // islands
    for i in range(islands):
        start = i * stride
        data[start:start + island_size] = rng.randbytes(island_size)
    return bytes(data)


def _run_targeted_obfuscation(monkeypatch, size, payload):
    import dumpex.hunt.encoding.targeted as encoding_targeted
    from dumpex.core.va_range import VirtualRange
    from dumpex.hunt._execution import build_execution_context
    from dumpex.hunt._request import HuntRequest

    region = Region(_TARGETED_BASE, _TARGETED_BASE, size, "MEM_COMMIT",
                    "PAGE_READWRITE", "MEM_PRIVATE")
    segment = Segment(_TARGETED_BASE, 0x1000, size)

    class MF(FakeMF):
        memory_info = FakeStream([region], "infos")
        memory_segments_64 = FakeStream([segment], "memory_segments")
        modules = FakeStream([], "modules")

    reads = []

    def _read(mf, addr, length):
        reads.append((addr, length))
        offset = addr - _TARGETED_BASE
        return payload[offset:offset + length]

    monkeypatch.setattr(encoding_targeted, "read_region_spanning", _read)
    request = HuntRequest.targeted("obfuscation", "encoding_scan",
                                    VirtualRange(_TARGETED_BASE, size))
    ctx = build_execution_context(MF(), request)
    return encoding_targeted.run_targeted_encoding(ctx), reads




def _measurements(closure):
    """Every measurement on one closure, grouped by name -- `entropy_top_window`
    is repeated once per retained window, so a plain dict would lose the count
    this test is about."""
    grouped = {}
    for m in closure.measurements:
        grouped.setdefault(m.name, []).append(m)
    return grouped


def test_targeted_obfuscation_at_the_request_ceiling_stays_bounded_in_time_and_retention(
        monkeypatch):
    """One rescan at exactly the largest range the CLI accepts: the window pass
    is deterministic in the range's own size, every layer's spend stays inside
    its frozen limit, and what the result retains is capped independently of how
    much of the range is high-entropy."""
    size = _ceiling("obfuscation")
    payload = _mostly_empty_with_entropy_islands(size, island_size=1 << 20, islands=8)

    start = time.perf_counter()
    result, _reads = _run_targeted_obfuscation(monkeypatch, size, payload)
    elapsed = time.perf_counter() - start

    assert [c.scope for c in result.closures] == ["sleep_mask", "entropy", "decode"]
    # Generous against the real cost while still catching a budget that stopped
    # being enforced at the largest range the CLI will accept.
    assert elapsed < 120.0, (
        f"a {size >> 20} MiB targeted obfuscation rescan took {elapsed:.1f}s -- "
        f"a retained-bytes, attempt, or window budget is no longer bounding it")

    entropy = _measurements(next(c for c in result.closures if c.scope == "entropy"))
    window_size = entropy["entropy_window_size"][0].value
    total = entropy["entropy_windows_total"][0].value
    # Deterministic in the requested size alone -- never in how much of the
    # range happens to be above the threshold.
    assert total == size // window_size
    assert entropy["entropy_windows_evaluated"][0].value == total
    above = entropy["entropy_windows_above_threshold"][0].value
    retained = entropy["entropy_ranges_retained"][0].value
    assert above > 0, "the synthetic islands must exercise the above-threshold path"
    assert retained <= above
    # Retention is capped, not proportional: thousands of qualifying windows
    # still reach the result as a handful of retained ones.
    assert len(entropy["entropy_top_window"]) == retained
    assert retained <= 16, f"{retained} entropy windows retained at the request ceiling"

    for closure in result.closures:
        grouped = _measurements(closure)
        if "budget_attempts_limit" not in grouped:
            continue
        for spend, limit in (("budget_attempts", "budget_attempts_limit"),
                              ("budget_decoded_bytes", "budget_decoded_bytes_limit"),
                              ("budget_retained_bytes", "budget_retained_bytes_limit"),
                              ("budget_hits", "budget_hits_limit")):
            assert grouped[f"{spend}_spent"][0].value <= grouped[limit][0].value, (
                f"{closure.scope}: {spend} exceeded its own frozen limit")


def test_targeted_obfuscation_reads_the_requested_range_once(monkeypatch):
    """Every layer, and the entropy window pass inside one of them, works from
    the one captured buffer: a rescan costs one read of the requested range, not
    one per layer or one per window."""
    size = 4 << 20
    payload = _mostly_empty_with_entropy_islands(size, island_size=1 << 19, islands=2)

    _result, reads = _run_targeted_obfuscation(monkeypatch, size, payload)

    assert len(reads) == 1, f"the requested range was read {len(reads)} times"
    assert reads[0] == (_TARGETED_BASE, size)
