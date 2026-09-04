"""Regression coverage for the evaluation prototype in
scripts/evaluate_entropy_page_local_pass.py.

The prototype is not shipped -- it is not imported by
`dumpex.hunt.encoding`, and nothing here exercises production code paths.
These tests pin the CONTRACT the evaluation's own measurements rely on: a
fixed input and page budget always produce the same retained observations,
a whole-region hit gates out page-local work on that region, an exhausted
budget still accounts for every eligible page it never reached, and
retention is bounded during the scan rather than after it. See
docs/developer/hunt_entropy_full_scope_page_pass_evaluation.md.
"""
import contextlib
import io
import json
import random
import time

from scripts.evaluate_entropy_page_local_pass import (
    ENTROPY_EVIDENCE_LIMIT, POLICIES, _Region, _TopN, _open_dump_redacted,
    _print_result, benign_noise_fixtures, record_delta, record_growth_bytes,
    retention_bias_fixture, run_page_local_pass, sparse_blind_spot_fixture,
    stress_fixture,
)

from dumpex.hunt.encoding.config import EncodingConfig, ENTROPY_RWX_THRESHOLD
from dumpex.hunt.encoding.entropy import _shannon_entropy
from dumpex.hunt.encoding.models import RegionRef
from dumpex.hunt.encoding.report_facts import _entropy_item_fact

_SUSP_PROTS = ("PAGE_EXECUTE_READWRITE",)
_GENEROUS = dict(max_pages=1_000_000, max_bytes=1024 * 1024 * 1024, deadline_seconds=30.0)

# Pause injected into the harness's own instrumentation to prove it is
# timed separately from the scan. The tolerance is below the pause so a
# coarse platform sleep clock (Windows' ~15.6 ms timer granularity) cannot
# make a correct implementation look wrong.
_INJECTED_PAUSE = 0.25
_PAUSE_TOLERANCE = 0.2


def _benign(label):
    return dict((name, (r, m, reader))
                for name, r, m, reader, _calibrates in benign_noise_fixtures())[label]


def test_sparse_blind_spot_is_found_under_both_policies():
    """A bounded high-entropy page inside a sparse allocation, invisible
    to the whole-region average, is
    localized by the page-local pass regardless of eligibility policy."""
    regions, modules, reader = sparse_blind_spot_fixture()
    config = EncodingConfig()
    for policy in POLICIES:
        result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                     config, policy, **_GENEROUS)
        assert result.pages_above_threshold == 1
        assert result.exhaustive
        assert result.retained_observations[0].entropy >= ENTROPY_RWX_THRESHOLD
        assert result.retained_observations[0].base_address == 0x10000000 + 0x100000


def test_whole_region_hit_gates_out_the_page_pass():
    """A region whose whole-region average already reaches its threshold
    is never windowed -- the same mutual-exclusivity rule
    `scan_entropy_targeted` applies, so an already-flagged region cannot
    also contribute page-local noise."""
    regions, modules, reader = _benign("already_flagged_whole_region")
    config = EncodingConfig()
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 config, "all_eligible", **_GENEROUS)
    assert result.regions_gated_by_whole_region_hit == 1
    assert result.pages_examined == 0
    assert result.retained_observations == ()


def test_rwx_only_policy_excludes_non_rwx_regions():
    regions, modules, reader = _benign("periodic_block_structured")   # PAGE_READWRITE
    config = EncodingConfig()
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 config, "rwx_only", **_GENEROUS)
    assert result.regions_in_scope == 0
    assert result.pages_examined == 0


def test_only_above_threshold_windows_are_retained():
    """Retention is evidence, not a sample: a benign region whose every
    window measures below its own threshold retains nothing at all, and
    contributes nothing to structured output. `highest_window` still
    reports what the pass measured, so "measured 768 windows, highest
    6.18" stays distinguishable from "did not measure"."""
    regions, modules, reader = _benign("uniform_alphabet_tiling")
    config = EncodingConfig()
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 config, "rwx_only", **_GENEROUS)
    assert result.pages_examined > 0
    assert result.pages_above_threshold == 0
    assert result.retained_observations == ()
    assert result.details_entropy_json_bytes == 0
    assert result.facts_json_bytes == 0
    assert result.record_growth_bytes == 0
    assert result.highest_window is not None
    assert result.highest_window.entropy < ENTROPY_RWX_THRESHOLD


def test_exhausted_budget_still_accounts_for_every_eligible_page():
    """A spent budget stops window measurement, not the region walk: the
    pages it never reached stay counted, so "how much was left
    unevaluated" is answerable. Without this, a coverage limitation built
    on these numbers would understate the gap by every region the walk
    never got to."""
    regions, modules, reader = stress_fixture()
    config = EncodingConfig()
    tight = dict(max_pages=50, max_bytes=16 * 1024 * 1024, deadline_seconds=30.0)
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 config, "rwx_only", **tight)

    assert result.eligible_pages_in_scope == 24_576   # 12 regions x 8 MiB / 4 KiB
    assert result.pages_examined == 50
    assert result.pages_missed == 24_526
    assert not result.exhaustive
    # One region cut off mid-way, the other eleven never measured at all --
    # two different states a coverage report must not conflate.
    assert result.regions_partially_examined == 1
    assert result.regions_unexamined == 11


def test_page_budget_retention_is_deterministic():
    """Under the page/byte budgets the run is fully deterministic: the
    same input stops at the same window and retains the same set. (The
    wall-clock deadline deliberately is not covered here -- it stops
    wherever the machine happened to be, so it guarantees only a
    deterministic PREFIX of the same page order, not a fixed length.)"""
    regions, modules, reader = stress_fixture()
    config = EncodingConfig()
    tight = dict(max_pages=50, max_bytes=16 * 1024 * 1024, deadline_seconds=30.0)
    for policy in POLICIES:
        first = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                    config, policy, **tight)
        second = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                     config, policy, **tight)
        assert not first.stopped_on_time and not second.stopped_on_time
        assert first.retained_observations == second.retained_observations
        assert first.pages_examined == second.pages_examined == 50


def test_regions_with_nothing_to_window_do_not_count_against_exhaustive():
    """A region that was reached but had nothing to contribute (too little
    data, or a whole-region hit that gates it out) is a complete,
    accounted-for disposition -- it must not make an otherwise generous
    budget read as incomplete."""
    sparse_regions, sparse_modules, sparse_reader = sparse_blind_spot_fixture()
    flagged_regions, flagged_modules, flagged_reader = _benign("already_flagged_whole_region")

    regions = sparse_regions + flagged_regions
    modules = sparse_modules + flagged_modules
    boundary = flagged_regions[0].BaseAddress

    def reader(mf, addr, size):
        return flagged_reader(mf, addr, size) if addr >= boundary else sparse_reader(mf, addr, size)

    config = EncodingConfig()
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 config, "all_eligible", **_GENEROUS)
    assert result.regions_gated_by_whole_region_hit == 1
    assert result.pages_above_threshold == 1
    assert result.pages_missed == 0
    assert result.exhaustive


def test_retention_is_bounded_during_the_scan_not_after_it():
    """`_TopN` never holds more than `n` entries at any point. Asserting
    only the FINAL length would pass just as happily on an implementation
    that accumulated every measured window and truncated at the end --
    which is exactly what a bounded-retention design must not do."""
    ref = RegionRef(base_address=0x1000, allocation_base=0x1000, size=8 * 1024 * 1024,
                    state="MEM_COMMIT", protect="PAGE_EXECUTE_READWRITE",
                    type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(4)
    for i in range(1000):
        top.offer(entropy=(i % 97) / 12.0, base_address=0x1000 * i, size=4096,
                  ref=ref, threshold=6.5)
        assert len(top) <= 4

    ordered = top.ordered()
    assert len(ordered) == 4
    # Descending entropy, ascending address on ties -- the ordering
    # `scan_entropy_windows` already uses.
    assert [o.entropy for o in ordered] == sorted((o.entropy for o in ordered), reverse=True)


def test_output_size_is_measured_with_the_current_window_projector():
    """The output-size measurement has to model what `--json` actually
    emits for a page-local observation: `report_record._entropy_hit_dict`
    adds a `window` sub-object (base address + size) for a bounded value,
    and the fact string gains `window_size=`. Measuring with the legacy
    `report_legacy` projector instead -- which predates the `window` key --
    understates a page observation by roughly a third."""
    from dumpex.hunt.encoding.report_legacy import _entropy_hit_dict as legacy_dict
    from dumpex.hunt.encoding.report_record import _entropy_hit_dict as current_dict

    ref = RegionRef(base_address=0x10000000, allocation_base=0x10000000,
                    size=4 * 1024 * 1024, state="MEM_COMMIT",
                    protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(1)
    top.offer(entropy=7.95, base_address=0x10100000, size=4096, ref=ref, threshold=6.5)
    details_bytes, facts_bytes = top.output_bytes()

    hit = top.hits()[0]
    assert "window" in current_dict(hit)
    assert "window" not in legacy_dict(hit)
    assert details_bytes > len(json.dumps([legacy_dict(hit)], separators=(",", ":")))
    assert "window_size=4096" in json.loads(json.dumps([_entropy_item_fact(hit, None)]))[0]
    assert facts_bytes > 0


def test_fact_strings_stop_at_the_shipped_evidence_limit():
    """`obfuscation.entropy_observation` renders at most
    `ENTROPY_EVIDENCE_LIMIT` per-item facts plus one "... and N more"
    line, so facts do NOT grow one-per-observation past that cap -- an
    output-size estimate that assumed they did would overstate the cost of
    a large retained set."""
    ref = RegionRef(base_address=0x20000000, allocation_base=0x20000000,
                    size=8 * 1024 * 1024, state="MEM_COMMIT",
                    protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    at_limit = _TopN(ENTROPY_EVIDENCE_LIMIT)
    over_limit = _TopN(ENTROPY_EVIDENCE_LIMIT * 4)
    for index in range(ENTROPY_EVIDENCE_LIMIT * 4):
        for sink in (at_limit, over_limit):
            sink.offer(entropy=7.0 + index / 1000, base_address=0x20000000 + index * 4096,
                       size=4096, ref=ref, threshold=6.5)

    at_details, at_facts = at_limit.output_bytes()
    over_details, over_facts = over_limit.output_bytes()

    assert len(over_limit.ordered()) == ENTROPY_EVIDENCE_LIMIT * 4
    assert over_details > at_details * 3          # details grows per observation
    assert over_facts < at_facts * 2              # facts does not


def test_record_growth_counts_the_whole_finding_not_only_the_arrays():
    """The first observation materializes an entire
    `obfuscation.entropy_observation` finding -- inference, rationale,
    limitations and all -- on top of its `details.entropy` entry and fact
    string. An output-size figure built from the two arrays alone
    understates what `--json` actually grows by, several times over for a
    small retained set."""
    ref = RegionRef(base_address=0x10000000, allocation_base=0x10000000,
                    size=4 * 1024 * 1024, state="MEM_COMMIT",
                    protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(8)
    top.offer(entropy=7.95, base_address=0x10100000, size=4096, ref=ref, threshold=6.5)
    details_bytes, facts_bytes = top.output_bytes()

    whole_record = record_growth_bytes(top.hits())
    assert whole_record > (details_bytes + facts_bytes) * 2

    # The finding is a one-time cost; further observations add only their
    # own array entries, so growth is sub-linear in the observation count.
    top.offer(entropy=7.94, base_address=0x10200000, size=4096, ref=ref, threshold=6.5)
    assert record_growth_bytes(top.hits()) - whole_record < whole_record


def test_exactly_maximal_entropy_lands_in_the_top_band():
    """A page holding all 256 byte values in equal proportion measures
    EXACTLY 8.0. The top band is closed, so such a page is counted there
    rather than falling through an implicit overflow bucket the band
    labels would then misreport as `<8.0`.

    The region is mostly zero so its whole-region average stays under the
    threshold; otherwise the gate skips it and the binning code never runs
    at all. The rendered label is pinned separately by
    `test_band_labels_mark_the_top_band_as_closed`."""
    base = 0x40000000
    size = 256 * 1024                       # 64 pages, 63 of them zero
    maximal_page = bytes(range(256)) * 16   # exactly 4096 bytes, every value 16x
    body = bytearray(size)
    body[0x8000:0x8000 + 4096] = maximal_page
    data = bytes(body)

    def reader(mf, addr, length):
        offset = addr - base
        return data[offset:offset + length]

    regions = [_Region(base, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    config = EncodingConfig()
    result = run_page_local_pass(regions, [], None, _SUSP_PROTS, reader,
                                 config, "rwx_only", **_GENEROUS)

    # The gate let it through, so the binning code actually ran.
    assert result.regions_gated_by_whole_region_hit == 0
    assert result.pages_examined == 64

    assert _shannon_entropy(maximal_page) == 8.0
    assert result.highest_window.entropy == 8.0

    bands = dict(result.band_counts)
    assert bands[8.0] == 1              # the maximal page, in the CLOSED top band
    assert bands[4.0] == 63             # the zero pages
    assert sum(bands.values()) == 64    # nothing fell through an overflow bucket


def test_band_labels_mark_the_top_band_as_closed():
    """The printed distribution has to say `<=8.0` for the closed top band:
    an exactly-maximal page rendered under a `<8.0` label is a wrong
    statement about the most interesting window in the scan."""
    base = 0x41000000
    size = 64 * 1024
    body = bytearray(size)
    body[0x4000:0x4000 + 4096] = bytes(range(256)) * 16
    data = bytes(body)

    regions = [_Region(base, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]
    result = run_page_local_pass(regions, [], None, _SUSP_PROTS,
                                 lambda mf, addr, n: data[addr - base:addr - base + n],
                                 EncodingConfig(), "rwx_only", **_GENEROUS)

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        _print_result("maximal", result)
    bands_line = next(line for line in buffer.getvalue().splitlines()
                      if "entropy_bands" in line)
    assert "<=8.0:1" in bands_line
    assert "<8.0" not in bands_line


def test_top_n_keeps_the_highest_entropy_windows():
    """The bounded set is the TOP n, not merely the first n offered."""
    ref = RegionRef(base_address=0x2000, allocation_base=0x2000, size=4 * 1024 * 1024,
                    state="MEM_COMMIT", protect="PAGE_EXECUTE_READWRITE",
                    type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(3)
    for entropy in (1.0, 7.9, 2.0, 6.6, 3.0, 8.0):
        top.offer(entropy=entropy, base_address=0x2000 + int(entropy * 10),
                  size=4096, ref=ref, threshold=6.5)
    assert [o.entropy for o in top.ordered()] == [8.0, 7.9, 6.6]


def test_corpus_mode_never_prints_a_sample_path_on_failure(tmp_path, capsys):
    """`--corpus` promises output quotable in a public record. A dump path
    can itself name a customer, case, host, or analyst -- and
    `dumpex.core.memory.open_dump` prints the path it was given on BOTH of
    its failure paths before exiting. Neither may reach stdout here."""
    sensitive = tmp_path / "SensitiveClient" / "Case-157"
    sensitive.mkdir(parents=True)

    missing = sensitive / "missing.dmp"
    assert _open_dump_redacted(missing, "sample A") is None
    out = capsys.readouterr().out
    assert "sample A" in out
    assert "SensitiveClient" not in out and "Case-157" not in out and "missing.dmp" not in out

    unparseable = sensitive / "not_a_dump.dmp"
    unparseable.write_bytes(b"definitely not a minidump")
    assert _open_dump_redacted(unparseable, "sample B") is None
    out = capsys.readouterr().out
    assert "sample B" in out
    assert "SensitiveClient" not in out and "Case-157" not in out and "not_a_dump.dmp" not in out


def test_record_growth_handles_observations_spanning_several_small_regions():
    """The retained set is global: its observations routinely come from
    different regions, each with its own base, size, protection, and
    threshold. Measuring growth by synthesizing N observations inside the
    first hit's region instead loses all of that -- and, once the regions
    are smaller than the synthesized stride, fabricates addresses past the
    first region's end, which `Location` rejects outright:

        ValueError: Location: va=0x... is at/beyond region end 0x...
    """
    base = 0x50000000
    region_size = 8 * 1024          # two pages: smaller than the retained count
    payload = {}
    regions = []
    for index in range(3):
        region_base = base + index * 0x100000
        body = bytearray(region_size)
        body[0:4096] = random.Random(index).randbytes(4096)
        payload[region_base] = bytes(body)
        regions.append(_Region(region_base, region_size, "MEM_COMMIT",
                               "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"))

    def reader(mf, addr, length):
        for region_base, data in payload.items():
            if region_base <= addr < region_base + len(data):
                offset = addr - region_base
                return data[offset:offset + length]
        return b"\x00" * length

    result = run_page_local_pass(regions, [], None, _SUSP_PROTS, reader,
                                 EncodingConfig(), "rwx_only", **_GENEROUS)

    assert result.pages_above_threshold == 3
    assert len({o.base_address for o in result.retained_observations}) == 3
    assert result.record_growth_bytes > 0


def _one_rwx_region(size=8 * 1024, base=0x60000000):
    return [_Region(base, size, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]


def test_a_region_that_could_not_be_read_is_not_a_complete_scan():
    """A region in scope whose read RAISED delivered no bytes at all. How
    many pages it held is unknown, not zero -- reporting `pages_missed == 0`
    and `exhaustive` for it would turn an unanswered question about memory
    in scope into a clean negative."""
    def boom(mf, addr, size):
        raise OSError("unreadable")

    result = run_page_local_pass(_one_rwx_region(), [], None, _SUSP_PROTS, boom,
                                 EncodingConfig(), "rwx_only", **_GENEROUS)
    assert result.regions_in_scope == 1
    assert result.read_failed_regions == 1
    assert result.pages_missed == 0          # it contributed no measurable pages
    assert not result.exhaustive


def test_a_region_that_read_back_empty_is_not_a_complete_scan():
    """`b""` is a failed read, not a short one: there is no prefix to
    measure, so the same unknown-scope rule applies."""
    result = run_page_local_pass(_one_rwx_region(), [], None, _SUSP_PROTS,
                                 lambda mf, addr, size: b"",
                                 EncodingConfig(), "rwx_only", **_GENEROUS)
    assert result.read_failed_regions == 1
    assert result.pages_examined == 0
    assert not result.exhaustive


def test_a_short_read_leaves_the_unread_tail_counted_and_incomplete():
    """Half a region arrived. The pages of the half that did not are
    outside `eligible_pages_in_scope` -- which is derived from the bytes in
    hand -- so completeness has to be decided on the missing BYTES, or the
    unread tail silently becomes a clean negative."""
    declared = 8 * 1024
    delivered = 4 * 1024
    result = run_page_local_pass(_one_rwx_region(size=declared), [], None, _SUSP_PROTS,
                                 lambda mf, addr, size: b"\x41" * delivered,
                                 EncodingConfig(), "rwx_only", **_GENEROUS)
    assert result.short_read_regions == 1
    assert result.short_read_unexamined_bytes == declared - delivered
    assert result.pages_missed == 0          # every page IT HAD was measured
    assert not result.exhaustive             # but the region was not delivered in full


def test_scan_timing_excludes_the_harness_own_measurement_cost(monkeypatch):
    """`record_delta()` builds and serializes two whole `HunterRecord`s --
    work no scan performs. Charging it to
    `elapsed_seconds` would inflate the candidate pass's measured cost, and
    `duration_delta_vs_production` with it, purely because of how the
    harness instruments itself."""
    import scripts.evaluate_entropy_page_local_pass as harness

    real = harness.record_delta

    def slow(observations):
        time.sleep(_INJECTED_PAUSE)
        return real(observations)

    monkeypatch.setattr(harness, "record_delta", slow)
    regions, modules, reader = sparse_blind_spot_fixture()

    started = time.perf_counter()
    result = harness.run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                         EncodingConfig(), "rwx_only", **_GENEROUS)
    total = time.perf_counter() - started

    # Relational, not absolute: the injected pause must land OUTSIDE the
    # reported scan time, whatever the scan itself costs on this machine.
    # Asserting `elapsed_seconds < PAUSE` instead would be a bet on the
    # host being fast enough to window 1024 pages in under a quarter
    # second -- true here, false on a loaded CI runner, and never what
    # this test is about.
    assert result.instrumentation_seconds >= _PAUSE_TOLERANCE
    assert total - result.elapsed_seconds >= _PAUSE_TOLERANCE
    assert result.window_seconds <= result.elapsed_seconds


def test_a_region_over_the_size_cap_is_not_a_complete_scan():
    """A region past `ENTROPY_SCAN_MAX` passed every eligibility filter and
    then went unexamined. Dropping it before any counter would report a
    clean page-level negative over memory nobody looked at -- the same
    shape as an unread region, one filter earlier. Production
    `_scan_entropy` records the same region as an explicit oversize skip."""
    config = EncodingConfig()
    oversized = config.entropy_scan_max + 1
    regions = [_Region(0x70000000, oversized, "MEM_COMMIT",
                       "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    result = run_page_local_pass(regions, [], None, _SUSP_PROTS,
                                 lambda mf, addr, size: b"\x00" * size,
                                 config, "rwx_only", **_GENEROUS)

    assert result.oversized_regions == 1
    assert result.oversized_bytes == oversized
    assert result.pages_missed == 0          # it contributed no measurable pages
    assert not result.exhaustive             # and must not read as complete


def test_flat_global_retention_drops_whole_regions_a_per_region_floor_keeps():
    """A global top-N is deterministic but not unbiased: one loud region
    can fill every slot and evict every observation from every other
    region. The count survives -- `pages_above_threshold` still says 65 --
    but the ADDRESSES, which are what an investigator extracts, are gone
    for a whole region. A per-region reservation under the same global cap
    keeps them."""
    regions, modules, reader, quiet_base = retention_bias_fixture()

    flat = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                               EncodingConfig(), "rwx_only", top_n=64,
                               per_region_top_n=0, **_GENEROUS)
    floored = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                  EncodingConfig(), "rwx_only", top_n=64,
                                  per_region_top_n=5, **_GENEROUS)

    # Same pages cleared the threshold under both policies.
    assert flat.pages_above_threshold == floored.pages_above_threshold == 65
    assert len(flat.retained_observations) == len(floored.retained_observations) == 64

    # The divergence is entirely in WHICH addresses survived.
    assert flat.distinct_regions_retained == 1
    assert floored.distinct_regions_retained == 2
    assert not any(o.base_address >= quiet_base for o in flat.retained_observations)
    assert any(o.base_address >= quiet_base for o in floored.retained_observations)


def test_entropy_observations_move_review_priority_and_nothing_else():
    """Entropy is observation-only, and the record bears that out for
    score, confidence, verdict_level, lead_count and status. It does NOT
    for `review_priority`: an entropy observation carries TAG_OBSERVATION,
    and `review_priority()` returns PRIORITY_LOW for any observation, so a
    dump that previously had no obfuscation finding moves none -> low in
    both JSON and the console summary table.

    Pinned as a positive assertion in both directions so an implementation
    cannot quietly move a different field, or stop moving this one."""
    ref = RegionRef(base_address=0x10000000, allocation_base=0x10000000,
                    size=4 * 1024 * 1024, state="MEM_COMMIT",
                    protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(4)
    top.offer(entropy=7.95, base_address=0x10100000, size=4096, ref=ref, threshold=6.5)

    delta = record_delta(top.hits())

    for field in ("score", "confidence", "verdict_level", "lead_count", "status"):
        assert delta["baseline"][field] == delta["candidate"][field], field
    assert delta["moved"] == {"review_priority": ("none", "low")}


def test_uniform_alphabet_fixtures_are_identities_not_measurements():
    """A uniform alphabet of k symbols measures exactly log2(k) bits/byte.
    The band such a fixture lands in is chosen by whoever picked the
    alphabet, so it carries no calibration weight and no threshold
    argument may rest on it. Asserted at the point of construction so the
    identity cannot be re-read as a measurement."""
    assert _shannon_entropy(bytes(range(64)) * 64) == 6.0      # log2(64)
    assert _shannon_entropy(bytes(range(16)) * 256) == 4.0     # log2(16)

    calibrating = {label: calibrates
                   for label, _r, _m, _reader, calibrates in benign_noise_fixtures()}
    assert calibrating["uniform_alphabet_tiling"] is False
    assert calibrating["periodic_block_structured"] is False
    # Only content whose byte distribution is produced by a real
    # algorithm -- here a real compressor over synthetic structured input
    # -- can carry any calibration weight at all, and even that is a
    # mechanism, not a rate observed on real memory.
    assert calibrating["zlib_stream_rwx"] is True
    assert calibrating["zlib_stream_readwrite"] is True


def test_a_real_compressed_stream_produces_benign_above_threshold_observations():
    """The one benign fixture whose entropy is measured rather than chosen
    clears the threshold on dozens of its pages. Benign compressed memory
    is exactly what the whole-region average currently keeps quiet, and
    exactly what a page pass would start reporting."""
    regions, modules, reader = _benign("zlib_stream_rwx")
    result = run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                 EncodingConfig(), "rwx_only", **_GENEROUS)

    # Bounded below rather than pinned: the exact count depends on the zlib
    # build (see the protection test below), the point is that benign
    # compressed memory clears the bar on many pages, not on how many.
    assert result.pages_above_threshold > 10
    assert result.record_growth_bytes > 5000
    assert result.record_fields_moved == {"review_priority": ("none", "low")}


def test_the_per_region_floor_holds_to_the_global_cap_and_reports_its_overrun():
    """A per-region reservation is only a floor while the regions that
    produced hits still fit under the global cap. Filling breadth-first --
    every region's best before any region's second -- makes the floor hold
    all the way to `n` regions; past that no set of size `n` can represent
    them all, and the count that goes unrepresented is reported rather than
    left silent."""
    def _ref(index):
        base = 0x1000000 * (index + 1)
        return RegionRef(base_address=base, allocation_base=base, size=4 * 1024 * 1024,
                         state="MEM_COMMIT", protect="PAGE_EXECUTE_READWRITE",
                         type="MEM_PRIVATE", is_rwx=True)

    def _fill(region_count, cap=64, per_region=5):
        top = _TopN(cap, per_region=per_region)
        for index in range(region_count):
            ref = _ref(index)
            for page in range(8):
                top.offer(entropy=7.99 - index * 0.01 - page * 0.001,
                          base_address=ref.base_address + page * 4096,
                          size=4096, ref=ref, threshold=6.5)
        return top

    # Well past regions x per_region (34 x 5 = 170 reservations, cap 64):
    # every region is still represented.
    many = _fill(34)
    assert many.distinct_regions() == 34
    assert many.regions_dropped_from_retention() == 0
    assert len(many.ordered()) == 64

    # More regions than the cap itself: representation is impossible, and
    # the shortfall is counted instead of hidden.
    too_many = _fill(80)
    assert too_many.distinct_regions() == 64
    assert too_many.regions_dropped_from_retention() == 16


def test_per_region_retention_stays_bounded_during_the_scan():
    """Peak retention in per-region mode is bounded by the cap plus the
    per-region reservations, never by pages examined."""
    ref = RegionRef(base_address=0x20000000, allocation_base=0x20000000,
                    size=8 * 1024 * 1024, state="MEM_COMMIT",
                    protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    other = RegionRef(base_address=0x30000000, allocation_base=0x30000000,
                      size=8 * 1024 * 1024, state="MEM_COMMIT",
                      protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE", is_rwx=True)
    top = _TopN(4, per_region=2)
    for index in range(2000):
        source = ref if index % 2 else other
        top.offer(entropy=(index % 97) / 12.0,
                  base_address=source.base_address + index * 4096,
                  size=4096, ref=source, threshold=6.5)
        # Bounded by the cap, the region being scanned, and the reserved
        # set -- never a function of the 2000 windows offered.
        held = (len(top._heap) + len(top._current)
                + sum(len(entries) for entries in top._reserved.values()))
        assert held <= 4 + 2 + 4 * 2
    assert len(top.ordered()) == 4


def test_flat_retention_holds_no_per_region_structure():
    """Flat mode's retained set is the global heap alone, so it keeps no
    reserved set: holding one would double the default policy's retained
    entries and charge a rank-and-evict pass per region to a structure
    nothing reads.

    The one entry kept for the region in progress is what
    `regions_with_hits` counts, and it is dropped as soon as the scan
    leaves that region."""
    top = _TopN(64, per_region=0)
    for index in range(100):
        ref = RegionRef(base_address=0x10000000 + index * 0x100000,
                        allocation_base=0x10000000 + index * 0x100000,
                        size=8 * 1024 * 1024, state="MEM_COMMIT",
                        protect="PAGE_EXECUTE_READWRITE", type="MEM_PRIVATE",
                        is_rwx=True)
        top.offer(entropy=7.9 - index / 1000, base_address=ref.base_address,
                  size=4096, ref=ref, threshold=6.5)
        assert top._reserved == {}
        assert len(top._current) <= 1
        assert len(top._heap) <= 64

    # Every count the reserved set would have fed is still exact without
    # it: 100 regions hit, 64 of them present in the retained set, 36
    # absent from it entirely.
    assert top.regions_with_hits() == 100
    assert len(top.ordered()) == 64
    assert top.distinct_regions() == 64
    assert top.regions_dropped_from_retention() == 36


def test_the_compressed_stream_result_depends_on_the_region_protection():
    """The benign-noise headline is protection-dependent, and pinning that
    keeps it from being read as a property of compressed content alone.

    Benign compressed data ordinarily lives in PAGE_READWRITE private
    memory, which `rwx_only` never windows -- so under the narrower policy
    the same bytes produce nothing at all. The RWX row models compressed
    content staged in an RWX allocation (a JIT or unpacker buffer), which
    is a real but narrower case."""
    def _run(label, policy):
        regions, modules, reader = _benign(label)
        return run_page_local_pass(regions, modules, None, _SUSP_PROTS, reader,
                                   EncodingConfig(), policy, **_GENEROUS)

    # Relational, not absolute. `zlib.compress` output differs between zlib
    # builds (stock zlib and zlib-ng do not agree byte for byte), and page
    # entropy is measured on 4 KiB boundaries, so a few bytes of difference
    # move pages across the threshold and the exact counts vary by
    # environment. What is invariant is the SHAPE: in scope vs not, and
    # higher threshold means fewer pages.
    rwx_narrow = _run("zlib_stream_rwx", "rwx_only")
    assert rwx_narrow.pages_above_threshold > 0

    # The same bytes in ordinary read/write private memory: out of scope for
    # the narrower policy entirely.
    rw_narrow = _run("zlib_stream_readwrite", "rwx_only")
    assert rw_narrow.regions_in_scope == 0
    assert rw_narrow.pages_above_threshold == 0
    assert rw_narrow.record_fields_moved == {}

    # Under the wider policy they are measured against the higher private
    # threshold, so fewer pages clear it -- but the record still moves.
    rw_wide = _run("zlib_stream_readwrite", "all_eligible")
    assert 0 < rw_wide.pages_above_threshold < rwx_narrow.pages_above_threshold
    assert rw_wide.record_fields_moved == {"review_priority": ("none", "low")}


def test_retention_memory_is_bounded_in_region_count_not_only_page_count():
    """Peak retention must not grow with the number of REGIONS either.
    Holding one open heap per region bounds entries within a region while
    letting the number of heaps track the region count, so a dump with
    thousands of eligible regions would hold thousands of them for a
    retained set that can never exceed the cap.

    Regions are scanned one at a time, so a region's candidates are folded
    into a reserved set capped at `n` regions as soon as the scan leaves
    it. Offered here one region at a time, as the scan does."""
    cap, per_region, region_count = 64, 5, 10_000

    top = _TopN(cap, per_region=per_region)
    for index in range(region_count):
        base = 0x1000000 * (index + 1)
        ref = RegionRef(base_address=base, allocation_base=base, size=4 * 1024 * 1024,
                        state="MEM_COMMIT", protect="PAGE_EXECUTE_READWRITE",
                        type="MEM_PRIVATE", is_rwx=True)
        for page in range(8):
            top.offer(entropy=7.0 + (index % 90) / 1000 - page * 0.0001,
                      base_address=base + page * 4096, size=4096,
                      ref=ref, threshold=6.5)
        held = (len(top._heap) + len(top._current)
                + sum(len(entries) for entries in top._reserved.values()))
        assert held <= cap + per_region + cap * per_region
        assert len(top._reserved) <= cap

    assert len(top.ordered()) == cap
    assert top.regions_with_hits() == region_count
    assert top.regions_dropped_from_retention() == region_count - cap


def _region_ref(base):
    return RegionRef(base_address=base, allocation_base=base, size=0x100000,
                     state="MEM_COMMIT", protect="PAGE_EXECUTE_READWRITE",
                     type="MEM_PRIVATE", is_rwx=True)


def test_equal_entropy_across_regions_keeps_the_lower_address():
    """Retention order is descending entropy, then ASCENDING address. When
    two regions tie on entropy the lower-addressed one is kept, and that
    has to hold in the cross-region ranking as well as within a region.

    Ties are not a theoretical edge: a page holding all 256 byte values in
    equal proportion measures exactly 8.0, and duplicated buffers produce
    identical values readily."""
    top = _TopN(1, per_region=1)
    top.offer(7.5, 0x1000, 4096, _region_ref(0x1000), 6.5)
    top.offer(7.5, 0x2000, 4096, _region_ref(0x2000), 6.5)
    assert top.ordered()[0].base_address == 0x1000

    # Offered in the other order, the same winner.
    reversed_order = _TopN(1, per_region=1)
    reversed_order.offer(7.5, 0x2000, 4096, _region_ref(0x2000), 6.5)
    reversed_order.offer(7.5, 0x1000, 4096, _region_ref(0x1000), 6.5)
    assert reversed_order.ordered()[0].base_address == 0x1000

    # Several regions all at exactly maximal entropy: the lowest address
    # wins, and the retained set is ordered by address throughout.
    maximal = _TopN(3, per_region=1)
    for base in (0x9000, 0x3000, 0x7000, 0x1000):
        maximal.offer(8.0, base, 4096, _region_ref(base), 6.5)
    assert [o.base_address for o in maximal.ordered()] == [0x1000, 0x3000, 0x7000]


def test_reading_the_retained_set_does_not_advance_the_scan_state():
    """Every read is pure. A read that closed the region being scanned
    would make merely looking at the retained set -- a progress line, a
    debug print, a mid-scan snapshot -- split one region into two and
    inflate `regions_with_hits`."""
    ref = _region_ref(0x5000)

    quiet = _TopN(64, per_region=5)
    quiet.offer(7.9, 0x5000, 4096, ref, 6.5)
    quiet.offer(7.8, 0x6000, 4096, ref, 6.5)

    observed = _TopN(64, per_region=5)
    observed.offer(7.9, 0x5000, 4096, ref, 6.5)
    # Read between the two pages of the SAME region.
    assert len(observed) == 1
    assert observed.regions_with_hits() == 1
    assert observed.distinct_regions() == 1
    observed.offer(7.8, 0x6000, 4096, ref, 6.5)

    for result in (quiet, observed):
        assert result.regions_with_hits() == 1
        assert result.distinct_regions() == 1
        assert result.regions_dropped_from_retention() == 0
    assert quiet.ordered() == observed.ordered()


def test_the_region_being_scanned_is_visible_to_reads_before_it_is_closed():
    """The in-progress region participates in a read as a snapshot, so the
    retained set is the same whether it is inspected mid-region or after
    the scan moves on."""
    top = _TopN(4, per_region=2)
    first = _region_ref(0x1000)
    top.offer(7.9, 0x1000, 4096, first, 6.5)

    mid_scan = top.ordered()
    assert [o.base_address for o in mid_scan] == [0x1000]
    assert top.regions_with_hits() == 1

    # Moving to another region closes the first; the earlier observation is
    # still there, and the count reflects both regions exactly once.
    top.offer(7.8, 0x2000, 4096, _region_ref(0x2000), 6.5)
    assert [o.base_address for o in top.ordered()] == [0x1000, 0x2000]
    assert top.regions_with_hits() == 2
    assert top.regions_dropped_from_retention() == 0
