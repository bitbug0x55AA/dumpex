"""The full-scope entropy averaging blind spot.

`_scan_entropy` computes one Shannon value over each eligible region --
that region's average. A bounded high-entropy payload inside an otherwise
sparse multi-megabyte allocation is diluted by the zero-filled majority, so
the region-level average can sit well below threshold even though a single
page inside it sits well above. `scan_entropy_targeted`'s VA-aligned window
pass, run over the identical bytes, measures the page independently of the
allocation around it and is not subject to the same dilution.

These tests pin the contract as it stands: `_scan_entropy` measures one
value per region and localizes nothing inside it, while
`scan_entropy_targeted` localizes. The pair is a contrast between two
contracts, not a guard on one -- should full-scope scanning ever gain a page
pass, `test_full_scope_whole_region_average_hides_the_hot_page` states the
behaviour that changes, and inverting it is the correct response rather than
weakening the pass to keep it green.

See docs/developer/hunt_entropy_full_scope_page_pass_evaluation.md.
"""
import random

from tests.fixtures.fakes import Region, FakeStream, FakeMF, mem_reader

from dumpex.hunt.encoding.config import EncodingConfig, ENTROPY_RWX_THRESHOLD
from dumpex.hunt.encoding.entropy import _scan_entropy, scan_entropy_targeted

# A 4 MiB MEM_PRIVATE PAGE_EXECUTE_READWRITE allocation, page-aligned and
# mostly zero-filled -- the shape a sparse implant allocation takes.
_REGION_BASE = 0x0000000010000000
_REGION_SIZE = 4 * 1024 * 1024
_PAGE_SIZE = 4 * 1024
# Page-aligned offset comfortably inside the allocation, away from both
# edges, so the page-alignment logic in `_window_spans` never has to be
# reasoned about to trust this fixture.
_HOT_PAGE_OFFSET = 0x100000
_SUSP_PROTS = ("PAGE_EXECUTE_READWRITE",)


def _sparse_region_with_one_hot_page() -> bytes:
    """4 MiB of zero bytes with one deterministic, page-aligned 4 KiB
    high-entropy block planted in the middle. Seeded so the fixture is
    exactly reproducible across runs and machines."""
    data = bytearray(_REGION_SIZE)
    hot_page = random.Random(1234).randbytes(_PAGE_SIZE)
    data[_HOT_PAGE_OFFSET:_HOT_PAGE_OFFSET + _PAGE_SIZE] = hot_page
    return bytes(data)


def _fixture_mf():
    regions = [Region(_REGION_BASE, _REGION_BASE, _REGION_SIZE,
                       "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")

    return regions, MF()


def test_full_scope_whole_region_average_hides_the_hot_page():
    """The full-scope entropy scan measures one average over the whole
    4 MiB allocation. A single 4 KiB high-entropy page
    diluted by ~4092 KiB of zeros pulls that average far below the RWX
    threshold, so the region produces no entropy hit at all."""
    regions, mf = _fixture_mf()
    reader = mem_reader({_REGION_BASE: _sparse_region_with_one_hot_page()})

    result = _scan_entropy(regions, [], mf, _SUSP_PROTS, reader)

    assert result.hits == ()
    assert result.coverage.scanned == 1


def test_targeted_window_pass_localizes_the_same_hot_page():
    """The identical bytes, measured by the targeted VA-aligned 4 KiB
    window pass, localize the hot page as its own above-threshold
    observation -- the same bytes the full-scope average called clean."""
    regions, mf = _fixture_mf()
    reader = mem_reader({_REGION_BASE: _sparse_region_with_one_hot_page()})
    config = EncodingConfig()

    result, windowed = scan_entropy_targeted(regions, [], mf, _SUSP_PROTS, reader, config)

    # The whole-range average is still below threshold -- windows are what
    # surface the hot page, not the range-level hit path.
    assert windowed.whole_range_entropy < ENTROPY_RWX_THRESHOLD
    assert windowed.windows_above_threshold >= 1
    assert windowed.exhaustive

    hot_page_hits = [h for h in result.hits if h.location.va == _REGION_BASE + _HOT_PAGE_OFFSET]
    assert len(hot_page_hits) == 1
    assert hot_page_hits[0].size == _PAGE_SIZE
    assert hot_page_hits[0].entropy >= ENTROPY_RWX_THRESHOLD

    # `_scan_entropy` never produced this hit -- confirms the two functions
    # are actually diverging on the identical input, not merely that the
    # targeted path found *something*.
    range_level_hits = [h for h in result.hits if h.size is None]
    assert range_level_hits == []
