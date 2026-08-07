"""
Tests for dumpex.hunt._location.Location/resolve_location -- the shared
address-resolution value object every hunter's Evidence/CheckResult/Report
pilot (injection first, then encoding) will build on. Pins down the two
things a hasty per-hunter reimplementation would be most likely to get
wrong: region_offset vs. file_offset are NOT the same number, and a
resolved file_offset of 0 must never collapse into "not captured" (None)
or vice versa via an `x or 0`/`x or None` shortcut.

No hunter output changes as part of this commit -- this module isn't
wired into any hunter yet.
"""
import dataclasses

import pytest

from dumpex.hunt._location import Location, resolve_location


def test_region_offset_computed_from_va_and_region_base():
    loc = Location(va=0x1000_0100, region_base=0x1000_0000, file_offset=0x500)
    assert loc.region_offset == 0x100


def test_region_offset_zero_when_va_equals_region_base():
    loc = Location(va=0x2000_0000, region_base=0x2000_0000, file_offset=None)
    assert loc.region_offset == 0


def test_va_below_region_base_raises_value_error():
    with pytest.raises(ValueError, match="below its own region_base"):
        Location(va=0x1000_0000, region_base=0x1000_0100, file_offset=None)


def test_file_offset_none_means_not_captured_not_zero():
    loc = Location(va=0x1000, region_base=0x1000, file_offset=None)
    assert loc.file_offset is None
    assert loc.file_offset != 0


def test_file_offset_zero_is_a_valid_distinct_value():
    # The very first byte of the .dmp is offset 0 -- a legitimate resolved
    # value, not a stand-in for "resolution failed".
    loc = Location(va=0x1000, region_base=0x1000, file_offset=0)
    assert loc.file_offset == 0
    assert loc.file_offset is not None


def test_location_is_frozen():
    loc = Location(va=0x1000, region_base=0x1000, file_offset=0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        loc.va = 0x2000


def test_resolve_location_calls_va_to_file_offset_with_the_evidence_va(monkeypatch):
    # resolve_location must resolve the actual evidence VA, never the
    # containing region's own BaseAddress -- those two are frequently
    # different (an evidence item partway through a region).
    seen = {}

    def fake_va_to_file_offset(mf, va):
        seen["mf"] = mf
        seen["va"] = va
        return 0xAB0

    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", fake_va_to_file_offset)

    sentinel_mf = object()
    loc = resolve_location(sentinel_mf, va=0x3000_0040, region_base=0x3000_0000)

    assert seen == {"mf": sentinel_mf, "va": 0x3000_0040}
    assert loc.va == 0x3000_0040
    assert loc.region_base == 0x3000_0000
    assert loc.region_offset == 0x40
    assert loc.file_offset == 0xAB0


def test_resolve_location_preserves_none_when_va_not_covered_by_any_segment(monkeypatch):
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset", lambda mf, va: None)

    loc = resolve_location(object(), va=0x4000_0010, region_base=0x4000_0000)

    assert loc.file_offset is None


# ── invalid/out-of-bounds addresses must never be silently frozen ───────

@pytest.mark.parametrize("va,region_base,file_offset", [
    (-5, 0, None),        # negative va
    (0x1000, -1, None),   # negative region_base
    (0x1000, 0, -1),      # negative file_offset
])
def test_rejects_negative_address_components(va, region_base, file_offset):
    with pytest.raises(ValueError, match="non-negative int"):
        Location(va=va, region_base=region_base, file_offset=file_offset)


@pytest.mark.parametrize("field,value", [("va", True), ("region_base", False)])
def test_rejects_bool_where_int_expected(field, value):
    # bool is a subclass of int -- True/False must not be silently
    # accepted as if they were addresses 1/0.
    kwargs = dict(va=0x1000, region_base=0x1000, file_offset=None)
    kwargs[field] = value
    with pytest.raises(TypeError, match="non-negative int"):
        Location(**kwargs)


def test_rejects_va_at_or_beyond_region_end_when_region_size_given():
    with pytest.raises(ValueError, match="region end"):
        Location(va=0x1000_1000, region_base=0x1000_0000, file_offset=None, region_size=0x1000)


def test_accepts_va_at_region_start_and_just_below_region_end():
    Location(va=0x1000_0000, region_base=0x1000_0000, file_offset=None, region_size=0x1000)
    Location(va=0x1000_0FFF, region_base=0x1000_0000, file_offset=None, region_size=0x1000)


def test_region_size_none_skips_the_upper_bound_check():
    # No region_size in scope -- still a valid Location, just without the
    # upper-bound guarantee (see this field's own docstring).
    loc = Location(va=0x1000_9999, region_base=0x1000_0000, file_offset=None)
    assert loc.region_offset == 0x9999


def test_resolve_location_validates_before_calling_the_resolver(monkeypatch):
    # An invalid va/region_base must never reach va_to_file_offset() at
    # all -- resolving "evidence" at a malformed address and only
    # rejecting it afterwards would mean the resolver was already asked
    # to look up nonsense as if it were legitimate.
    calls = []
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset",
                         lambda mf, va: calls.append(va) or 0)

    with pytest.raises(ValueError, match="non-negative int"):
        resolve_location(object(), va=-1, region_base=0)

    assert calls == []


def test_resolve_location_validates_region_size_before_calling_the_resolver(monkeypatch):
    calls = []
    monkeypatch.setattr("dumpex.hunt._location.va_to_file_offset",
                         lambda mf, va: calls.append(va) or 0)

    with pytest.raises(ValueError, match="region end"):
        resolve_location(object(), va=0x2000_1000, region_base=0x2000_0000, region_size=0x1000)

    assert calls == []


# ── region_size must not affect Location's identity ──────────────────────

def test_region_size_does_not_affect_equality_or_hash():
    # Two Locations resolved to the same (va, region_base, file_offset)
    # must compare equal and hash equal regardless of whether one caller
    # happened to also pass region_size (a construction-time-only bounds
    # check, not part of what this Location IS) and another didn't --
    # otherwise the same evidence address would silently get two
    # different identities depending on which collector built it.
    without_size = Location(va=0x1100, region_base=0x1000, file_offset=0x500)
    with_size = Location(va=0x1100, region_base=0x1000, file_offset=0x500, region_size=0x1000)

    assert without_size == with_size
    assert hash(without_size) == hash(with_size)


def test_region_size_differing_alone_does_not_break_equality():
    a = Location(va=0x1100, region_base=0x1000, file_offset=0x500, region_size=0x1000)
    b = Location(va=0x1100, region_base=0x1000, file_offset=0x500, region_size=0x2000)

    assert a == b
    assert hash(a) == hash(b)
