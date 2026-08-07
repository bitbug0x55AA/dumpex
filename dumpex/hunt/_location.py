"""
Immutable address-resolution value object, shared by every hunter's scan
layer -- the ONE place VA / region-relative-offset / file-offset semantics
are defined, before any hunter migrates onto the Evidence/CheckResult/
Report pilot (see dumpex/hunt/injection/ and dumpex/hunt/encoding/ for the
first two hunters to consume this). Building this in isolation, with its
own tests, means the semantics are fixed once rather than re-derived ad
hoc per hunter as each one migrates.

This module intentionally has NO opinion on what evidence is (a region, a
thread, a decoded payload, ...) -- see MemoryEvidence-shaped types living
in each hunter's own aggregate module instead. Non-memory evidence (pipe
handle metadata, IOC token hits, CS beacon config fields) never needs a
Location at all and must not be forced through this type.
"""
from dataclasses import dataclass, field
from typing import Optional

from dumpex.core.memory import va_to_file_offset


def _require_non_negative_int(name: str, value) -> None:
    # bool is a subclass of int in Python (isinstance(True, int) is True),
    # so it must be rejected explicitly -- a caller passing a stray
    # boolean where an address/size was meant is a bug, not a 0/1 address.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"Location: {name} must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"Location: {name} must be a non-negative int, got {value}")


def _validate_address(va, region_base, region_size) -> None:
    """Shared validation for both Location.__post_init__ and
    resolve_location() -- called by the latter BEFORE it ever calls
    va_to_file_offset(), so a malformed va/region_base/region_size fails
    loudly instead of first being handed to the resolver and only
    rejected afterwards, by which point an invalid address has already
    been "looked up" as if it were legitimate evidence."""
    _require_non_negative_int("va", va)
    _require_non_negative_int("region_base", region_base)
    if va < region_base:
        raise ValueError(
            f"Location: va=0x{va:x} is below its own region_base "
            f"0x{region_base:x} -- region_offset would be negative")
    if region_size is not None:
        _require_non_negative_int("region_size", region_size)
        region_end = region_base + region_size
        if va >= region_end:
            raise ValueError(
                f"Location: va=0x{va:x} is at/beyond region end 0x{region_end:x} "
                f"(region_base=0x{region_base:x} region_size=0x{region_size:x})")


@dataclass(frozen=True)
class Location:
    """A single resolved address inside the dumped process's memory.

    va: absolute virtual address (process address space at capture time).
        Always known -- a Location with no VA at all isn't a memory
        location. Must be a non-negative int (bool rejected too).

    region_base: the containing MemoryInfo region's own BaseAddress.
        `va` must be >= `region_base` (enforced in __post_init__) --
        `region_offset` is derived from these two, never stored
        separately, so the two can never silently disagree.

    file_offset: the .dmp file's byte offset for `va`, or None if the
        minidump's memory segment table doesn't cover `va` at all (e.g.
        it fell outside every captured Memory64List/MemoryList range).
        None means "not captured" -- it is NOT the same claim as "resolved
        to offset zero". 0 is one ordinary, valid file_offset among many
        (the very first byte of the .dmp) and must never be treated as
        falsy. Callers must never write `location.file_offset or 0` --
        that silently turns "not captured" into "byte zero of the file".

    region_size: OPTIONAL, construction-time-only upper-bound check --
        when given, `va` must fall strictly within [region_base,
        region_base + region_size), enforced once in __post_init__. NOT
        part of this Location's identity: excluded from __eq__/__hash__
        (field(compare=False)) because it carries no resolved information
        beyond what (va, region_base, file_offset) already fully
        determine -- two Locations built from the same va/region_base/
        file_offset must compare equal and hash equal regardless of
        whether one caller happened to also pass region_size and another
        didn't (e.g. two different evidence collectors for the same
        region, one with the region's size in scope and one without).
        Left None when a caller doesn't have the region's size in scope
        (still a valid Location, just without the upper-bound guarantee).
    """
    va: int
    region_base: int
    file_offset: Optional[int]
    region_size: Optional[int] = field(default=None, compare=False)

    def __post_init__(self):
        _validate_address(self.va, self.region_base, self.region_size)
        if self.file_offset is not None:
            _require_non_negative_int("file_offset", self.file_offset)

    @property
    def region_offset(self) -> int:
        """Byte offset of `va` WITHIN its region -- independent of where
        that region's bytes happen to live in the .dmp file. Not the
        same value as `file_offset` (which two evidence items in
        DIFFERENT regions could coincidentally share; region_offset
        alone never identifies a unique byte in the dump)."""
        return self.va - self.region_base


def resolve_location(mf, va: int, region_base: int, region_size: Optional[int] = None) -> Location:
    """Build a Location for `va` (a specific evidence address, not
    necessarily a region's own BaseAddress) against `region_base` (the
    containing region's BaseAddress) and `mf`. The ONE place a hunter's
    scan layer should call va_to_file_offset() when constructing
    evidence -- once this is adopted, aggregate.py/presentation.py never
    need `mf` for address resolution again (they read the already-
    resolved `file_offset` off the evidence instead). Validates va/
    region_base/region_size BEFORE calling va_to_file_offset() -- see
    _validate_address()'s own docstring for why the order matters."""
    _validate_address(va, region_base, region_size)
    return Location(va=va, region_base=region_base,
                     file_offset=va_to_file_offset(mf, va), region_size=region_size)
