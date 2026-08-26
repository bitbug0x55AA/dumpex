"""Immutable hollowing evidence and resolved image-base context.

Raw PEB, module, and memory-region objects are reduced to plain values at the
collection boundary. Header failure, missing capture, absent modules, and clean
observations remain distinct so downstream scoring cannot invent evidence.
"""
import ntpath
from dataclasses import dataclass

from dumpex.core.memory import prot_str
from dumpex.hunt._domain import require_recursively_immutable


# ── Shared field validators ───────────────────────────────────────────────
# Same two-layer defense dumpex.hunt.stomping.models applies: an exact
# field TYPE check (so a poison reference is refused at the earliest, most
# specific point, with a message naming the field) plus a
# `require_recursively_immutable` depth walk (so a mutable payload smuggled
# a level or more INSIDE an otherwise well-typed field cannot survive
# either).

def _require_type(value, expected, field_name: str) -> None:
    if not isinstance(value, expected):
        expected_names = (expected.__name__ if isinstance(expected, type)
                          else " or ".join(t.__name__ for t in expected))
        raise TypeError(
            f"{field_name} must be a {expected_names}, got {type(value).__name__}: {value!r}")


def _require_optional_type(value, expected, field_name: str) -> None:
    if value is not None:
        _require_type(value, expected, field_name)


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise TypeError(f"{field_name} must be a bool, got {type(value).__name__}: {value!r}")


def _require_str(value, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}: {value!r}")


def _require_optional_str(value, field_name: str) -> None:
    if value is not None:
        _require_str(value, field_name)


def _require_bytes(value, field_name: str) -> None:
    # Exact type, not isinstance: a `bytearray` is mutable in place and a
    # `memoryview` keeps whatever buffer it was cut from alive and
    # writable -- neither may sit inside a "frozen" evidence object.
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes, got {type(value).__name__}: {value!r}")


def _require_optional_bytes(value, field_name: str) -> None:
    if value is not None:
        _require_bytes(value, field_name)


def _require_count(value, field_name: str) -> None:
    # bool is excluded explicitly: it is an int subclass, and a stray
    # boolean where an address was meant is a caller bug, not 0/1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


# ── Path handling ─────────────────────────────────────────────────────────

def basename_lower(path: str) -> str:
    """The lowercased Windows basename of `path`.

    Paths embedded in a minidump are from the ORIGINAL Windows system
    (e.g. 'C:\\Windows\\System32\\foo.exe'). `os.path.basename` only splits
    on '/' when running on a POSIX analysis host, so it would return the
    whole backslash-separated string unchanged there -- `ntpath.basename`
    always applies Windows path rules regardless of the host OS dumpex
    itself runs on. Lowercased because the PEB-vs-module-list comparison
    this feeds is a case-insensitive one (Windows paths are).

    This is the pre-migration `dumpex.hunt.hollowing._basename_lower`,
    unchanged in behavior, moved here because it is now part of resolving
    identity ONCE at scan time rather than something the renderer re-runs
    on a raw `Module` the domain model must not retain.
    """
    return ntpath.basename(path or "").lower()


# ── Identity snapshots ────────────────────────────────────────────────────

def module_ref(module) -> "ModuleRef":
    """The ONE place a raw minidump `Module` becomes an immutable identity
    snapshot -- the basename is resolved here, once, so no projector ever
    needs the `Module` object (or `ntpath`) again."""
    return ModuleRef(name=module.name or "",
                      basename=ntpath.basename(module.name or ""),
                      base_address=module.baseaddress, size=module.size or 0)


def region_ref(region) -> "RegionRef":
    """The ONE place a raw minidump MemoryInfo region becomes an immutable
    `RegionRef` -- `state`/`protect`/`type` go through `prot_str()` here,
    once, so no projector ever calls it on a live region again (the
    pre-migration renderer called it FOUR more times, on a raw region the
    Report had kept alive purely so it could)."""
    return RegionRef(base_address=region.BaseAddress,
                      allocation_base=getattr(region, "AllocationBase", None),
                      size=region.RegionSize, state=prot_str(region.State),
                      protect=prot_str(region.Protect), type=prot_str(region.Type))


@dataclass(frozen=True)
class ModuleRef:
    """Immutable snapshot of one loaded module's identity -- everything any
    projection ever needs about the module the module list attributes the
    image base to, without holding the `Module` object itself. `name` is
    the module's own recorded (Windows) path, kept because
    `HollowingDetails.module_name` exposes it verbatim; `basename` is
    `ntpath.basename(name)`, resolved once at scan time."""
    name: str
    basename: str
    base_address: int
    size: int = 0

    def __post_init__(self):
        _require_str(self.name, "ModuleRef.name")
        _require_str(self.basename, "ModuleRef.basename")
        _require_count(self.base_address, "ModuleRef.base_address")
        _require_count(self.size, "ModuleRef.size")

    @property
    def basename_lower(self) -> str:
        """The case-insensitive form the PEB-vs-module-list comparison (and
        the console line reporting its outcome) both use. A property, never
        a second stored field: one fact, one place, nothing to drift."""
        return self.basename.lower()


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of the MemoryInfo region covering the image base.
    `state`/`protect`/`type` are `prot_str()`-resolved once at scan time
    (see `region_ref()` above)."""
    base_address: int
    allocation_base: "int | None"
    size: int
    state: str      # prot_str(region.State),   resolved once at scan time
    protect: str    # prot_str(region.Protect), resolved once at scan time
    type: str       # prot_str(region.Type),    resolved once at scan time

    def __post_init__(self):
        _require_count(self.base_address, "RegionRef.base_address")
        _require_optional_count(self.allocation_base, "RegionRef.allocation_base")
        _require_count(self.size, "RegionRef.size")
        for attribute in ("state", "protect", "type"):
            _require_str(getattr(self, attribute), f"RegionRef.{attribute}")


# ── The MZ/DOS-header read ────────────────────────────────────────────────
# Five mutually exclusive outcomes, named once here. The pre-migration
# Report carried the same five as a bare `mz_outcome: str | None` plus THREE
# derived booleans (`mz_read_failed`/`mz_wiped`, and `mz_header_present`
# recomputed a fourth time inside the record projector) that nothing kept
# in agreement -- they are properties of this one value object now.

OUTCOME_CLEAN       = "clean"          # MZ magic present where it should be
OUTCOME_WIPED_ZERO  = "wiped_zero"     # the whole read came back zeroed
OUTCOME_WIPED_OTHER = "wiped_other"    # non-zero bytes, but not MZ
OUTCOME_SHORT_READ  = "short_read"     # fewer than MZ_MIN_BYTES returned
OUTCOME_EXCEPTION   = "exception"      # the read itself raised

_OUTCOMES = (OUTCOME_CLEAN, OUTCOME_WIPED_ZERO, OUTCOME_WIPED_OTHER,
             OUTCOME_SHORT_READ, OUTCOME_EXCEPTION)


@dataclass(frozen=True)
class HeaderRead:
    """What the single MZ/DOS-header read at the image base actually
    produced.

    `header_bytes` is whatever came back (the full `config.MZ_READ_LEN`
    window on a successful read, a shorter prefix on a short read) and is
    `None` only for `OUTCOME_EXCEPTION`, where no bytes were ever returned
    -- distinct from `b""`, which would claim a successful zero-length
    read. `error` is the exception's own text, and is set for exactly that
    one outcome.

    The three booleans below are DERIVED, never stored: a read cannot be
    simultaneously "wiped" and "failed", and the pre-migration Report kept
    both as independent fields that a future edit could have set
    inconsistently.
    """
    outcome:      str
    header_bytes: "bytes | None" = None
    error:        "str | None" = None

    def __post_init__(self):
        if self.outcome not in _OUTCOMES:
            raise ValueError(
                f"HeaderRead.outcome must be one of {_OUTCOMES}, got {self.outcome!r}")
        _require_optional_bytes(self.header_bytes, "HeaderRead.header_bytes")
        _require_optional_str(self.error, "HeaderRead.error")
        if self.outcome == OUTCOME_EXCEPTION:
            if self.header_bytes is not None:
                raise ValueError(
                    "HeaderRead.header_bytes must be None for an exception outcome -- no "
                    "bytes were ever returned")
        elif self.header_bytes is None:
            raise ValueError(
                f"HeaderRead.header_bytes is required for outcome {self.outcome!r} -- only "
                f"an exception outcome has no bytes at all")
        require_recursively_immutable(self, "HeaderRead")

    @property
    def read_failed(self) -> bool:
        """The check never actually ran -- a COVERAGE GAP, not a result. A
        short read is deliberately in here: fewer than two bytes back
        cannot confirm OR deny the MZ magic, and treating it as a wiped
        header previously reached a false DETECTED when combined with
        MEM_PRIVATE."""
        return self.outcome in (OUTCOME_SHORT_READ, OUTCOME_EXCEPTION)

    @property
    def wiped(self) -> bool:
        """A real structural anchor: bytes came back, and they are not an
        MZ header."""
        return self.outcome in (OUTCOME_WIPED_ZERO, OUTCOME_WIPED_OTHER)

    @property
    def header_present(self) -> "bool | None":
        """`HollowingDetails.mz_header_present`'s own tri-state: `None`
        when the read failed (nothing was checked), else whether an MZ
        header was actually there."""
        if self.read_failed:
            return None
        return self.outcome == OUTCOME_CLEAN


# ── The resolved image-base context ───────────────────────────────────────

@dataclass(frozen=True)
class ImageBaseContext:
    """Everything about the PEB's own image base, resolved ONCE before
    aggregation -- the replacement for the pre-migration Report's
    `image_base`/`image_path`/`peb_image_path_raw`/`fo_base`/`base_region`/
    `main_mod`/`mz_*` fields, two of which were live minidump objects and
    four of which were re-derived from them at render time.

    `image_path` is the "(unknown)"-coerced DISPLAY string every fact,
    comparison, and console line uses, exactly as before this migration.
    `peb_image_path` is the genuinely-`None`-when-absent raw value, tracked
    separately purely for `HollowingDetails.peb_image_path`, whose
    `str | None` contract means null, not the display string "(unknown)".

    `region` is `None` when the image base page was not captured in this
    dump at all, and `module` is `None` when the module list has no entry
    covering that base -- two different, individually meaningful absences
    (see `domain.CoverageSnapshot` for the third, a failed header read).
    """
    image_base:         int
    image_path:         str
    peb_image_path:     "str | None"
    header:             HeaderRead
    file_offset:        "int | None" = None   # .dmp offset of image_base
    region:             "RegionRef | None" = None
    region_file_offset: "int | None" = None   # .dmp offset of region.base_address
    module:             "ModuleRef | None" = None

    def __post_init__(self):
        _require_count(self.image_base, "ImageBaseContext.image_base")
        _require_str(self.image_path, "ImageBaseContext.image_path")
        _require_optional_str(self.peb_image_path, "ImageBaseContext.peb_image_path")
        _require_type(self.header, HeaderRead, "ImageBaseContext.header")
        _require_optional_count(self.file_offset, "ImageBaseContext.file_offset")
        _require_optional_type(self.region, RegionRef, "ImageBaseContext.region")
        _require_optional_count(self.region_file_offset,
                                 "ImageBaseContext.region_file_offset")
        _require_optional_type(self.module, ModuleRef, "ImageBaseContext.module")
        if self.region is None and self.region_file_offset is not None:
            raise ValueError(
                "ImageBaseContext.region_file_offset cannot be set without a region -- it is "
                "that region's own .dmp offset")
        require_recursively_immutable(self, "ImageBaseContext")

    @property
    def image_name(self) -> str:
        """The PEB image path's own lowercased basename -- the left-hand
        side of the module-list name comparison, and the name the console
        reports it under."""
        return basename_lower(self.image_path)


# ── Evidence ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class MemPrivateEvidence:
    """ANCHOR 1: the image base is backed by memory whose type is not
    MEM_IMAGE -- nothing was mapped from the executable file this process
    is supposed to be running.

    Holds the `RegionRef` rather than the raw `MinidumpMemoryInfo` the
    pre-migration Report kept alive for the renderer's benefit."""
    region: RegionRef

    def __post_init__(self):
        _require_type(self.region, RegionRef, "MemPrivateEvidence.region")
        require_recursively_immutable(self, "MemPrivateEvidence")


@dataclass(frozen=True)
class WipedHeaderEvidence:
    """ANCHOR 2: bytes came back from the image base and they are not an
    MZ/DOS header (zeroed, or something else entirely).

    Deliberately NOT constructed for a short/failed read: that is a
    coverage gap recorded on `domain.CoverageSnapshot`, not evidence the
    header is missing (see `HeaderRead.read_failed`)."""
    image_base:   int
    header_bytes: bytes

    def __post_init__(self):
        _require_count(self.image_base, "WipedHeaderEvidence.image_base")
        _require_bytes(self.header_bytes, "WipedHeaderEvidence.header_bytes")
        require_recursively_immutable(self, "WipedHeaderEvidence")


@dataclass(frozen=True)
class RwxProtectionEvidence:
    """CORROBORATOR 3: the image base carries an RWX-family protection --
    what writing replacement code there requires, but also what JITs,
    debuggers, and some legitimate packers do routinely."""
    region: RegionRef

    def __post_init__(self):
        _require_type(self.region, RegionRef, "RwxProtectionEvidence.region")
        require_recursively_immutable(self, "RwxProtectionEvidence")


@dataclass(frozen=True)
class NameMismatchEvidence:
    """CORROBORATOR 4: the PEB's own ImagePath name doesn't match the module
    list's name for this base address, or the base isn't in the module list
    at all.

    `module` is `None` for the second case -- and only ever constructed at
    all when the module list itself WAS available, since without it the
    check could not run and a `None` module means nothing (see
    `memory_scan.collect_signals`)."""
    image_path: str
    module:     "ModuleRef | None" = None

    def __post_init__(self):
        _require_str(self.image_path, "NameMismatchEvidence.image_path")
        _require_optional_type(self.module, ModuleRef, "NameMismatchEvidence.module")
        require_recursively_immutable(self, "NameMismatchEvidence")


@dataclass(frozen=True)
class StructuralCorrelationEvidence:
    """The ONLY scored signal: anchor 1 (MEM_PRIVATE) firing together with
    EITHER anchor 2 (a wiped MZ header) or corroborator 3 (RWX) at the SAME
    image base.

    `mem_private`/`wiped_header`/`rwx` are the SAME instances the Report's
    own buckets hold (never copies) -- enforced by identity in
    `HollowingEvidence`, so the correlation and the individual leads can
    never describe the same region differently. That is also why this type
    stores references rather than re-copying the region: the pre-migration
    code rebuilt the corroborator LABELS from three loose booleans
    (`mem_private`/`mz_wiped`/`is_rwx`) that were computed in one place and
    re-read in three others.
    """
    image_base:   int
    mem_private:  MemPrivateEvidence
    wiped_header: "WipedHeaderEvidence | None" = None
    rwx:          "RwxProtectionEvidence | None" = None

    def __post_init__(self):
        _require_count(self.image_base, "StructuralCorrelationEvidence.image_base")
        _require_type(self.mem_private, MemPrivateEvidence,
                       "StructuralCorrelationEvidence.mem_private")
        _require_optional_type(self.wiped_header, WipedHeaderEvidence,
                                "StructuralCorrelationEvidence.wiped_header")
        _require_optional_type(self.rwx, RwxProtectionEvidence,
                                "StructuralCorrelationEvidence.rwx")
        if self.wiped_header is None and self.rwx is None:
            raise ValueError(
                "StructuralCorrelationEvidence requires at least one corroborating signal "
                "alongside MEM_PRIVATE (a wiped MZ header and/or RWX protection) -- a lone "
                "anchor is a lead, never a correlation")
        require_recursively_immutable(self, "StructuralCorrelationEvidence")

    @property
    def corroborators(self) -> tuple:
        """The correlating signals' own labels, in the fixed order the
        pre-migration fact/inference text used. Derived from which
        references are actually set, so the rendered list can never claim
        a signal this evidence does not hold."""
        labels = ["MEM_PRIVATE at image base"]
        if self.wiped_header is not None:
            labels.append("MZ header missing/wiped")
        if self.rwx is not None:
            labels.append("RWX protection")
        return tuple(labels)

    @property
    def full_correlation(self) -> bool:
        """All three signals at once -- the only thing that takes this
        hunter's score from 1 to 2."""
        return self.wiped_header is not None and self.rwx is not None
