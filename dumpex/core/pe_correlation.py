"""Pure main-image PE correlation: consistency observations over one
:class:`~dumpex.core.pe_profile.PeImageProfile` and the process memory
evidence that surrounds it.

What this module is
-------------------
It is the **derived observation** tier of
``docs/developer/pe_image_profile_contract.md`` §1.1: it compares two
already-established facts and reports ``consistent``, ``conflict``, or
``unavailable`` over them, and nothing else. It never scores, never
assigns a confidence, never emits a hunter :class:`Finding`, and never
re-reads a byte of PE or memory -- every value it uses is one the profile
already decoded or one the caller already reduced from ``mf``.

Two rules from the contract bind every observation here:

- §8.3's three-valued rule. When the established facts determine an
  observation's predicate the result is ``conflict`` (true) or
  ``consistent`` (false); when they do not, it is ``unavailable``. "An
  operand is ``None``" is not on its own an answer in either direction.
- §1.2's first rule, applied to an observation: an uncaptured fact is a
  gap, never a ``conflict``. A missing ModuleList entry, a missing
  MemoryInfo region, and an unwritten page each yield ``unavailable``,
  never a PE defect.

The frozen five and the correlation layer
-----------------------------------------
§8.3 freezes five cross-surface consistency observations --
``base_vs_preferred``, ``relocation_expected``, ``machine_vs_format``,
``entry_point_in_section``, and ``size_vs_image_extent``. §8.8 adds the
correlation layer this module also produces: the size cross-checks against
the ModuleList record and the section table, the per-section range
observations, the per-descriptor bounds observations, the entry point's
memory-evidence context, and the identity comparisons that only exist
where a second attributable source does.

Evidence boundary
-----------------
``correlate_main_image`` is pure: it takes the profile and the neutral
:mod:`dumpex.core.va_range` value views, performs no I/O, and retains no
parser object. :meth:`ModuleListImage.at_base` is the one helper that
reads raw ``minidump`` module objects, and it reduces them to four
scalars at its own boundary exactly as
:func:`dumpex.core.process_info._module_reference` does.
"""
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType

from dumpex.core.pe_profile import (
    DIRECTORY_NAMES, MEMORY_SOURCE_KINDS, ComponentState, PeImageProfile,
)
from dumpex.core.va_range import (
    CapturedEnumeration, RangeError, VirtualRange, region_containing,
    slice_captured,
)

__all__ = [
    "ObservationState",
    "Observation",
    "ModuleListImage",
    "SectionCorrelation",
    "DirectoryCorrelation",
    "EntryPointContext",
    "CorrelationCoverage",
    "MainImageCorrelation",
    "correlate_main_image",
    "section_interval",
    "OBSERVATION_NAMES",
    "MAX_DISTINCT_PROTECTIONS",
]

_ADDRESS_SPACE = 1 << 64

# COFF ``Machine`` to the optional-header format it fixes (§8.4). ``EBC``
# (``0x0ebc``) is deliberately absent: EFI Byte Code images ship in both
# widths, so a width guess here would manufacture a conflict for a
# legitimate image. A value absent from the table -- ``EBC`` or a
# ``Machine`` the profile has no name for -- leaves the observation
# ``unavailable``, never ``conflict``.
_MACHINE_FORMAT = MappingProxyType({
    0x014c: False,   # I386   -> PE32
    0x01c0: False,   # ARM    -> PE32
    0x01c4: False,   # ARMNT  -> PE32
    0x0200: True,    # IA64   -> PE32+
    0x8664: True,    # AMD64  -> PE32+
    0xaa64: True,    # ARM64  -> PE32+
})
_EBC_MACHINE = 0x0ebc

_SECURITY_DIRECTORY_INDEX = 4

#: How many distinct live-protection names a single section correlation
#: keeps (§10.1's cap on retained records). Real image mappings carry a
#: handful; an attacker-inflated region table cannot make one section
#: retain an unbounded list.
MAX_DISTINCT_PROTECTIONS = 32

#: Every observation name this module can produce, in the order
#: :class:`MainImageCorrelation` lists them. A per-section or
#: per-descriptor family contributes one name; the instance count follows
#: the profile's own section and descriptor counts.
OBSERVATION_NAMES = (
    "base_vs_preferred",
    "relocation_expected",
    "machine_vs_format",
    "entry_point_in_section",
    "size_vs_image_extent",
    "size_vs_modulelist",
    "size_vs_section_extent",
    "identity_time_date_stamp",
    "identity_check_sum",
    "identity_machine",
    "section_range_overflow",
    "section_image_bound",
    "section_overlap",
    "directory_image_bound",
)

# The reason tokens an observation may carry. Every one is dumpex-authored
# and states why the result is what it is -- especially why an
# ``unavailable`` withheld an answer. Kept as a closed set so a typo
# becomes a test failure rather than a silent new vocabulary.
_REASONS = frozenset({
    # shared
    "size_of_image_null",
    "section_alignment_null",
    "profile_field_null",
    # base_vs_preferred
    "delta_recorded",
    "preferred_image_base_null",
    # relocation_expected
    "zero_delta",
    "relocation_delta_null",
    "relocation_conflict",
    "relocation_undetermined",
    "relocation_consistent",
    # machine_vs_format
    "machine_null",
    "format_null",
    "machine_has_no_width",
    "unconstrained_machine",
    "format_matches_machine",
    "format_contradicts_machine",
    # entry_point_in_section
    "entry_point_null",
    "zero_entry_point",
    "entry_point_in_decoded_section",
    "entry_point_outside_every_section",
    "entry_point_table_incomplete",
    # size_vs_image_extent
    "regions_unavailable",
    "regions_lossy",
    "base_not_in_region",
    "base_not_reservation_start",
    "reservation_not_contiguous",
    "segments_unavailable",
    "segments_lossy",
    "segments_overlap_in_extent",
    "short_capture",
    "size_within_base_region",
    "size_within_reservation",
    "size_exceeds_reservation",
    # size_vs_modulelist
    "no_modulelist_entry",
    "modulelist_size_null",
    "size_matches_modulelist",
    "size_matches_modulelist_aligned",
    "size_contradicts_modulelist",
    # size_vs_section_extent
    "no_decoded_sections",
    "section_table_incomplete",
    "size_covers_section_extent",
    "section_extent_exceeds_size",
    # identity_*
    "no_second_source",
    "operand_null",
    "identity_matches",
    "identity_contradicts",
    "header_checksum_absent",
    "machine_no_independent_source",
    # section_range_*
    "section_range_representable",
    "section_range_overflows_address_space",
    "section_within_image_bound",
    "section_escapes_image_bound",
    "section_disjoint_from_others",
    "section_overlaps_another",
    "section_overlap_undetermined",
    "section_field_null",
    # directory_image_bound
    "directory_declared_absent",
    "directory_presence_unknown",
    "descriptor_partial",
    "file_offset_semantics",
    "directory_within_image_bound",
    "directory_escapes_image_bound",
})


class ObservationState(str, Enum):
    """The three values every observation carries (§8.1). Never
    ``trusted``, ``clean``, ``malicious``, ``suspicious``, a score, or a
    confidence (§8.2): structural agreement is not integrity."""
    CONSISTENT = "consistent"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class Observation:
    """One comparison of two established facts.

    ``name`` is one of :data:`OBSERVATION_NAMES`. ``state`` is §8.3's
    three-valued result. ``reason`` is a dumpex-authored token from the
    closed set explaining why the state is what it is. ``sources`` names
    the evidence actually evaluated -- ``"profile.optional_header"``,
    ``"module_list"``, ``"memory_info"``, ``"memory_segments"`` -- so a
    consumer can say which stream a gap belongs to. ``operands`` is the
    exact scalar values compared, JSON-safe and immutable.
    """
    name: str
    state: ObservationState
    reason: str
    sources: "tuple[str, ...]" = ()
    operands: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self):
        if self.name not in OBSERVATION_NAMES:
            raise ValueError(f"unknown observation name: {self.name!r}")
        if not isinstance(self.state, ObservationState):
            raise ValueError(
                f"Observation.state must be an ObservationState, got {self.state!r}")
        if self.reason not in _REASONS:
            raise ValueError(f"unknown observation reason: {self.reason!r}")
        object.__setattr__(self, "sources", tuple(self.sources))
        for token in self.sources:
            if not isinstance(token, str) or not token:
                raise ValueError(f"Observation.sources must be non-empty strings, got {token!r}")
        if not isinstance(self.operands, MappingProxyType):
            object.__setattr__(self, "operands", MappingProxyType(dict(self.operands)))
        for key, value in self.operands.items():
            if not isinstance(key, str):
                raise ValueError(f"Observation.operands keys must be str, got {key!r}")
            if not isinstance(value, (int, float, str, bool, type(None))):
                raise ValueError(
                    f"Observation.operands[{key!r}] must be a JSON-safe scalar, got {value!r}")


def _obs(name, state, reason, *, sources=(), **operands) -> Observation:
    return Observation(name=name, state=state, reason=reason, sources=tuple(sources),
                       operands=MappingProxyType(dict(operands)))


# ── three-valued helpers (§8.3) ────────────────────────────────────────


def _kleene_or(a, b):
    """Three-valued disjunction over ``True`` / ``False`` / ``None``: a
    single true operand is true whatever the other is."""
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


def _checked_end(base: int, length: int) -> "int | None":
    """``base + length`` as an exclusive end when it stays at or below the
    top of the 64-bit space (§2.6), or ``None`` on overflow -- a
    resolution failure, never a wrapped address. An end of exactly
    ``1 << 64`` is the legal exclusive bound of the whole space."""
    end = base + length
    return end if end <= _ADDRESS_SPACE else None


def _checked_va(base: int, offset: int) -> "int | None":
    """``base + offset`` as an addressable location -- strictly inside the
    64-bit space -- or ``None`` when it is not."""
    va = base + offset
    return va if va < _ADDRESS_SPACE else None


def _align_up(value: int, alignment: "int | None") -> "int | None":
    if not isinstance(alignment, int) or alignment <= 0:
        return None
    return ((value + alignment - 1) // alignment) * alignment


def _actual_base_source(profile: PeImageProfile) -> str:
    """The evidence `actual_base` was taken from (§2.1) -- the profile's
    own `source_kind`. Named on every observation whose operands include
    `actual_base` or the delta derived from it, so a consumer can tell a
    PEB base from a module-list base from a scanned candidate."""
    return f"profile.source:{profile.source_kind.value}"


def _usable_views(enumeration: "CapturedEnumeration | None"):
    """The region or segment views only when the table is whole: a
    `None` enumeration, or one whose `skipped` count is non-zero, is not
    usable for a per-address context claim (§8.6.2). A skipped descriptor
    the value model could not represent might be the one covering the
    address in question, so the context is withheld rather than taken
    from an incomplete table."""
    if enumeration is None or enumeration.skipped:
        return None
    return enumeration.views


# ── ModuleList evidence ────────────────────────────────────────────────


@dataclass(frozen=True)
class ModuleListImage:
    """The loader's own ``MODULE`` record for one image, reduced to the
    facts the PE header also declares -- an independently attributable
    second source for a size, a timestamp, and a checksum comparison.

    Every field but ``base_address`` is nullable, and a ``None`` is §1.3's
    ``null``: the record did not carry it, and nothing is guessed. This
    type never wraps a raw ``minidump`` module object.
    """
    base_address: int
    size: "int | None" = None
    time_date_stamp: "int | None" = None
    check_sum: "int | None" = None

    def __post_init__(self):
        if not isinstance(self.base_address, int) or isinstance(self.base_address, bool):
            raise ValueError(
                f"ModuleListImage.base_address must be an int, got {self.base_address!r}")
        if not 0 <= self.base_address < _ADDRESS_SPACE:
            raise ValueError("ModuleListImage.base_address is outside the 64-bit space")
        for name in ("size", "time_date_stamp", "check_sum"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool)
                                      or value < 0):
                raise ValueError(
                    f"ModuleListImage.{name} must be a non-negative int or None, got {value!r}")

    @classmethod
    def at_base(cls, modules, base_address: int) -> "ModuleListImage | None":
        """The ``MODULE`` record registered at exactly ``base_address``,
        reduced to a :class:`ModuleListImage`, or ``None`` when no module
        is registered there or its own base address is not a plain int.

        ``modules`` is any iterable of raw ``minidump`` module objects
        (``dumpex.core.memory.get_modules(mf)``). Exact-base matching, the
        same question :func:`dumpex.core.process_info.resolve_module_by_base`
        asks -- containment would match the main image for any address
        inside it.
        """
        if not isinstance(base_address, int) or isinstance(base_address, bool):
            return None
        for module in modules:
            if getattr(module, "baseaddress", None) != base_address:
                continue
            return cls(
                base_address=base_address,
                size=_non_negative_int(getattr(module, "size", None)),
                time_date_stamp=_non_negative_int(getattr(module, "timestamp", None)),
                check_sum=_non_negative_int(getattr(module, "checksum", None)),
            )
        return None


def _non_negative_int(value) -> "int | None":
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


# ── per-section and per-descriptor correlation ─────────────────────────


@dataclass(frozen=True)
class SectionCorrelation:
    """One decoded section related to the image it belongs to and the
    memory that backs it, in section-table order.

    ``range_overflow`` / ``image_bound`` / ``overlap`` are observations. An
    ``overlap`` conflict carries the lowest-index section it overlaps and
    the exact intersecting RVA range in its ``operands``.
    ``declared_readable`` / ``declared_writable`` / ``declared_executable``
    are the header's own R/W/X bits, surfaced so no consumer repeats the
    bit test. ``live_protections`` is the distinct protection names of the
    captured regions the section's mapped range falls in, ascending --
    context only, never an observation. ``PAGE_EXECUTE_WRITECOPY`` is
    ordinary loader context for an executable image section; a consumer
    must not substring-match ``WRITE`` against these names.
    ``capture_state`` is how much of the section's mapped range the dump
    wrote.
    """
    section_index: int
    name: str
    mapped_range: "VirtualRange | None"
    range_overflow: Observation
    image_bound: Observation
    overlap: Observation
    declared_readable: bool
    declared_writable: bool
    declared_executable: bool
    live_protections: "tuple[str, ...]" = ()
    capture_state: "str | None" = None


@dataclass(frozen=True)
class DirectoryCorrelation:
    """One data-directory descriptor related to the image, in index
    order. All sixteen are always present.

    ``image_bound`` asks whether ``[value, value + size)`` stays inside
    ``[0, SizeOfImage)``. Index 4 (Security) is a file offset, not an RVA
    (§2.5): its ``image_bound`` is ``unavailable`` with reason
    ``file_offset_semantics``, its ``containing_section_index`` is
    ``None``, and it carries no capture claim -- the certificate bytes are
    not part of the image mapping.
    """
    index: int
    name: str
    value_kind: str
    present: "bool | None"
    descriptor_state: str
    image_bound: Observation
    containing_section_index: "int | None" = None
    capture_state: "str | None" = None


@dataclass(frozen=True)
class EntryPointContext:
    """The entry point resolved into the process, and the memory evidence
    around it -- context for §8.5's ``entry_point_in_section``, not a
    second verdict.

    ``entry_point_va`` is ``actual_base + AddressOfEntryPoint``, checked
    for 64-bit overflow (§2.6); ``va_overflow`` says the addition wrapped
    and the VA could not be formed. A zero ``AddressOfEntryPoint`` is "no
    entry point" (§8.5): ``entry_point_rva`` is ``0`` but the VA and every
    memory-context field are ``None`` -- resolving ``actual_base + 0``
    would present the header page as where execution begins.
    ``containing_section_index`` is the decoded section whose mapped
    interval holds the entry RVA. ``region_state`` / ``region_type`` /
    ``region_protection`` are the MemoryInfo facts for the region the
    entry VA falls in; ``None`` when no region does, the region table was
    not supplied, or it was lossy (§8.6.2). Entry point in a
    nonstandard-named section, and an unusual section name, are weak
    context here -- never a conflict on their own.
    """
    entry_point_rva: "int | None"
    entry_point_va: "int | None"
    va_overflow: bool
    containing_section_index: "int | None"
    capture_state: "str | None"
    region_state: "str | None"
    region_type: "str | None"
    region_protection: "str | None"


@dataclass(frozen=True)
class CorrelationCoverage:
    """A plain tally of the observations this correlation produced.

    It is **not** a coverage status and it is **not** a
    ``PROCESS_MAIN_IMAGE_*`` limitation. It changes no exit code and no
    legacy ``--process`` field coverage. Until a public cutover contract
    adopts it, it is a diagnostic count and nothing more.
    """
    total: int
    consistent: int
    conflict: int
    unavailable: int

    @property
    def evaluated(self) -> int:
        """Observations the established facts actually decided -- the
        complement of ``unavailable``."""
        return self.consistent + self.conflict


@dataclass(frozen=True)
class MainImageCorrelation:
    """Every main-image observation for one profile, immutable and
    complete in itself.

    The first five fields are §8.3's frozen set. The rest are §8.8's
    correlation layer. ``sections`` follows the profile's own decoded
    section order; ``directories`` is all sixteen indices in order;
    ``identity`` is the fixed triple of source-attributed comparisons,
    each present even when it can only be ``unavailable`` -- represented,
    never omitted.
    """
    profile_actual_base: int
    base_vs_preferred: Observation
    relocation_expected: Observation
    machine_vs_format: Observation
    entry_point_in_section: Observation
    size_vs_image_extent: Observation
    size_vs_modulelist: Observation
    size_vs_section_extent: Observation
    identity: "tuple[Observation, ...]"
    sections: "tuple[SectionCorrelation, ...]"
    directories: "tuple[DirectoryCorrelation, ...]"
    entry_point: EntryPointContext
    coverage: CorrelationCoverage

    def __post_init__(self):
        if len(self.identity) != 3:
            raise ValueError(
                f"a correlation carries the three identity observations, got {len(self.identity)}")
        for expected, section in enumerate(self.sections):
            if section.section_index != expected:
                raise ValueError("section correlations must be in section-table order")
        if len(self.directories) != len(DIRECTORY_NAMES):
            raise ValueError(
                f"a correlation carries all {len(DIRECTORY_NAMES)} directory correlations, "
                f"got {len(self.directories)}")
        for expected, descriptor in enumerate(self.directories):
            if descriptor.index != expected:
                raise ValueError("directory correlations must be in index order 0..15")

    def all_observations(self) -> "tuple[Observation, ...]":
        """Every :class:`Observation` this result carries, in a
        deterministic order: the frozen five, the two size cross-checks,
        the identity triple, then each section's three and each
        descriptor's one."""
        flat = [
            self.base_vs_preferred, self.relocation_expected, self.machine_vs_format,
            self.entry_point_in_section, self.size_vs_image_extent,
            self.size_vs_modulelist, self.size_vs_section_extent,
        ]
        flat.extend(self.identity)
        for section in self.sections:
            flat.extend((section.range_overflow, section.image_bound, section.overlap))
        for descriptor in self.directories:
            flat.append(descriptor.image_bound)
        return tuple(flat)

    def conflicts(self) -> "tuple[Observation, ...]":
        """The observations that resolved to ``conflict`` -- a
        disagreement between two captured facts, still never a finding."""
        return tuple(o for o in self.all_observations()
                     if o.state is ObservationState.CONFLICT)


# ── the frozen five (§8.3) ─────────────────────────────────────────────


def _observe_base_vs_preferred(profile: PeImageProfile) -> Observation:
    """§8.3: the delta is recorded, never flagged. ``unavailable`` only
    when there is no delta to record."""
    actual = profile.actual_base
    preferred = profile.preferred_image_base
    delta = profile.relocation.relocation_delta
    sources = (_actual_base_source(profile), "profile.optional_header")
    if preferred is None:
        return _obs("base_vs_preferred", ObservationState.UNAVAILABLE,
                    "preferred_image_base_null", sources=sources,
                    actual_base=actual, preferred_image_base=None, relocation_delta=None)
    return _obs("base_vs_preferred", ObservationState.CONSISTENT, "delta_recorded",
                sources=sources,
                actual_base=actual, preferred_image_base=preferred, relocation_delta=delta)


def _observe_relocation_expected(profile: PeImageProfile) -> Observation:
    """§8.3.1: ``conflict`` when the delta is non-zero **and**
    (``relocs_stripped`` **or** not ``basereloc_present``). A zero delta
    settles it on the delta alone."""
    reloc = profile.relocation
    delta = reloc.relocation_delta
    stripped = reloc.relocs_stripped
    present = reloc.basereloc_present
    operands = dict(relocation_delta=delta, relocs_stripped=stripped,
                    basereloc_present=present)
    # The delta alone -- the two bases -- settles both short-circuit rows;
    # the stripped bit and the BASERELOC descriptor are consulted only
    # past them.
    delta_sources = (_actual_base_source(profile), "profile.optional_header")
    sources = (_actual_base_source(profile), "profile.coff_header",
               "profile.optional_header", "profile.directory_descriptors")
    if delta is None:
        return _obs("relocation_expected", ObservationState.UNAVAILABLE,
                    "relocation_delta_null", sources=delta_sources, **operands)
    if delta == 0:
        return _obs("relocation_expected", ObservationState.CONSISTENT, "zero_delta",
                    sources=delta_sources, **operands)
    stripped_disjunct = stripped
    absent_disjunct = None if present is None else (present is False)
    predicate = _kleene_or(stripped_disjunct, absent_disjunct)
    if predicate is True:
        return _obs("relocation_expected", ObservationState.CONFLICT, "relocation_conflict",
                    sources=sources, **operands)
    if predicate is False:
        return _obs("relocation_expected", ObservationState.CONSISTENT, "relocation_consistent",
                    sources=sources, **operands)
    return _obs("relocation_expected", ObservationState.UNAVAILABLE, "relocation_undetermined",
                sources=sources, **operands)


def _observe_machine_vs_format(profile: PeImageProfile) -> Observation:
    """§8.4: each named ``Machine`` fixes one width, except ``EBC`` which
    accepts either. An unnamed value, or either operand ``null``, is
    ``unavailable`` -- never a conflict with an expectation that does not
    exist."""
    machine = profile.machine
    is_plus = profile.is_pe32_plus
    operands = dict(machine=machine, machine_name=profile.machine_name, is_pe32_plus=is_plus)
    sources = ("profile.coff_header", "profile.optional_header")
    if machine is None:
        return _obs("machine_vs_format", ObservationState.UNAVAILABLE, "machine_null",
                    sources=sources, **operands)
    if is_plus is None:
        return _obs("machine_vs_format", ObservationState.UNAVAILABLE, "format_null",
                    sources=sources, **operands)
    if machine == _EBC_MACHINE:
        return _obs("machine_vs_format", ObservationState.CONSISTENT, "unconstrained_machine",
                    sources=sources, **operands)
    expected_plus = _MACHINE_FORMAT.get(machine)
    if expected_plus is None:
        return _obs("machine_vs_format", ObservationState.UNAVAILABLE, "machine_has_no_width",
                    sources=sources, **operands)
    if bool(is_plus) == expected_plus:
        return _obs("machine_vs_format", ObservationState.CONSISTENT, "format_matches_machine",
                    sources=sources, **operands)
    return _obs("machine_vs_format", ObservationState.CONFLICT, "format_contradicts_machine",
                sources=sources, **operands)


def section_interval(section) -> "tuple[int, int] | None":
    """A decoded :class:`~dumpex.core.pe_profile.SectionDescriptor`'s
    mapped RVA interval ``[VirtualAddress, VirtualAddress + VirtualSize)``,
    or ``None`` when ``VirtualSize`` is zero -- a section with no mapped
    extent contains no address and overlaps nothing."""
    if section.virtual_size <= 0:
        return None
    return section.virtual_address, section.virtual_address + section.virtual_size


# In-module callers use the private spelling; `section_interval` is the
# public name an out-of-module consumer resolving an address into a
# section imports.
_section_interval = section_interval


def _observe_entry_point_in_section(profile: PeImageProfile,
                                    containing_index: "int | None") -> Observation:
    """§8.5's first-matching-row table over ``AddressOfEntryPoint`` and
    the section table."""
    entry = profile.address_of_entry_point
    table_state = profile.components.section_table
    operands = dict(address_of_entry_point=entry,
                    section_table_state=None if table_state is None else table_state.value,
                    containing_section_index=containing_index)
    # The field alone settles the `null` and zero rows (§8.5); the
    # section table is only consulted past them.
    field_only = ("profile.optional_header",)
    sources = ("profile.optional_header", "profile.section_table")
    if entry is None:
        return _obs("entry_point_in_section", ObservationState.UNAVAILABLE,
                    "entry_point_null", sources=field_only, **operands)
    if entry == 0:
        return _obs("entry_point_in_section", ObservationState.CONSISTENT,
                    "zero_entry_point", sources=field_only, **operands)
    if containing_index is not None:
        return _obs("entry_point_in_section", ObservationState.CONSISTENT,
                    "entry_point_in_decoded_section", sources=sources, **operands)
    if table_state is ComponentState.COMPLETE or table_state is ComponentState.DECLARED_ABSENT:
        return _obs("entry_point_in_section", ObservationState.CONFLICT,
                    "entry_point_outside_every_section", sources=sources, **operands)
    return _obs("entry_point_in_section", ObservationState.UNAVAILABLE,
                "entry_point_table_incomplete", sources=sources, **operands)


# ── size_vs_image_extent (§8.6) ───────────────────────────────────────


def _mapped_extent(profile: PeImageProfile,
                   regions: "CapturedEnumeration | None"):
    """§8.6.1's mapped extent as ``(VirtualRange, base_region)``, or
    ``(None, reason)`` -- every failure is a reason not to answer, never a
    conflict."""
    if regions is None:
        return None, "regions_unavailable"
    if regions.skipped:
        return None, "regions_lossy"
    base = profile.actual_base
    base_region = region_containing(base, regions.views)
    if base_region is None:
        return None, "base_not_in_region"
    if base_region.allocation_base is None or base_region.allocation_base != base:
        return None, "base_not_reservation_start"
    members = sorted(
        (r for r in regions.views if r.allocation_base == base),
        key=lambda r: (r.base_address, r.end_address))
    cursor = base
    for region in members:
        if region.base_address > cursor:
            return None, "reservation_not_contiguous"
        cursor = max(cursor, region.end_address)
    try:
        return VirtualRange.from_endpoints(base, cursor), base_region
    except RangeError:
        return None, "reservation_not_contiguous"


def _captured_extent(mapped: VirtualRange, segments: "CapturedEnumeration | None"):
    """§8.6.2's captured extent as a ``VirtualRange`` (possibly shorter
    than ``mapped``), or ``(None, reason)``."""
    if segments is None:
        return None, "segments_unavailable"
    if segments.skipped:
        return None, "segments_lossy"
    clipped = []
    for segment in segments.views:
        piece = segment.range.intersection(mapped)
        if piece is not None:
            clipped.append(piece)
    clipped.sort(key=lambda r: (r.base_address, r.end_address))
    cursor = mapped.base_address
    for piece in clipped:
        if piece.base_address < cursor:
            return None, "segments_overlap_in_extent"
        cursor = piece.end_address
    # The captured extent is the contiguous prefix of ``mapped`` the
    # clipped spans tile from its base.
    run = mapped.base_address
    for piece in clipped:
        if piece.base_address != run:
            break
        run = piece.end_address
    length = run - mapped.base_address
    if length <= 0:
        return None, "short_capture"
    return VirtualRange(mapped.base_address, length), None


def _observe_size_vs_image_extent(profile: PeImageProfile,
                                  regions: "CapturedEnumeration | None",
                                  segments: "CapturedEnumeration | None") -> Observation:
    size = profile.size_of_image
    # The mapped extent is anchored at ``actual_base``, so that fact's
    # provenance is part of the evidence.
    base_source = _actual_base_source(profile)
    sources = (base_source, "profile.optional_header", "memory_info", "memory_segments")
    operands = dict(size_of_image=size)
    if size is None:
        # The region and segment tables are never consulted past this
        # short-circuit, so they are not named as evidence.
        return _obs("size_vs_image_extent", ObservationState.UNAVAILABLE,
                    "size_of_image_null", sources=("profile.optional_header",), **operands)
    mapped, base_region = _mapped_extent(profile, regions)
    if mapped is None:
        # The segment table is reached only once a mapped extent exists.
        return _obs("size_vs_image_extent", ObservationState.UNAVAILABLE, base_region,
                    sources=(base_source, "profile.optional_header", "memory_info"), **operands)
    captured, reason = _captured_extent(mapped, segments)
    if captured is None:
        return _obs("size_vs_image_extent", ObservationState.UNAVAILABLE, reason,
                    sources=sources, mapped_extent_bytes=mapped.size, **operands)
    if captured.size < mapped.size:
        return _obs("size_vs_image_extent", ObservationState.UNAVAILABLE, "short_capture",
                    sources=sources, mapped_extent_bytes=mapped.size,
                    captured_extent_bytes=captured.size, **operands)
    size_end = _checked_end(profile.actual_base, size)
    operands = dict(size_of_image=size, mapped_extent_bytes=mapped.size,
                    base_region_bytes=base_region.size)
    if size_end is not None and size_end <= base_region.end_address:
        return _obs("size_vs_image_extent", ObservationState.CONSISTENT,
                    "size_within_base_region", sources=sources, **operands)
    if size_end is not None and size_end <= mapped.end_address:
        return _obs("size_vs_image_extent", ObservationState.CONSISTENT,
                    "size_within_reservation", sources=sources, **operands)
    return _obs("size_vs_image_extent", ObservationState.CONFLICT,
                "size_exceeds_reservation", sources=sources, **operands)


# ── size cross-checks (§8.8) ──────────────────────────────────────────


def _observe_size_vs_modulelist(profile: PeImageProfile,
                                module: "ModuleListImage | None") -> Observation:
    """§8.8: ``SizeOfImage`` against the loader's ``MODULE.SizeOfImage``.
    Documented alignment is normalized before a conflict is declared; an
    unknown ``SectionAlignment`` that leaves a raw mismatch undecided is
    ``unavailable``, not ``conflict``."""
    header = profile.size_of_image
    sources = ("profile.optional_header", "module_list")
    if module is None:
        return _obs("size_vs_modulelist", ObservationState.UNAVAILABLE, "no_modulelist_entry",
                    sources=sources, size_of_image=header, modulelist_size=None)
    loader = module.size
    align = profile.section_alignment
    operands = dict(size_of_image=header, modulelist_size=loader, section_alignment=align)
    if header is None:
        return _obs("size_vs_modulelist", ObservationState.UNAVAILABLE, "size_of_image_null",
                    sources=sources, **operands)
    if loader is None:
        return _obs("size_vs_modulelist", ObservationState.UNAVAILABLE, "modulelist_size_null",
                    sources=sources, **operands)
    if header == loader:
        return _obs("size_vs_modulelist", ObservationState.CONSISTENT, "size_matches_modulelist",
                    sources=sources, **operands)
    aligned_header = _align_up(header, align)
    aligned_loader = _align_up(loader, align)
    if aligned_header is None or aligned_loader is None:
        return _obs("size_vs_modulelist", ObservationState.UNAVAILABLE, "section_alignment_null",
                    sources=sources, **operands)
    if aligned_header == aligned_loader:
        return _obs("size_vs_modulelist", ObservationState.CONSISTENT,
                    "size_matches_modulelist_aligned", sources=sources, **operands)
    return _obs("size_vs_modulelist", ObservationState.CONFLICT, "size_contradicts_modulelist",
                sources=sources, **operands)


def _observe_size_vs_section_extent(profile: PeImageProfile) -> Observation:
    """§8.8: ``SizeOfImage`` against the extent the section table itself
    describes. ``conflict`` when a decoded section's own
    ``[VirtualAddress, VirtualAddress + VirtualSize)`` reaches past
    ``SizeOfImage`` -- the raw section extent, not an alignment-rounded
    one; §8.8.3 reserves alignment normalization for the ModuleList size
    comparison. Sections that all fit are ``consistent`` only once the
    table is ``complete``; a ``SizeOfImage`` larger than the extent is
    legal padding, never a conflict."""
    header = profile.size_of_image
    table_state = profile.components.section_table
    sections = profile.sections
    sources = ("profile.optional_header", "profile.section_table")
    operands = dict(size_of_image=header,
                    section_table_state=None if table_state is None else table_state.value)
    if header is None:
        return _obs("size_vs_section_extent", ObservationState.UNAVAILABLE, "size_of_image_null",
                    sources=("profile.optional_header",), **operands)
    if not sections:
        return _obs("size_vs_section_extent", ObservationState.UNAVAILABLE, "no_decoded_sections",
                    sources=sources, **operands)
    extent = max(s.virtual_address + s.virtual_size for s in sections)
    operands["section_extent"] = extent
    if extent > header:
        return _obs("size_vs_section_extent", ObservationState.CONFLICT,
                    "section_extent_exceeds_size", sources=sources, **operands)
    if table_state is not ComponentState.COMPLETE:
        return _obs("size_vs_section_extent", ObservationState.UNAVAILABLE,
                    "section_table_incomplete", sources=sources, **operands)
    return _obs("size_vs_section_extent", ObservationState.CONSISTENT,
                "size_covers_section_extent", sources=sources, **operands)


# ── identity comparisons (§8.8) ───────────────────────────────────────


def _observe_identity(name: str, header_value, loader_value, *,
                      sources, reason_null="operand_null", **extra) -> Observation:
    operands = dict(header_value=header_value, module_list_value=loader_value, **extra)
    if header_value is None or loader_value is None:
        return _obs(name, ObservationState.UNAVAILABLE, reason_null, sources=sources, **operands)
    if header_value == loader_value:
        return _obs(name, ObservationState.CONSISTENT, "identity_matches",
                    sources=sources, **operands)
    return _obs(name, ObservationState.CONFLICT, "identity_contradicts",
                sources=sources, **operands)


def _identity_observations(profile: PeImageProfile,
                           module: "ModuleListImage | None") -> "tuple[Observation, ...]":
    loader_ts = module.time_date_stamp if module is not None else None
    loader_cs = module.check_sum if module is not None else None
    ts = _observe_identity(
        "identity_time_date_stamp", profile.time_date_stamp, loader_ts,
        sources=("profile.coff_header", "module_list"),
        reason_null="no_second_source" if module is None else "operand_null")
    header_cs = profile.checksum
    if header_cs == 0:
        # A zero optional-header ``CheckSum`` is "not checksummed", the
        # common case for a linked image. Comparing it to the loader's
        # real checksum would manufacture a conflict from a field the
        # image never populated.
        cs = _obs("identity_check_sum", ObservationState.UNAVAILABLE, "header_checksum_absent",
                  sources=("profile.optional_header", "module_list"),
                  header_value=0, module_list_value=loader_cs)
    else:
        cs = _observe_identity(
            "identity_check_sum", header_cs, loader_cs,
            sources=("profile.optional_header", "module_list"),
            reason_null="no_second_source" if module is None else "operand_null")
    # The dump's SystemInfo processor architecture is not an independent
    # source for the main image's ``Machine``: a WOW64 process runs a
    # 32-bit ``I386`` image while SystemInfo reports the 64-bit host, so
    # that comparison would conflict on every WOW64 process. With no
    # second attributable source the observation is represented and
    # ``unavailable``.
    machine = _obs("identity_machine", ObservationState.UNAVAILABLE,
                   "machine_no_independent_source", sources=("profile.coff_header",),
                   machine=profile.machine, machine_name=profile.machine_name)
    return (ts, cs, machine)


# ── per-section correlation (§8.8) ────────────────────────────────────


def _correlate_section(section, profile: PeImageProfile,
                       region_views, segment_views,
                       other_sections: "list[tuple[int, int, int]]") -> SectionCorrelation:
    base = profile.actual_base
    size = profile.size_of_image
    va = section.virtual_address
    vsize = section.virtual_size
    index = section.section_index
    rva_source = ("profile.section_table",)
    # The overflow check resolves the section RVA against ``actual_base``,
    # so that fact's provenance is evidence for it.
    overflow_source = (_actual_base_source(profile), "profile.section_table")

    rva_end = va + vsize
    mapped_start = _checked_va(base, va)
    mapped_end = None if mapped_start is None else _checked_end(base, rva_end)
    if mapped_start is not None and mapped_end is not None and mapped_end > mapped_start:
        try:
            mapped_range = VirtualRange.from_endpoints(mapped_start, mapped_end)
        except RangeError:
            mapped_range = None
    else:
        mapped_range = None

    if mapped_start is None or mapped_end is None:
        range_overflow = _obs("section_range_overflow", ObservationState.CONFLICT,
                              "section_range_overflows_address_space", sources=overflow_source,
                              section_index=index, virtual_address=va, virtual_size=vsize,
                              actual_base=base)
    else:
        range_overflow = _obs("section_range_overflow", ObservationState.CONSISTENT,
                              "section_range_representable", sources=overflow_source,
                              section_index=index, virtual_address=va, virtual_size=vsize,
                              actual_base=base)

    if size is None:
        image_bound = _obs("section_image_bound", ObservationState.UNAVAILABLE,
                           "size_of_image_null", sources=("profile.optional_header",
                                                          "profile.section_table"),
                           section_index=index, virtual_address=va, virtual_size=vsize,
                           size_of_image=None)
    else:
        escapes = rva_end > size if vsize > 0 else va >= size
        image_bound = _obs(
            "section_image_bound",
            ObservationState.CONFLICT if escapes else ObservationState.CONSISTENT,
            "section_escapes_image_bound" if escapes else "section_within_image_bound",
            sources=("profile.optional_header", "profile.section_table"),
            section_index=index, virtual_address=va, virtual_size=vsize, size_of_image=size)

    interval = _section_interval(section)
    table_state = profile.components.section_table
    overlap_operands = dict(section_index=index, virtual_address=va, virtual_size=vsize)
    if interval is None:
        overlap = _obs("section_overlap", ObservationState.CONSISTENT,
                       "section_disjoint_from_others", sources=rva_source,
                       section_index=index, virtual_address=va, virtual_size=0)
    else:
        # The lowest-index section this one overlaps -- a bounded,
        # deterministically ordered counterpart -- with the exact
        # intersecting range, so a consumer explains the conflict
        # without recomputing it.
        clash = next(
            ((oi, os, oe) for oi, os, oe in sorted(other_sections)
             if os < interval[1] and interval[0] < oe), None)
        if clash is not None:
            oi, os, oe = clash
            overlap = _obs("section_overlap", ObservationState.CONFLICT,
                           "section_overlaps_another", sources=rva_source,
                           overlaps_section_index=oi,
                           overlap_start=max(interval[0], os),
                           overlap_end=min(interval[1], oe), **overlap_operands)
        elif table_state is ComponentState.COMPLETE:
            overlap = _obs("section_overlap", ObservationState.CONSISTENT,
                           "section_disjoint_from_others", sources=rva_source,
                           **overlap_operands)
        else:
            overlap = _obs("section_overlap", ObservationState.UNAVAILABLE,
                           "section_overlap_undetermined", sources=rva_source,
                           **overlap_operands)

    live_protections = ()
    capture_state = None
    if mapped_range is not None:
        if region_views is not None:
            names = []
            for region in region_views:
                if region.range.overlaps(mapped_range) and region.protection is not None:
                    if region.protection not in names:
                        names.append(region.protection)
                    if len(names) >= MAX_DISTINCT_PROTECTIONS:
                        break
            live_protections = tuple(sorted(names))
        if segment_views is not None:
            capture_state = slice_captured(mapped_range, segment_views).state.value

    return SectionCorrelation(
        section_index=index,
        name=section.name,
        mapped_range=mapped_range,
        range_overflow=range_overflow,
        image_bound=image_bound,
        overlap=overlap,
        declared_readable=section.is_readable,
        declared_writable=section.is_writable,
        declared_executable=section.is_executable,
        live_protections=live_protections,
        capture_state=capture_state,
    )


# ── per-descriptor correlation (§8.8) ────────────────────────────────


def _correlate_directory(descriptor, profile: PeImageProfile,
                         segment_views) -> DirectoryCorrelation:
    index = descriptor.index
    size = profile.size_of_image
    value = descriptor.value
    dvalue_size = descriptor.size
    base = profile.actual_base

    if index == _SECURITY_DIRECTORY_INDEX:
        image_bound = _obs("directory_image_bound", ObservationState.UNAVAILABLE,
                           "file_offset_semantics", sources=("profile.directory_descriptors",),
                           index=index, value=value, size=dvalue_size, value_kind="file_offset")
        return DirectoryCorrelation(
            index=index, name=descriptor.name, value_kind=descriptor.value_kind,
            present=descriptor.present, descriptor_state=descriptor.state.value,
            image_bound=image_bound, containing_section_index=None, capture_state=None)

    descriptor_only = ("profile.directory_descriptors",)
    with_size = ("profile.optional_header", "profile.directory_descriptors")
    operands = dict(index=index, value=value, size=dvalue_size, size_of_image=size)
    if descriptor.present is False:
        image_bound = _obs("directory_image_bound", ObservationState.UNAVAILABLE,
                           "directory_declared_absent", sources=descriptor_only, **operands)
    elif descriptor.present is None:
        image_bound = _obs("directory_image_bound", ObservationState.UNAVAILABLE,
                           "directory_presence_unknown", sources=descriptor_only, **operands)
    elif value is None or dvalue_size is None:
        image_bound = _obs("directory_image_bound", ObservationState.UNAVAILABLE,
                           "descriptor_partial", sources=descriptor_only, **operands)
    elif size is None:
        image_bound = _obs("directory_image_bound", ObservationState.UNAVAILABLE,
                           "size_of_image_null", sources=with_size, **operands)
    else:
        end = value + dvalue_size
        escapes = value >= size or end > size
        image_bound = _obs(
            "directory_image_bound",
            ObservationState.CONFLICT if escapes else ObservationState.CONSISTENT,
            "directory_escapes_image_bound" if escapes else "directory_within_image_bound",
            sources=with_size, **operands)

    containing = None
    if value is not None:
        for section in profile.sections:
            interval = _section_interval(section)
            if interval is not None and interval[0] <= value < interval[1]:
                containing = section.section_index
                break

    capture_state = None
    if segment_views is not None and value is not None and dvalue_size is not None \
            and dvalue_size > 0:
        start = _checked_va(base, value)
        span_end = None if start is None else _checked_end(base, value + dvalue_size)
        if start is not None and span_end is not None and span_end > start:
            try:
                span = VirtualRange.from_endpoints(start, span_end)
            except RangeError:
                span = None
            if span is not None:
                capture_state = slice_captured(span, segment_views).state.value

    return DirectoryCorrelation(
        index=index, name=descriptor.name, value_kind=descriptor.value_kind,
        present=descriptor.present, descriptor_state=descriptor.state.value,
        image_bound=image_bound, containing_section_index=containing,
        capture_state=capture_state)


# ── entry-point context (§8.5, §8.8) ─────────────────────────────────


def _entry_point_context(profile: PeImageProfile, region_views, segment_views,
                         containing_index: "int | None") -> EntryPointContext:
    entry = profile.address_of_entry_point
    base = profile.actual_base
    # A zero ``AddressOfEntryPoint`` means "no entry point" (§8.5) --
    # resource-only DLLs and ``.mui`` modules carry it -- so it resolves
    # to no VA and no memory context; reading ``actual_base`` there would
    # present the header page as where execution begins.
    resolvable = entry is not None and entry != 0
    va = _checked_va(base, entry) if resolvable else None
    va_overflow = resolvable and va is None

    capture_state = None
    region_state = region_type = region_protection = None
    if va is not None:
        if segment_views is not None:
            try:
                probe = VirtualRange(va, 1)
            except RangeError:
                probe = None
            if probe is not None:
                capture_state = slice_captured(probe, segment_views).state.value
        if region_views is not None:
            region = region_containing(va, region_views)
            if region is not None:
                region_state = region.state
                region_type = region.type
                region_protection = region.protection

    return EntryPointContext(
        entry_point_rva=entry,
        entry_point_va=va,
        va_overflow=va_overflow,
        containing_section_index=containing_index,
        capture_state=capture_state,
        region_state=region_state,
        region_type=region_type,
        region_protection=region_protection,
    )


def _containing_section_index(profile: PeImageProfile) -> "int | None":
    entry = profile.address_of_entry_point
    if entry is None or entry == 0:
        return None
    for section in profile.sections:
        interval = _section_interval(section)
        if interval is not None and interval[0] <= entry < interval[1]:
            return section.section_index
    return None


# ── the public entry point ───────────────────────────────────────────


_EMPTY_COVERAGE = CorrelationCoverage(total=0, consistent=0, conflict=0, unavailable=0)


def _coverage(observations) -> CorrelationCoverage:
    consistent = conflict = unavailable = 0
    for observation in observations:
        if observation.state is ObservationState.CONSISTENT:
            consistent += 1
        elif observation.state is ObservationState.CONFLICT:
            conflict += 1
        else:
            unavailable += 1
    return CorrelationCoverage(
        total=consistent + conflict + unavailable,
        consistent=consistent, conflict=conflict, unavailable=unavailable)


def correlate_main_image(
    profile: PeImageProfile,
    *,
    regions: "CapturedEnumeration | None" = None,
    segments: "CapturedEnumeration | None" = None,
    module_list_image: "ModuleListImage | None" = None,
) -> MainImageCorrelation:
    """Correlate one memory-sourced :class:`PeImageProfile` against the
    process memory evidence around it, and return every §8.3 and §8.8
    observation.

    ``regions`` and ``segments`` are the neutral
    :class:`~dumpex.core.va_range.CapturedEnumeration` views --
    ``enumerate_captured_regions(mf)`` and
    ``enumerate_captured_segments(mf)``. ``None`` for either means the
    stream was absent or failed to parse; a non-zero ``skipped`` count
    makes it lossy. Either way every observation that needed the table is
    ``unavailable`` and every per-address context drawn from it is
    withheld, never a PE defect. ``module_list_image`` is the
    loader's own record for this image, from
    :meth:`ModuleListImage.at_base`; ``None`` when no module is registered
    at the profile's base.

    Never raises for hostile or truncated profile content -- the profile
    already sanitized it. A caller error does raise: a ``disk_reference``
    profile has no ``actual_base`` to correlate, and a
    ``module_list_image`` for a different base is a mismatched pairing.
    """
    if not isinstance(profile, PeImageProfile):
        raise ValueError(f"profile must be a PeImageProfile, got {type(profile).__name__}")
    if profile.source_kind not in MEMORY_SOURCE_KINDS:
        raise ValueError(
            f"{profile.source_kind.value} has no actual_base to correlate against "
            "process memory evidence (§2.1)")
    for name, value in (("regions", regions), ("segments", segments)):
        if value is not None and not isinstance(value, CapturedEnumeration):
            raise ValueError(
                f"{name} must be a CapturedEnumeration or None, got {type(value).__name__}")
    if module_list_image is not None:
        if not isinstance(module_list_image, ModuleListImage):
            raise ValueError(
                f"module_list_image must be a ModuleListImage or None, got "
                f"{type(module_list_image).__name__}")
        if module_list_image.base_address != profile.actual_base:
            raise ValueError(
                "module_list_image.base_address must be the profile's actual_base "
                f"(0x{profile.actual_base:x}), got 0x{module_list_image.base_address:x}")

    containing_index = _containing_section_index(profile)
    # A lossy table is not usable evidence for a per-address context claim
    # (§8.6.2); the extent observation keeps the full enumeration so it
    # can still distinguish "lossy" from "absent".
    region_views = _usable_views(regions)
    segment_views = _usable_views(segments)

    base_vs_preferred = _observe_base_vs_preferred(profile)
    relocation_expected = _observe_relocation_expected(profile)
    machine_vs_format = _observe_machine_vs_format(profile)
    entry_point_in_section = _observe_entry_point_in_section(profile, containing_index)
    size_vs_image_extent = _observe_size_vs_image_extent(profile, regions, segments)
    size_vs_modulelist = _observe_size_vs_modulelist(profile, module_list_image)
    size_vs_section_extent = _observe_size_vs_section_extent(profile)
    identity = _identity_observations(profile, module_list_image)

    all_intervals = []
    for section in profile.sections:
        interval = _section_interval(section)
        if interval is not None:
            all_intervals.append((section.section_index, interval[0], interval[1]))

    section_correlations = []
    for section in profile.sections:
        others = [triple for triple in all_intervals if triple[0] != section.section_index]
        section_correlations.append(
            _correlate_section(section, profile, region_views, segment_views, others))

    directory_correlations = tuple(
        _correlate_directory(descriptor, profile, segment_views)
        for descriptor in profile.directories)

    entry_point = _entry_point_context(profile, region_views, segment_views, containing_index)

    result = MainImageCorrelation(
        profile_actual_base=profile.actual_base,
        base_vs_preferred=base_vs_preferred,
        relocation_expected=relocation_expected,
        machine_vs_format=machine_vs_format,
        entry_point_in_section=entry_point_in_section,
        size_vs_image_extent=size_vs_image_extent,
        size_vs_modulelist=size_vs_modulelist,
        size_vs_section_extent=size_vs_section_extent,
        identity=identity,
        sections=tuple(section_correlations),
        directories=directory_correlations,
        entry_point=entry_point,
        coverage=_EMPTY_COVERAGE,
    )
    # ``all_observations()`` is the one definition of the flattened set
    # and its order, so the tally is built from it rather than from a
    # second list assembled here.
    return replace(result, coverage=_coverage(result.all_observations()))
