"""Immutable, capture-aware PE image profile collection.

Implements the collector half of
``docs/developer/pe_image_profile_contract.md``: a staged, bounded,
reader-injected acquisition of one image's header structures into a single
frozen :class:`PeImageProfile` that Recon, Report, and Hunt consumers share
instead of each projecting ``dumpex.core.pe_utils.parse_pe_header()``'s dict
into its own shape.

What this module is, and is not
-------------------------------
It is a **raw profile** in the contract's §1.1 sense: bytes actually read,
decoded fields, per-component state, and the exact byte ranges nothing
looked at. It holds no comparison, no interpretation, and no severity. The
derived consistency observations of §8, the profile cache of §7, and the
console/structured projections of §9 are separate consumers built on top of
what this module returns.

Acquisition is **pure with respect to I/O**: every byte comes from a
caller-supplied ``read(addr, size) -> bytes`` callback, so one collector
serves a PEB image base, a module-list entry, and a scanned memory
candidate alike, and is testable against a synthetic image with no
minidump fixture. ``dumpex.core.va_range`` is the only capture model; a
caller that has a dump's segment table hands the matching
:class:`~dumpex.core.va_range.CapturedSlice` in so the profile can keep
§5.1's three independent byte facts apart.

The ``disk_reference`` source of §2.1 is deliberately not collected here.
Its bytes are indexed by file offset, and §5.1.1 gives it its own
provenance type rather than a ``VirtualRange``; a collector that accepted
it would have to put a file offset into the virtual-address model this
module is built on.

Vocabulary
----------
Component
    One independently acquirable part of the image (§1.2). Six of them,
    each carrying exactly one :class:`ComponentState`.

Stage
    One step of §6.1's acquisition ladder. A consumer needing only image
    identity requests stage 1 and never pays for a section table; the
    stage it requested is what selects the components its profile state is
    folded over (§5.4.1).

Bounded stop
    Acquisition ending because one of dumpex's own budgets was reached
    rather than because the image said so (§6.2). A stop is always
    attributed, and never yields ``malformed`` or ``declared_absent``.

Unexamined range
    Bytes of a locatable component that nothing looked at (§5.2). It is a
    statement about bytes only: never that the image is intact there, and
    never that it is damaged there.
"""
from dataclasses import dataclass
from enum import Enum, IntEnum
import struct

from dumpex.core.pe_utils import (
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    _KNOWN_MACHINES, _MAX_SECTIONS,
)
from dumpex.core.va_range import CapturedSlice, ReadSlice, VirtualRange

__all__ = [
    "ComponentState",
    "PeStage",
    "SourceKind",
    "ModuleIdentity",
    "BoundedStop",
    "DirectoryDescriptor",
    "SectionDescriptor",
    "ComponentStates",
    "RelocationContext",
    "PeImageProfile",
    "collect_pe_image_profile",
    "in_scope_components",
    "DIRECTORY_NAMES",
    "MAX_DIRECTORY_COUNT",
    "MAX_E_LFANEW",
    "MAX_STRING_BYTES",
    "PE_HEADER_READ_MAX",
    "PE_HEADER_READ_OPERATIONS_MAX",
    "PEB_SOURCE_IDENTITY",
]


# ── Frozen constants (§1.5) ─────────────────────────────────────────────
# Four different kinds of limit, producing four different outcomes.
# Nothing below may treat one as another.

# Acquisition budgets -- work dumpex declines to do. Reaching one is a
# bounded stop (§6.2), never a claim about the image.
PE_HEADER_READ_MAX = 4096              # bytes requested at an image base
MAX_E_LFANEW = 4096                    # how far past the image start e_lfanew is followed

# The second cumulative budget. A byte budget alone does not catch a
# pathological many-tiny-reads pattern: thousands of one-byte reads stay
# far under the byte ceiling while still hanging a collection. It is set
# well above what any segmented reader needs -- a header split across
# several captured segments costs one read per segment, not one per byte
# -- so reaching it means the reader is trickling, not that the header was
# fragmented.
PE_HEADER_READ_OPERATIONS_MAX = 1024

# Projection scope -- meaning this contract does not define. Reaching it
# is recorded as `unprojected_directory_count`, not as a stop (§4.5).
MAX_DIRECTORY_COUNT = 16

# Retention bound -- how much of one already-established string the
# profile keeps. It changes no component state and produces no unexamined
# range; its whole attribution is a per-field `truncated` flag (§10.3.1).
MAX_STRING_BYTES = 4096

# The structural constraint on the section count is `_MAX_SECTIONS`,
# imported from `pe_utils` so the format cap has one definition. Exceeding
# it is `malformed` -- a fact about the image, not about dumpex.

_ADDRESS_SPACE = 1 << 64

_DOS_HEADER_SIZE = 0x40
_E_LFANEW_OFFSET = 0x3C
_MZ_SIGNATURE = b"MZ"

_PE_SIGNATURE = b"PE\x00\x00"
_PE_SIGNATURE_SIZE = 4
_COFF_FIELDS_SIZE = 20
_COFF_COMPONENT_SIZE = _PE_SIGNATURE_SIZE + _COFF_FIELDS_SIZE

# The §3.3 fixed fields end at `DllCharacteristics` + 2. `NumberOfRvaAndSizes`
# and the array it counts belong to `directory_array` (§1.2), so the two
# components partition the optional header's bytes rather than overlapping
# on those four.
_OPTIONAL_FIXED_FIELDS_SIZE = 72

# Where a format's fixed portion ends -- the §3.3.1 minimum a header must
# declare to be the format its own `Magic` names, and the offset the
# directory array starts at (§2.4).
_FIXED_PORTION_PE32 = 96
_FIXED_PORTION_PE32_PLUS = 112

_DIRECTORY_DESCRIPTOR_SIZE = 8
_SECTION_HEADER_SIZE = 40

_MAGIC_PE32 = 0x10b
_MAGIC_PE32_PLUS = 0x20b

IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040

#: The sixteen indices this contract assigns meanings to, in index order
#: (§4.2). Index 4 is the one descriptor whose first value is a file
#: offset rather than an RVA (§2.5).
DIRECTORY_NAMES = (
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
    "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG",
    "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
)

_SECURITY_DIRECTORY_INDEX = 4
_BASERELOC_DIRECTORY_INDEX = 5

# The three indices the format constrains in their own right (§4.3.1).
# Every other index can reach `unavailable`, `declared_absent`, `partial`,
# or `complete`, and cannot reach `malformed`: this table is the only
# source of a malformed descriptor state.
_ARCHITECTURE_DIRECTORY_INDEX = 7
_GLOBALPTR_DIRECTORY_INDEX = 8
_RESERVED_DIRECTORY_INDEX = 15


class ComponentState(str, Enum):
    """The five states a component carries (§1.2).

    Three rules bind the vocabulary. Uncaptured bytes never support a
    ``MALFORMED`` and never a ``DECLARED_ABSENT``. A ``DECLARED_ABSENT``
    requires a captured owner that positively denies the component. A
    ``MALFORMED`` requires every byte the defect rests on to have been
    read -- unread bytes elsewhere in the component neither create a
    defect nor soften one that was fully read.
    """
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    MALFORMED = "malformed"
    DECLARED_ABSENT = "declared_absent"


class PeStage(IntEnum):
    """§6.1's acquisition ladder. Stage *n* requires stage *n-1*: a stage
    that cannot start because the previous one did not deliver the field
    locating its bytes yields ``UNAVAILABLE`` components, never
    ``MALFORMED``."""
    DOS = 0
    COFF = 1
    OPTIONAL = 2
    SECTIONS = 3


def _check_stage(value, name: str = "requested_stage") -> PeStage:
    """Coerce ``value`` to a :class:`PeStage`, refusing anything that is
    not one or a plain integer naming one.

    ``PeStage(value)`` alone accepts ``True`` and ``1.0`` and silently
    returns ``COFF`` for both, because an ``IntEnum`` looks its members up
    by equality. The stage is not an incidental parameter: it selects how
    far acquisition goes and which components the profile's own state is
    folded over (§5.4.1), so a mistyped argument would quietly change what
    the returned state means rather than saying the call was wrong.
    """
    if isinstance(value, PeStage):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        try:
            return PeStage(value)
        except ValueError:
            pass
    raise ValueError(
        f"{name} must be a PeStage or an int in "
        f"{PeStage.DOS.value}..{PeStage.SECTIONS.value}, got {value!r}")


class SourceKind(str, Enum):
    """Where a profile came from (§2.1). Never promoted: a profile
    acquired from a module-list entry stays one even when its
    ``actual_base`` equals the PEB-reported image base."""
    PEB_IMAGE_BASE = "peb_image_base"
    MODULE_LIST_ENTRY = "module_list_entry"
    MEMORY_CANDIDATE = "memory_candidate"
    DISK_REFERENCE = "disk_reference"


#: The source kinds indexed by target-process virtual address, which is
#: the address space this collector works in. ``DISK_REFERENCE`` is
#: indexed by file offset and carries §5.1.1's own provenance type.
MEMORY_SOURCE_KINDS = frozenset({
    SourceKind.PEB_IMAGE_BASE,
    SourceKind.MODULE_LIST_ENTRY,
    SourceKind.MEMORY_CANDIDATE,
})

#: The one identity a ``peb_image_base`` source can have -- a process has
#: one PEB, so the identity is a constant rather than a discriminator
#: (§7.1.1).
PEB_SOURCE_IDENTITY = "peb"

# What makes a string a token rather than a name: dumpex authors it, it is
# short, and it holds no separator. Both bounds are enforced, so no
# attacker-controlled path can pass as one.
_MAX_SOURCE_TOKEN_LENGTH = 64
_SOURCE_TOKEN_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")

#: Which components each stage acquires (§6.1's ``Yields``). The rollup
#: folds the cumulative yields of stages ``0..requested_stage`` (§5.4.1).
_STAGE_YIELDS = {
    PeStage.DOS: ("dos_header",),
    PeStage.COFF: ("coff_header",),
    PeStage.OPTIONAL: ("optional_header", "directory_array", "directory_descriptors"),
    PeStage.SECTIONS: ("section_table",),
}


def in_scope_components(stage: PeStage) -> "tuple[str, ...]":
    """The component names a request for ``stage`` covers -- the
    cumulative yields of stages ``0..stage`` (§5.4.1), in §1.2's order.

    ``directory_descriptors`` is one member here, never sixteen: its own
    state is the fold of its sixteen descriptors, and that single result
    is what enters the profile fold (§5.4.3.1).
    """
    stage = _check_stage(stage, "stage")
    names: "list[str]" = []
    for step in PeStage:
        if step > stage:
            break
        names.extend(_STAGE_YIELDS[step])
    return tuple(names)


@dataclass(frozen=True)
class ModuleIdentity:
    """What the source calls this image (§2.1.1) -- a claim of the source,
    never of the header.

    The object itself is never ``None``: absence is ``value`` being
    ``None`` inside it, so the same fact has exactly one encoding.
    ``form`` says which of a path and a name ``value`` is, because a
    module *name* may legitimately contain a separator and an attacker may
    put one anywhere. ``truncated`` belongs to this object rather than to
    the profile, since a profile can carry several identities and only one
    may have been shortened.
    """
    value: "str | None" = None
    form: "str | None" = None
    truncated: bool = False

    def __post_init__(self):
        # Every invariant is enforced here rather than only in the
        # constructors below, because :meth:`of` is not the only way one
        # of these is built: a direct construction, or a
        # ``dataclasses.replace`` of a profile's identity, reaches this
        # and nothing else. An identity that skipped the bound would carry
        # an attacker-sized string into a value the profile calls
        # immutable and bounded.
        if not isinstance(self.value, (str, type(None))):
            raise ValueError(
                f"module_identity.value must be a str or None, got "
                f"{type(self.value).__name__}")
        if not isinstance(self.truncated, bool):
            raise ValueError(
                f"module_identity.truncated must be a bool, got "
                f"{type(self.truncated).__name__}")
        if self.form not in (None, "path", "name"):
            raise ValueError(f"module_identity.form must be 'path', 'name', or None, got {self.form!r}")
        if self.value is None:
            if self.form is not None:
                raise ValueError("module_identity.form must be None when value is None")
            if self.truncated:
                raise ValueError("module_identity.truncated must be False when value is None")
            return
        if self.form is None:
            raise ValueError("module_identity.form must be set when value is not None")
        # The character count is checked first and short-circuits. It is
        # O(1) and cannot understate the byte count -- every code point is
        # at least one UTF-8 byte -- so an oversized value is rejected
        # without encoding it, and the encode that does run is bounded at
        # four bytes per kept character.
        if (len(self.value) > MAX_STRING_BYTES
                or len(self.value.encode("utf-8", errors="replace")) > MAX_STRING_BYTES):
            raise ValueError(
                f"module_identity.value must be at most {MAX_STRING_BYTES} UTF-8 bytes "
                f"(§10.3.1); build it with ModuleIdentity.of(), which applies the bound "
                f"and records whether it bound")

    @classmethod
    def absent(cls) -> "ModuleIdentity":
        """The identity of an image nothing named -- a candidate found by
        scanning, or a source that carried no path."""
        return cls()

    @classmethod
    def of(cls, value, form: str) -> "ModuleIdentity":
        """One source-supplied identity, bounded per §10.3.1: the kept
        prefix is measured in UTF-8 bytes and never splits a code point,
        so it may be shorter than the limit. A ``None`` value yields
        :meth:`absent` -- a name nobody supplied is not an empty one."""
        if value is None:
            return cls.absent()
        text = str(value)
        kept, truncated = _bound_string(text)
        return cls(value=kept, form=form, truncated=truncated)


def _bound_string(text: str) -> "tuple[str, bool]":
    """``text`` shortened to ``MAX_STRING_BYTES`` UTF-8 bytes, and whether
    it was.

    Bytes rather than characters because the cost being bounded is memory;
    a prefix rather than an elision because a prefix is still evidence of
    what the string began with, and because a marker inside the value
    would itself be attacker-forgeable.

    The character prefix is taken **before** anything is encoded. Encoding
    first and cutting afterwards would allocate a buffer the size of the
    attacker's own string -- larger, since a hostile code point encodes to
    four bytes -- to produce a 4096-byte result, which is the allocation
    the bound exists to prevent. A code point is at least one UTF-8 byte,
    so ``MAX_STRING_BYTES`` characters is always at least as much as the
    limit can keep; the encode that follows is bounded at four bytes per
    those characters, whatever the source's length.
    """
    prefix = text[:MAX_STRING_BYTES]
    encoded = prefix.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_STRING_BYTES:
        kept = prefix
    else:
        # `errors="ignore"` drops the partial code point the cut landed
        # inside, so the kept prefix can be shorter than the limit rather
        # than holding a replacement character the source never carried.
        kept = encoded[:MAX_STRING_BYTES].decode("utf-8", errors="ignore")
    # Truncation is "the kept value is not the whole source", compared by
    # character count so the original is never re-encoded to find out.
    return kept, len(kept) < len(text)


# What each scope's `budget_consumed` must satisfy against its own limit.
# A byte or read-operation budget stops exactly on its own boundary: the
# acquisition reads through the limit and no further, and issues its
# limit-th read and no further, so consumption at the stop equals the
# limit. Less than that describes an acquisition that stopped for some
# other reason and named a budget anyway -- the unattributed truncation
# §6.2 forbids, wearing an attribution. More describes work done past a
# budget that is supposed to have prevented it, which would make the
# limit a number the record itself contradicts. `e_lfanew` is the mirror
# case: the stop exists because the declared offset is past the budget,
# so a record at or below it describes an offset that was inside the
# budget and needed no stop.
#
# A scope not listed here is not validated. The set of budgets is not
# frozen by this contract, and a future one would state its own relation
# rather than inherit an analogy to these.
_BOUNDED_STOP_RELATIONS = {
    "pe_header_bytes": lambda limit, consumed: consumed == limit,
    "pe_header_read_operations": lambda limit, consumed: consumed == limit,
    "e_lfanew": lambda limit, consumed: consumed > limit,
}

_BOUNDED_STOP_REASONS = {
    "pe_header_bytes": "the acquisition stops on the budget's own last byte",
    "pe_header_read_operations": "the acquisition stops on the budget's own last read",
    "e_lfanew": "the stop exists because the declared offset is past the budget",
}


@dataclass(frozen=True)
class BoundedStop:
    """Why acquisition ended on one of dumpex's own budgets (§6.2) --
    which budget, its limit, and what was consumed.

    Unattributed truncation is not permitted: "the acquisition stopped"
    with no named budget is indistinguishable from a structural end. A
    stop never yields ``MALFORMED`` and never makes a component
    ``DECLARED_ABSENT``; what it yields follows §5.3 from how many bytes
    each component received.

    ``budget_consumed`` is where the acquisition stood when the budget
    fired, which is not always at or below ``budget_limit`` -- the same
    reading ``IatTruncation`` already gives it, where the index that
    tripped a per-item cap is the index past it. For ``pe_header_bytes``
    and ``pe_header_read_operations`` it is the bytes read and the reads
    issued, both at the limit. For ``e_lfanew`` it is the offset the image
    declared, which is above the limit by definition: that is the whole
    reason the stop exists, and clamping it would discard the one number
    that says how far past the budget the image asked to go.
    """
    scope: str
    budget_limit: int
    budget_consumed: int

    def __post_init__(self):
        # A limit that is not an integer count of the thing it bounds can
        # be exceeded by a consumption that is -- a stop reporting
        # `consumed 2` against `limit 1.5` attributes the halt to a
        # boundary the acquisition never actually crossed.
        for name in ("budget_limit", "budget_consumed"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(
                    f"BoundedStop.{name} must be a non-negative int, got {value!r}")
        if self.budget_limit <= 0:
            # A budget of zero declines everything, so an acquisition
            # under one never starts and has no stop to attribute. The
            # collector refuses a zero budget outright; a record claiming
            # one describes work that could not have been done.
            raise ValueError(
                f"BoundedStop.budget_limit must be positive, got {self.budget_limit}")
        relation = _BOUNDED_STOP_RELATIONS.get(self.scope)
        if relation is not None and not relation(self.budget_limit, self.budget_consumed):
            raise ValueError(
                f"BoundedStop({self.scope!r}) with limit {self.budget_limit} cannot "
                f"report {self.budget_consumed} consumed: {_BOUNDED_STOP_REASONS[self.scope]}")


@dataclass(frozen=True)
class DirectoryDescriptor:
    """One data-directory descriptor (§4.1), always present for all
    sixteen indices -- an omitted descriptor would make "not captured"
    indistinguishable from "not declared".

    A descriptor is eight bytes, and its two halves can land on opposite
    sides of where a read stopped, so ``state`` is resolved from
    ``bytes_read`` rather than from a count of fully-decoded descriptors.
    ``present`` is presence and is carried as presence: once four bytes
    are in hand ``value`` alone answers it, whatever the unread ``size``
    after it would have said.

    ``state`` describes the descriptor. It never describes the contents
    the descriptor points at.
    """
    index: int
    name: str
    value: "int | None"
    value_kind: str
    size: "int | None"
    bytes_read: int
    state: ComponentState
    present: "bool | None"


@dataclass(frozen=True)
class SectionDescriptor:
    """One section header (§3.4), in section-table order.

    ``is_executable`` / ``is_writable`` / ``is_readable`` are decoded once
    from ``characteristics`` so no consumer repeats the bit arithmetic.
    ``name`` is attacker-controlled bytes: decoded with replacement, never
    executed, never used as a path or a key.

    ``virtual_size`` may exceed ``size_of_raw_data`` -- the tail then has
    no file bytes at all -- and ``size_of_raw_data`` may exceed
    ``virtual_size`` because of file alignment. Neither is malformed.
    """
    section_index: int
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_readable: bool


@dataclass(frozen=True)
class ComponentStates:
    """The six components' states, in the frozen declaration order of
    §1.2. Declaration order is structural order: a profile built twice
    from the same bytes lists them identically.

    A component outside the requested stage carries ``None``, not
    ``UNAVAILABLE``. It is not part of the answer at all (§5.4.1), and the
    two must stay distinguishable: a stage-1 acquisition that answered its
    question completely would otherwise read as a profile whose section
    table went missing, exactly like a stage-3 acquisition that failed.
    ``None`` here is §1.3's ``null`` -- the question was never asked.
    """
    dos_header: "ComponentState | None"
    coff_header: "ComponentState | None"
    optional_header: "ComponentState | None"
    directory_array: "ComponentState | None"
    directory_descriptors: "ComponentState | None"
    section_table: "ComponentState | None"

    def state_of(self, component: str) -> "ComponentState | None":
        """The state of one component by its frozen name. An unknown name
        is a programming error, not a missing state."""
        try:
            return getattr(self, component)
        except AttributeError:
            raise KeyError(f"unknown component: {component!r}") from None

    def in_scope(self, stage: PeStage) -> "tuple[tuple[str, ComponentState], ...]":
        """The components ``stage`` was supposed to acquire -- the
        cumulative yields of stages ``0..stage`` (§5.4.1) -- as
        ``(name, state)`` pairs in §1.2's order. Every one of them carries
        a state; the components outside the stage are absent from this
        tuple rather than present with a weaker one.
        """
        return tuple((name, self.state_of(name)) for name in in_scope_components(stage))


@dataclass(frozen=True)
class RelocationContext:
    """§3.5's derived relocation facts, reported individually and folded
    nowhere.

    These are not a component: they hold no bytes of their own, carry no
    state of their own, and never enter §5.4's rollup. Every byte behind
    them belongs to a component that is already in the rollup's scope, so
    a fold over them could never change a profile state -- it could only
    misreport, since §1.2's states are defined over a component's own
    bytes and these facts have none.

    Each field is independently nullable, and a ``None`` here has §1.3's
    single meaning: this fact was not established. Nothing is guessed from
    a section layout, and no field is defaulted -- treating an unread
    ``Characteristics`` bit as ``False`` would manufacture "relocations
    are not stripped" from nothing.

    A consumer asking *why* a field is ``None`` reads the state of the
    component that field's bytes belong to: ``optional_header`` for
    ``preferred_image_base`` and ``dynamic_base``, ``coff_header`` for
    ``relocs_stripped``, and ``directory_array`` then index 5's descriptor
    for the two relocation-directory facts.
    """
    preferred_image_base: "int | None"
    actual_base: "int | None"
    relocation_delta: "int | None"
    relocs_stripped: "bool | None"
    dynamic_base: "bool | None"
    basereloc_present: "bool | None"
    basereloc_descriptor_state: ComponentState


@dataclass(frozen=True)
class PeImageProfile:
    """One image's header structures as acquired, immutable and complete
    in itself.

    Identity is *where the bytes came from* (§2.1), never what they turned
    out to contain. ``actual_base`` is the address the header was read at
    and is never taken from the header; ``preferred_image_base`` is the
    optional header's own ``ImageBase`` declaration. The two are different
    facts and every RVA in this profile resolves against the first
    (§2.3) -- resolving one against the second reads a relocated image at
    the wrong address.

    ``requested`` / ``capture`` / ``read`` are §5.1's three independent
    byte facts, never collapsed into one number: ``captured < requested``
    is a collection gap and ``read < captured`` is a read failure over
    bytes that were present, and the two have different remedies.
    ``capture`` and ``read`` are ``None`` when the caller supplied no
    segment table to resolve them against -- absence of the provenance,
    not a claim that nothing was captured.

    ``read_target_bytes`` is the fourth byte fact, and it belongs here
    rather than to a consumer. A staged acquisition stops when the ladder
    is satisfied, so ``read_bytes`` is normally far below both
    ``requested`` and ``captured`` on a perfectly healthy image -- which
    means ``ReadSlice.is_io_short`` is ``True`` for an acquisition that
    did everything right, and cannot on its own be read as an I/O
    failure. ``read_target_bytes`` is the furthest offset the stages
    actually asked to have satisfied, recorded as asked rather than as
    the byte budget allowed. :attr:`target_io_short` is the judgement
    those two facts support, so no consumer re-derives it.

    Recording the target here keeps that judgement resting on a fact the
    acquisition established. Deriving it downstream would mean inferring
    what the ladder wanted from what it got, which is exactly the
    inference the shortfall is being used to test.

    ``state`` is a summary for a single console line. It never replaces
    the components: a profile-level ``MALFORMED`` sits beside every field
    that did decode, and both are reported.
    """
    # Source identity (§2.1)
    source_kind: SourceKind
    source_identity: object
    module_identity: ModuleIdentity
    actual_base: int

    # Byte provenance (§5.1) and acquisition outcome (§6)
    requested: VirtualRange
    capture: "CapturedSlice | None"
    read: "ReadSlice | None"
    read_bytes: int
    read_target_bytes: int
    requested_stage: PeStage
    highest_completed_stage: "PeStage | None"
    bounded_stop: "BoundedStop | None"

    # DOS header (§3.1)
    has_mz: "bool | None"
    e_lfanew: "int | None"

    # COFF file header (§3.2)
    has_pe_sig: "bool | None"
    machine: "int | None"
    machine_name: "str | None"
    number_of_sections: "int | None"
    time_date_stamp: "int | None"
    pointer_to_symbol_table: "int | None"
    number_of_symbols: "int | None"
    size_of_optional_header: "int | None"
    coff_characteristics: "int | None"

    # Optional header, fixed fields (§3.3)
    is_pe32_plus: "bool | None"
    address_of_entry_point: "int | None"
    base_of_code: "int | None"
    preferred_image_base: "int | None"
    section_alignment: "int | None"
    file_alignment: "int | None"
    size_of_image: "int | None"
    size_of_headers: "int | None"
    checksum: "int | None"
    subsystem: "int | None"
    dll_characteristics: "int | None"

    # Data directories (§4)
    declared_directory_count_raw: "int | None"
    declared_directory_count: "int | None"
    readable_directory_count: "int | None"
    unprojected_directory_count: "int | None"
    directories: "tuple[DirectoryDescriptor, ...]"

    # Section table (§3.4)
    sections: "tuple[SectionDescriptor, ...]"

    # Coverage (§5)
    components: ComponentStates
    unexamined: "tuple[VirtualRange, ...]"

    # Derived facts (§3.5)
    relocation: RelocationContext

    def __post_init__(self):
        if len(self.directories) != MAX_DIRECTORY_COUNT:
            raise ValueError(
                f"a profile carries all {MAX_DIRECTORY_COUNT} directory descriptors, "
                f"got {len(self.directories)}")
        if not isinstance(self.module_identity, ModuleIdentity):
            # The collector refuses this at its own boundary too, but the
            # invariant belongs here: a `dataclasses.replace` reaches this
            # and nothing else, and a profile holding a caller's mutable
            # object is not the immutable value the rest of this module
            # promises.
            raise ValueError(
                f"module_identity must be a ModuleIdentity, got "
                f"{type(self.module_identity).__name__}")
        for expected, descriptor in enumerate(self.directories):
            if descriptor.index != expected:
                raise ValueError("directory descriptors must be in index order 0..15")
        for expected, section in enumerate(self.sections):
            if section.section_index != expected:
                raise ValueError("sections must be in section-table order")
        previous_end = None
        for span in self.unexamined:
            if previous_end is not None and span.base_address <= previous_end:
                raise ValueError(
                    "unexamined ranges must ascend, never overlap, and be merged when adjacent")
            previous_end = span.end_address
        # "The question was not asked" and "the question was asked and got
        # no answer" are different facts, and the scope boundary is what
        # keeps them apart. Enforced here rather than left to each writer,
        # because a single leaked `UNAVAILABLE` outside the stage silently
        # turns a completed short request into a failed long one.
        covered = frozenset(in_scope_components(self.requested_stage))
        for name in (n for names in _STAGE_YIELDS.values() for n in names):
            state = self.components.state_of(name)
            if name in covered and state is None:
                raise ValueError(
                    f"{name} is inside the requested stage and must carry a state")
            if name not in covered and state is not None:
                raise ValueError(
                    f"{name} is outside the requested stage and must carry None, "
                    f"not {state}")

    @property
    def state(self) -> ComponentState:
        """§5.4.2's fold over the components the requested stage was
        supposed to acquire.

        ``MALFORMED`` outranks the two gap states deliberately: a
        determined structural defect is a positive result, and hiding it
        behind a gap elsewhere in the image would suppress the stronger
        evidence. ``DECLARED_ABSENT`` participates in neither fold -- a
        positively declared absence is an answered component, and "this
        profile does not exist" is not a statement a rollup can make.

        This is not ``parse_pe_header()``'s ``valid`` flag under another
        name, and neither is derived from the other (§11.6, §11.7). That
        flag answers "will re-reading these bytes help?"; this state
        answers "is the image defective?". An ``e_lfanew`` past
        ``MAX_E_LFANEW`` is where they diverge by construction: the
        shipped parser rejects it deterministically, while here it is a
        bounded stop that leaves the profile ``UNAVAILABLE``. The
        ``PROCESS_MAIN_IMAGE_*`` limitation codes stay the sole authority
        for coverage and exit codes; this state is descriptive and changes
        neither.
        """
        return _fold_states(state for _name, state in self.components.in_scope(self.requested_stage))

    @property
    def target_io_short(self) -> "bool | None":
        """Whether the read came up short of bytes the dump actually
        holds -- ``None`` when the facts in hand do not settle it.

        This is the three-valued answer to "did reading fail?", kept apart
        from ``ReadSlice.is_io_short``, which compares the read against
        the whole captured prefix and is therefore ``True`` for a healthy
        staged acquisition that simply stopped when its ladder was
        satisfied.

        The first matching row:

        - the target was met -- every byte the stages asked for
          arrived -- so the answer is ``False``;
        - the target was not met and ``capture`` is known, so the answer
          is ``read_bytes < min(read_target_bytes, captured_bytes)``;
        - the target was not met and ``capture`` is ``None``, so the
          answer is ``None``.

        The third row is the one that has to be ``None``. Without a
        segment table there is nothing to say whether the missing bytes
        were never captured or were captured and not returned, and those
        two have different remedies (§5.1). Nothing here manufactures the
        distinction: ``capture`` being ``None`` already states that the
        provenance was not supplied, and adding a field to stand in for
        the evidence it names would fabricate the answer rather than
        withhold it.

        A bounded stop needs no term of its own. The stop leaves
        ``read_bytes`` at the budget while ``read_target_bytes`` names
        what was asked past it, so the second row's minimum already
        answers ``False`` -- the bytes that did not arrive are bytes
        dumpex declined to ask the dump for, not bytes it asked for and
        failed to get.

        What a consumer does with ``None`` is the consumer's own rule.
        This property states one byte fact three-valued; it does not
        decide which observations it downgrades.
        """
        if self.read_bytes >= self.read_target_bytes:
            return False
        if self.capture is None:
            return None
        return self.read_bytes < min(self.read_target_bytes, self.capture.captured_bytes)

    def directory(self, index: int) -> DirectoryDescriptor:
        """The descriptor at ``index``, which is always present."""
        return self.directories[index]


def _fold_states(states) -> ComponentState:
    """§5.4.2's fold: the first matching row over the states given.

    ``DECLARED_ABSENT`` never participates, which is why sixteen
    positively-absent descriptors fold to one ``COMPLETE`` unit. A fold
    over nothing but declared absences is ``COMPLETE``: every question in
    scope was answered.
    """
    seen = set(states)
    if ComponentState.MALFORMED in seen:
        return ComponentState.MALFORMED
    if ComponentState.UNAVAILABLE in seen:
        return ComponentState.UNAVAILABLE
    if ComponentState.PARTIAL in seen:
        return ComponentState.PARTIAL
    return ComponentState.COMPLETE


# ── Acquisition ─────────────────────────────────────────────────────────


class _Acquisition:
    """The contiguous prefix of an image's bytes one collection obtained,
    and the budgets that bounded obtaining it.

    Every §6.1 stage reads a prefix starting at the image base, so one
    growing buffer models all four -- and reading across contiguous
    captured segments (§6.3) is the caller's ``read`` callback's concern,
    not a boundary this class fails at.

    ``read`` is untrusted: it may raise, return ``None``, return something
    that is not bytes-like, return fewer bytes than asked, or return more.
    None of that escapes, and every call is charged against both budgets
    so a reader that only ever trickles back one byte cannot hang a
    collection.
    """
    __slots__ = ("_read", "base", "_budget_bytes", "_captured_bytes", "_max_ops",
                 "data", "ops_used", "stop", "exhausted", "target")

    def __init__(self, read, base: int, budget_bytes: int, max_ops: int,
                 captured_bytes: "int | None" = None):
        self._read = read
        self.base = base
        self._budget_bytes = budget_bytes
        # The dump's own claim about how far the contiguous captured
        # prefix reaches, when the caller supplied one. It bounds what may
        # enter `data` at all, not merely how the provenance is later
        # described: `read <= captured <= requested` is an invariant of
        # the acquisition, and a reader that hands back bytes the segment
        # table does not back must not have them decoded into header
        # facts.
        self._captured_bytes = captured_bytes
        self._max_ops = max_ops
        self.data = bytearray()
        self.ops_used = 0
        self.stop = None
        self.exhausted = False
        # The furthest offset any stage asked to have satisfied, recorded
        # as asked -- before the byte budget clamps it, so a request the
        # budget refused is still visible as a request.
        self.target = 0

    @property
    def read_len(self) -> int:
        return len(self.data)

    def reach(self, end_offset: int) -> bool:
        """Ensure the prefix through ``end_offset`` is available, and say
        whether it is.

        A shortfall has two entirely different causes and this is the one
        place they are told apart. Asking past a budget records a
        :class:`BoundedStop`: dumpex declined the work, so the components
        beyond it are ``PARTIAL`` or ``UNAVAILABLE`` by bytes and never
        ``MALFORMED``. A reader that simply came up short records no stop
        at all -- that is a capture gap or a read failure, which §5.1's
        byte facts describe and no budget explains.
        """
        self.target = max(self.target, end_offset)
        if end_offset <= self.read_len:
            return True
        if self.stop is not None or self.exhausted:
            return False
        # A ceiling bounds how far the acquisition goes, not whether it
        # goes at all: everything up to it is still read, so a component
        # the ceiling lands inside is `partial` with its unread tail
        # named, and only one it lands before is `unavailable`.
        ceiling = self._ceiling()
        target = min(end_offset, ceiling)
        while self.read_len < target:
            if self.ops_used >= self._max_ops:
                self.stop = BoundedStop(
                    "pe_header_read_operations", self._max_ops, self.ops_used)
                return False
            chunk = self._one_read(target - self.read_len)
            if not chunk:
                self.exhausted = True
                return False
            self.data += chunk
        if end_offset > ceiling:
            self._attribute_ceiling()
            return False
        return True

    def _ceiling(self) -> int:
        """The furthest offset this acquisition may read to.

        Two different limits can bind, and they are never interchanged. A
        capture shortfall is the dump not holding the bytes; the byte
        budget is dumpex declining to ask for them. The smaller binds
        first, and since ``captured <= requested`` always, a capture
        ceiling below the budget is the dump's gap and one equal to it is
        the budget's own edge.
        """
        if self._captured_bytes is None:
            return self._budget_bytes
        return min(self._budget_bytes, self._captured_bytes)

    def _attribute_ceiling(self) -> None:
        """Record why the acquisition stopped at its ceiling.

        Only a budget produces a :class:`BoundedStop`. Running past the
        captured prefix is a collection gap: dumpex declined nothing, so
        attributing it to a budget would report a limit of this tool over
        bytes that were never in the dump. It ends the acquisition the way
        a reader returning nothing does, and §5.1's byte facts are what
        describe it.
        """
        if self._captured_bytes is not None and self._captured_bytes < self._budget_bytes:
            self.exhausted = True
            return
        self.stop = BoundedStop("pe_header_bytes", self._budget_bytes, self.read_len)

    def _one_read(self, want: int) -> bytes:
        """One budgeted call to the caller's reader, clipped to ``want``
        and never raising.

        ``bytes(x)`` is not a safe validation of what came back: it does
        not raise for an ``int``, it silently produces that many zero
        bytes, and a large enough one allocates without bound -- defeating
        the point of a byte-budgeted reader. Only an object that is
        already bytes-like is accepted; anything else is a failed read,
        never coerced.
        """
        self.ops_used += 1
        try:
            chunk = self._read(self.base + self.read_len, want)
        except Exception:
            return b""
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            return b""
        try:
            return memoryview(chunk).cast("B")[:want].tobytes()
        except Exception:
            return b""

    def available(self, offset: int, size: int) -> int:
        """How many of the ``size`` bytes at ``offset`` were read: the
        byte fact every component state is derived from."""
        if offset >= self.read_len:
            return 0
        return min(size, self.read_len - offset)

    def uint(self, offset: int, width: int) -> "int | None":
        """The little-endian integer of ``width`` bytes at ``offset``, or
        ``None`` when any of its own bytes were not read. A field is
        established from its own bytes or not at all."""
        if self.available(offset, width) < width:
            return None
        return int.from_bytes(self.data[offset:offset + width], "little")

    def equals(self, offset: int, expected: bytes) -> "bool | None":
        """Whether the bytes at ``offset`` are ``expected``, or ``None``
        when fewer than all of them were read -- a constant read in part
        establishes nothing, in either direction."""
        if self.available(offset, len(expected)) < len(expected):
            return None
        return bytes(self.data[offset:offset + len(expected)]) == expected


class _Collector:
    """One staged acquisition in progress.

    Each ``_stage_*`` method decides its own components' states from the
    bytes that arrived, following §5.3's derivation order, and records the
    byte ranges nothing examined. A stage that cannot locate its bytes --
    because the field placing them was never established, or was
    established as a value the format does not permit -- yields
    ``UNAVAILABLE``, which is §6.1's "a stage that cannot start because
    the previous one did not complete".
    """

    def __init__(self, acquisition: _Acquisition, requested_stage: PeStage):
        self._acq = acquisition
        self._stage = requested_stage
        self.unexamined: "list[VirtualRange]" = []
        # A component the requested stage does not cover is `None` -- not
        # part of the answer (§5.4.1). One the stage does cover starts
        # `UNAVAILABLE` and is decided by the bytes that arrive, so a
        # stage that never runs leaves behind exactly what §6.1 says it
        # should: nothing was decoded.
        self._covered = frozenset(in_scope_components(requested_stage))
        self.states = {
            name: (ComponentState.UNAVAILABLE if name in self._covered else None)
            for names in _STAGE_YIELDS.values() for name in names}
        self.facts: dict = {}
        self.directories: "list[DirectoryDescriptor]" = []
        self.sections: "list[SectionDescriptor]" = []

    def _set_state(self, component: str, state: ComponentState) -> None:
        """Record one component's state, unless the requested stage never
        covered it.

        A component outside the stage keeps its ``None``: work a later
        stage would have done can still run -- §4.1 keeps all sixteen
        descriptors in every profile, whatever stage produced it -- but
        what it learns must not become an answer to a question nobody
        asked (§5.4.1).
        """
        if component in self._covered:
            self.states[component] = state

    # ── unexamined bookkeeping (§5.2) ───────────────────────────────────

    def _not_examined(self, offset: int, size: int) -> None:
        """Record the unread tail of a component whose bytes are locatable.

        A range is recorded for every locatable component with unread
        bytes, whatever state sits beside it: a range says which bytes
        nothing looked at, and that is not changed by why. A component
        whose position was never established has no range to name, and
        none is invented for it.
        """
        already = self._acq.available(offset, size)
        if already >= size:
            return
        base = self._acq.base + offset + already
        length = size - already
        if base + length > _ADDRESS_SPACE:
            # A legal `e_lfanew` near the top of the space can place a
            # later component past the end of it. The arithmetic is
            # checked before the range is built (§2.6), so nothing is
            # recorded rather than a wrapped range naming bytes at another
            # address. Every other value reaching here is in-range by
            # construction: `length` is at least one byte, and a `base`
            # outside the space already fails this same check.
            return
        self.unexamined.append(VirtualRange(base, length))

    def _merged_unexamined(self) -> "tuple[VirtualRange, ...]":
        """The recorded ranges as one canonical set: ascending,
        non-overlapping, and merged where they adjoin."""
        merged: "list[VirtualRange]" = []
        for span in sorted(self.unexamined, key=lambda r: (r.base_address, r.size)):
            if merged and span.base_address <= merged[-1].end_address:
                previous = merged[-1]
                end = max(previous.end_address, span.end_address)
                merged[-1] = VirtualRange.from_endpoints(previous.base_address, end)
            else:
                merged.append(span)
        return tuple(merged)

    # ── stage 0: the DOS header (§3.1) ──────────────────────────────────

    def _stage_dos(self) -> "int | None":
        """Decide ``dos_header`` and return the ``e_lfanew`` stage 1 can be
        located from, or ``None`` when it cannot be."""
        acq = self._acq
        acq.reach(_DOS_HEADER_SIZE)
        self._not_examined(0, _DOS_HEADER_SIZE)

        has_mz = acq.equals(0, _MZ_SIGNATURE)
        e_lfanew = acq.uint(_E_LFANEW_OFFSET, 4)
        self.facts["has_mz"] = has_mz
        self.facts["e_lfanew"] = e_lfanew

        if has_mz is False:
            # A determined defect (§5.3.1): the format fixes these two
            # bytes, they were read in full, and they hold something else.
            # It stands whether or not the rest of the header arrived.
            self._set_state("dos_header", ComponentState.MALFORMED)
            return None
        if has_mz is None:
            self._set_state("dos_header", ComponentState.UNAVAILABLE)
            return None
        if e_lfanew is None:
            self._set_state("dos_header", ComponentState.PARTIAL)
            return None
        if e_lfanew < _PE_SIGNATURE_SIZE:
            # Below four the PE signature would overlap the `MZ` magic the
            # DOS header already established, so the value cannot be an
            # offset to anything. Every byte of the component was read, so
            # §5.3's step 5 decides it.
            self._set_state("dos_header", ComponentState.MALFORMED)
            return None

        self._set_state("dos_header", ComponentState.COMPLETE)
        if e_lfanew > MAX_E_LFANEW:
            # A long DOS stub is legal and the format fixes no upper bound
            # here, so this is dumpex's own acquisition budget: a bounded
            # stop, never a defect. The DOS header stays `complete` --
            # `e_lfanew` lives inside it and stage 0 read all of it -- and
            # every later component is `unavailable` for want of bytes.
            self._acq.stop = BoundedStop("e_lfanew", MAX_E_LFANEW, e_lfanew)
            return None
        return e_lfanew

    # ── stage 1: the PE signature and COFF header (§3.2) ────────────────

    def _stage_coff(self, e_lfanew: int) -> bool:
        """Decide ``coff_header`` and say whether stage 2 can be located
        from it."""
        acq = self._acq
        acq.reach(e_lfanew + _COFF_COMPONENT_SIZE)
        self._not_examined(e_lfanew, _COFF_COMPONENT_SIZE)

        has_pe_sig = acq.equals(e_lfanew, _PE_SIGNATURE)
        self.facts["has_pe_sig"] = has_pe_sig

        signature_bytes = acq.available(e_lfanew, _PE_SIGNATURE_SIZE)
        if signature_bytes == 0:
            self._set_state("coff_header", ComponentState.UNAVAILABLE)
            return False
        if has_pe_sig is None:
            self._set_state("coff_header", ComponentState.PARTIAL)
            return False
        if has_pe_sig is False:
            # The signature's four bytes are this component's first four
            # and were all read, so this determined defect is decided
            # ahead of any gap in the twenty COFF bytes that follow.
            self._set_state("coff_header", ComponentState.MALFORMED)
            return False

        fields_offset = e_lfanew + _PE_SIGNATURE_SIZE
        machine = acq.uint(fields_offset + 0, 2)
        number_of_sections = acq.uint(fields_offset + 2, 2)
        self.facts.update(
            machine=machine,
            # An unnamed `Machine` value is a legitimate image this
            # contract has no name for, not a defect: the raw value is
            # reported and only the name is `None`.
            machine_name=_KNOWN_MACHINES.get(machine) if machine is not None else None,
            number_of_sections=number_of_sections,
            time_date_stamp=acq.uint(fields_offset + 4, 4),
            pointer_to_symbol_table=acq.uint(fields_offset + 8, 4),
            number_of_symbols=acq.uint(fields_offset + 12, 4),
            size_of_optional_header=acq.uint(fields_offset + 16, 2),
            coff_characteristics=acq.uint(fields_offset + 18, 2),
        )

        if number_of_sections is not None and not 1 <= number_of_sections <= _MAX_SECTIONS:
            # The format caps an image at `_MAX_SECTIONS` sections and a
            # loadable image declares at least one, so this is a count no
            # image can carry -- a determined defect on two bytes that
            # were read in full, decided ahead of a gap after them.
            self._set_state("coff_header", ComponentState.MALFORMED)
        elif acq.available(fields_offset, _COFF_FIELDS_SIZE) < _COFF_FIELDS_SIZE:
            self._set_state("coff_header", ComponentState.PARTIAL)
        else:
            self._set_state("coff_header", ComponentState.COMPLETE)
        return self.facts["size_of_optional_header"] is not None

    # ── stage 2: the optional header and directory array (§3.3, §4) ─────

    def _stage_optional(self, e_lfanew: int, size_of_optional_header: int) -> None:
        optional_offset = e_lfanew + _COFF_COMPONENT_SIZE
        fixed_portion = self._decide_optional_header(optional_offset, size_of_optional_header)
        self._decide_directory_array(optional_offset, size_of_optional_header, fixed_portion)

    def _decide_optional_header(self, optional_offset: int,
                                size_of_optional_header: int) -> "int | None":
        """Decide ``optional_header`` and return the fixed-portion size of
        the format its ``Magic`` names, or ``None`` when no format was
        established."""
        acq = self._acq
        acq.reach(optional_offset + min(_OPTIONAL_FIXED_FIELDS_SIZE, size_of_optional_header))

        magic = None
        if size_of_optional_header >= 2:
            magic = acq.uint(optional_offset, 2)

        if magic == _MAGIC_PE32:
            is_pe32_plus, fixed_portion = False, _FIXED_PORTION_PE32
        elif magic == _MAGIC_PE32_PLUS:
            is_pe32_plus, fixed_portion = True, _FIXED_PORTION_PE32_PLUS
        else:
            is_pe32_plus, fixed_portion = None, None
        self.facts["is_pe32_plus"] = is_pe32_plus

        # The component's own bytes end at the §3.3 fixed fields. Past a
        # declared `SizeOfOptionalHeader` the bytes are section table, so
        # they are not this component's to leave unexamined.
        own_bytes = min(_OPTIONAL_FIXED_FIELDS_SIZE, size_of_optional_header)
        self._not_examined(optional_offset, own_bytes)
        available = acq.available(optional_offset, own_bytes)

        if size_of_optional_header < 2:
            # A declared size this small leaves even `Magic` unreadable,
            # so nothing of the component was decoded and the profile has
            # no pointer width -- not a guessed one.
            self._set_state("optional_header", ComponentState.UNAVAILABLE)
            return None
        if available == 0:
            self._set_state("optional_header", ComponentState.UNAVAILABLE)
            return None
        if magic is not None and fixed_portion is None:
            # `Magic` read in full and neither `0x10b` nor `0x20b`: a
            # determined defect on its own two bytes.
            #
            # No field is decoded from the rest, unlike §3.3.1.1's case
            # below. There, `Magic` named a format and the fields at that
            # format's offsets are the fields the image declared, so they
            # are reported beside the defect (§5.4.4). Here it names none,
            # so nothing establishes that the bytes at §3.3's offsets are
            # those fields at all -- reporting an entry point read from
            # them would be reporting a field of a structure this
            # contract has no layout for.
            self._set_state("optional_header", ComponentState.MALFORMED)
            return None
        if fixed_portion is not None and size_of_optional_header < fixed_portion:
            # Once `Magic` names a format, that format's fixed portion has
            # a fixed length. A declared size below it is not a small
            # header -- it is a header that cannot be the format its own
            # `Magic` says it is. Two sub-fields, both read in full, that
            # cannot both be true of one image.
            self._set_state("optional_header", ComponentState.MALFORMED)
            self._decode_optional_fields(optional_offset, size_of_optional_header, is_pe32_plus)
            return fixed_portion

        self._decode_optional_fields(optional_offset, size_of_optional_header, is_pe32_plus)
        if available < own_bytes:
            self._set_state("optional_header", ComponentState.PARTIAL)
        else:
            self._set_state("optional_header", ComponentState.COMPLETE)
        return fixed_portion

    def _decode_optional_fields(self, optional_offset: int, size_of_optional_header: int,
                                is_pe32_plus: "bool | None") -> None:
        """Decode every §3.3 field that fits inside the declared optional
        header and was read.

        A field belongs to the optional header only if it fits inside it:
        the section table begins at ``e_lfanew + 24 + SizeOfOptionalHeader``,
        so every byte past the declared size *is* section-table content,
        and reading one as an optional-header field silently substitutes a
        section header for the field that was asked for.

        A ``malformed`` component still reports what decoded -- the state
        is a state, not an erasure of the component's contents.
        """
        acq = self._acq

        def field(offset: int, width: int) -> "int | None":
            if offset + width > size_of_optional_header:
                return None
            return acq.uint(optional_offset + offset, width)

        self.facts.update(
            address_of_entry_point=field(16, 4),
            base_of_code=field(20, 4),
            section_alignment=field(32, 4),
            file_alignment=field(36, 4),
            size_of_image=field(56, 4),
            size_of_headers=field(60, 4),
            checksum=field(64, 4),
            subsystem=field(68, 2),
            dll_characteristics=field(70, 2),
        )
        if is_pe32_plus is True:
            self.facts["preferred_image_base"] = field(24, 8)
        elif is_pe32_plus is False:
            self.facts["preferred_image_base"] = field(28, 4)

    def _decide_directory_array(self, optional_offset: int, size_of_optional_header: int,
                                fixed_portion: "int | None") -> None:
        """Decide ``directory_array`` and every one of the sixteen
        descriptors."""
        acq = self._acq
        if fixed_portion is None:
            # No format was established, so §2.4 selects no offset for the
            # count or the array. Nothing locates either.
            self._finish_directories()
            return

        if fixed_portion > size_of_optional_header:
            # The count field itself lies past the declared optional
            # header; §3.3.1.1 already made that component `malformed`.
            self._finish_directories()
            return

        count_offset = optional_offset + fixed_portion - 4
        array_offset = optional_offset + fixed_portion
        # How many descriptors the optional header's own declared size
        # leaves room for. Clamped at zero: a header smaller than the
        # array's own offset would otherwise yield a negative quotient,
        # and a count of descriptors that is not a count.
        capacity = max(0, (size_of_optional_header - fixed_portion) // _DIRECTORY_DESCRIPTOR_SIZE)

        acq.reach(count_offset + 4)
        raw = acq.uint(count_offset, 4)
        if raw is None:
            self._not_examined(count_offset, 4)
            self._finish_directories()
            return

        declared = min(raw, MAX_DIRECTORY_COUNT)
        unprojected = max(0, raw - MAX_DIRECTORY_COUNT)
        readable = min(declared, capacity)
        array_bytes = readable * _DIRECTORY_DESCRIPTOR_SIZE
        if array_bytes:
            acq.reach(array_offset + array_bytes)
            self._not_examined(array_offset, array_bytes)

        self._finish_directories(raw, declared, readable, unprojected,
                                 array_offset=array_offset, capacity=capacity)

    def _finish_directories(self, raw=None, declared=None, readable=None,
                            unprojected=None, array_offset: "int | None" = None,
                            capacity: "int | None" = None) -> None:
        """Build all sixteen descriptors and fold them into the
        ``directory_descriptors`` unit, then decide ``directory_array``.

        The array's state and the descriptors' states answer two different
        questions and are decided from different bytes: the array's from
        ``NumberOfRvaAndSizes`` against the header declaring it, each
        descriptor's from its own eight.
        """
        acq = self._acq
        self.facts.update(
            declared_directory_count_raw=raw,
            declared_directory_count=declared,
            readable_directory_count=readable,
            unprojected_directory_count=unprojected,
        )

        fully_read = 0
        for index in range(MAX_DIRECTORY_COUNT):
            if array_offset is None or readable is None or index >= readable:
                bytes_read = 0
                value = size = None
            else:
                offset = array_offset + index * _DIRECTORY_DESCRIPTOR_SIZE
                bytes_read = acq.available(offset, _DIRECTORY_DESCRIPTOR_SIZE)
                value = acq.uint(offset, 4)
                size = acq.uint(offset + 4, 4)
            if bytes_read == _DIRECTORY_DESCRIPTOR_SIZE:
                fully_read += 1
            state, present = _resolve_descriptor(index, declared, bytes_read, value, size)
            self.directories.append(DirectoryDescriptor(
                index=index,
                name=DIRECTORY_NAMES[index],
                value=value,
                # Index 4 is the one descriptor whose first field is a
                # file offset into the on-disk image rather than an RVA.
                # No field naming it may be called `rva`, and it is never
                # resolved as `actual_base + value`.
                value_kind=("file_offset" if index == _SECURITY_DIRECTORY_INDEX else "rva"),
                size=size,
                bytes_read=bytes_read,
                state=state,
                present=present,
            ))

        self._set_state("directory_descriptors", _fold_states(
            descriptor.state for descriptor in self.directories))

        if raw is None:
            self._set_state("directory_array", ComponentState.UNAVAILABLE)
        elif capacity is not None and raw > capacity:
            # The optional header's declared size is what places the
            # section table, so an array that does not fit inside it
            # overlaps that table: the two cannot both be where the header
            # says they are. Both fields were read in full, so no gap
            # elsewhere in the array softens it.
            self._set_state("directory_array", ComponentState.MALFORMED)
        elif raw == 0:
            self._set_state("directory_array", ComponentState.DECLARED_ABSENT)
        elif fully_read < declared:
            self._set_state("directory_array", ComponentState.PARTIAL)
        else:
            self._set_state("directory_array", ComponentState.COMPLETE)

    # ── stage 3: the section table (§3.4) ───────────────────────────────

    def _stage_sections(self, e_lfanew: int, size_of_optional_header: int,
                        number_of_sections: int) -> None:
        acq = self._acq
        table_offset = e_lfanew + _COFF_COMPONENT_SIZE + size_of_optional_header
        table_bytes = number_of_sections * _SECTION_HEADER_SIZE
        acq.reach(table_offset + table_bytes)
        self._not_examined(table_offset, table_bytes)

        for index in range(number_of_sections):
            entry = table_offset + index * _SECTION_HEADER_SIZE
            if acq.available(entry, _SECTION_HEADER_SIZE) < _SECTION_HEADER_SIZE:
                break
            raw_name = bytes(acq.data[entry:entry + 8]).rstrip(b"\x00")
            virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data = \
                struct.unpack_from("<IIII", acq.data, entry + 8)
            pointer_to_relocations, pointer_to_linenumbers = \
                struct.unpack_from("<II", acq.data, entry + 24)
            number_of_relocations, number_of_linenumbers = \
                struct.unpack_from("<HH", acq.data, entry + 32)
            characteristics = struct.unpack_from("<I", acq.data, entry + 36)[0]
            self.sections.append(SectionDescriptor(
                section_index=index,
                name=raw_name.decode("latin1", errors="replace"),
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                size_of_raw_data=size_of_raw_data,
                pointer_to_raw_data=pointer_to_raw_data,
                pointer_to_relocations=pointer_to_relocations,
                pointer_to_linenumbers=pointer_to_linenumbers,
                number_of_relocations=number_of_relocations,
                number_of_linenumbers=number_of_linenumbers,
                characteristics=characteristics,
                is_executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
                is_writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
                is_readable=bool(characteristics & IMAGE_SCN_MEM_READ),
            ))

        if len(self.sections) == number_of_sections:
            self._set_state("section_table", ComponentState.COMPLETE)
        elif acq.available(table_offset, table_bytes) > 0:
            self._set_state("section_table", ComponentState.PARTIAL)
        else:
            self._set_state("section_table", ComponentState.UNAVAILABLE)

    # ── driving the ladder ──────────────────────────────────────────────

    def run(self) -> None:
        self._walk()
        if not self.directories:
            # §4.1 keeps all sixteen indices represented in every profile,
            # so a ladder that ended before the array was located still
            # builds them. With no captured count they are `unavailable`:
            # a descriptor that was never captured is present and says so,
            # because omitting it would make "not captured" and "not
            # declared" the same absence.
            self._finish_directories()

    def _walk(self) -> None:
        e_lfanew = self._stage_dos()
        if self._stage < PeStage.COFF or e_lfanew is None:
            return
        located = self._stage_coff(e_lfanew)
        if self._stage < PeStage.OPTIONAL or not located:
            return
        size_of_optional_header = self.facts["size_of_optional_header"]
        self._stage_optional(e_lfanew, size_of_optional_header)
        if self._stage < PeStage.SECTIONS:
            return
        number_of_sections = self.facts.get("number_of_sections")
        if number_of_sections is None or not 1 <= number_of_sections <= _MAX_SECTIONS:
            # The count that would place and size the table is either
            # unestablished or a value no image can declare. Nothing
            # locates the table, so it is `unavailable`; the defect itself
            # belongs to `coff_header`, where its bytes are.
            return
        self._stage_sections(e_lfanew, size_of_optional_header, number_of_sections)

    def highest_completed_stage(self) -> "PeStage | None":
        """How far the acquisition got: the highest stage whose own
        components, and every earlier stage's, are answered.

        This is result metadata, not a claim about what was learned --
        §5.4's component states say that, and §6.2's bounded stop says why
        acquisition ended.
        """
        reached = None
        for stage in PeStage:
            if stage > self._stage:
                break
            answered = all(
                self.states[name] in (ComponentState.COMPLETE, ComponentState.DECLARED_ABSENT)
                for name in _STAGE_YIELDS[stage])
            if not answered:
                break
            reached = stage
        return reached


def _resolve_descriptor(index: int, declared: "int | None", bytes_read: int,
                        value: "int | None", size: "int | None"):
    """§4.3's descriptor table, with §4.3.1's per-index constraints, as
    ``(state, present)``.

    The owning count decides whether there *is* a descriptor, and only
    then does a constraint decide whether it is legal. Without that order
    a count denying the index would lose to a constraint applied to bytes
    that are not a descriptor at all -- whatever follows a shorter array,
    which is the section table.
    """
    if declared is None:
        # With no captured count, nothing establishes that the bytes at
        # this index's offset belong to a declared descriptor rather than
        # to whatever follows a shorter array.
        return ComponentState.UNAVAILABLE, None
    if index >= declared:
        return ComponentState.DECLARED_ABSENT, False
    if bytes_read == 0:
        return ComponentState.UNAVAILABLE, None
    if bytes_read < _DIRECTORY_DESCRIPTOR_SIZE:
        # Once four bytes are in hand the presence question is answered --
        # `value` alone decides presence. The descriptor is still
        # `partial`, because its `size` is not a fact yet.
        present = None if bytes_read < 4 else value != 0
        return ComponentState.PARTIAL, present
    present = value != 0
    if _violates_reserved_constraint(index, value, size):
        return ComponentState.MALFORMED, present
    if value == 0:
        # A zero `value` with a non-zero `size` is still declared absent:
        # the `value` field alone decides presence.
        return ComponentState.DECLARED_ABSENT, present
    return ComponentState.COMPLETE, present


def _violates_reserved_constraint(index: int, value: int, size: int) -> bool:
    """Whether a fully-read descriptor holds a value the format does not
    permit at this index.

    Indices 7 and 15 are reserved descriptors, not descriptors with a
    reserved address: the whole eight-byte entry is required to be zero,
    so a non-zero ``size`` under a zero ``value`` violates the constraint
    exactly as a non-zero ``value`` does. Checking only ``value`` would
    let such an entry pass as ``declared_absent`` -- a positive claim of
    absence drawn from an entry the format says should have been all
    zeroes.

    Index 8 is the one place ``size`` alone decides: ``GLOBALPTR``'s
    ``value`` is a genuine RVA the format permits, and only its ``size``
    is constrained.
    """
    if index in (_ARCHITECTURE_DIRECTORY_INDEX, _RESERVED_DIRECTORY_INDEX):
        return value != 0 or size != 0
    if index == _GLOBALPTR_DIRECTORY_INDEX:
        return size != 0
    return False


def _relocation_context(facts: dict, actual_base: int,
                        basereloc: DirectoryDescriptor) -> RelocationContext:
    """§3.5's facts, each established on its own field's bytes or left
    ``None``.

    A defect elsewhere in a source component erases nothing: a
    ``NumberOfSections`` of 200 makes ``coff_header`` malformed while
    ``Characteristics`` -- a different field of the same twenty bytes,
    read in full -- still decodes, so ``relocs_stripped`` is established.
    """
    preferred = facts.get("preferred_image_base")
    coff_characteristics = facts.get("coff_characteristics")
    dll_characteristics = facts.get("dll_characteristics")
    return RelocationContext(
        preferred_image_base=preferred,
        actual_base=actual_base,
        relocation_delta=(None if preferred is None else actual_base - preferred),
        relocs_stripped=(None if coff_characteristics is None
                         else bool(coff_characteristics & IMAGE_FILE_RELOCS_STRIPPED)),
        dynamic_base=(None if dll_characteristics is None
                      else bool(dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)),
        # Presence is carried as presence, never inferred from the
        # descriptor's state: §4.3 answers presence once four bytes are
        # read, so a `partial` index 5 can already have settled it.
        basereloc_present=basereloc.present,
        basereloc_descriptor_state=basereloc.state,
    )


def _is_token(value) -> bool:
    """Whether ``value`` is a fixed token in §7.1.1's sense: a short,
    dumpex-authored identifier, never a string taken from the image or
    the filesystem.

    The character set and the length are both part of what makes it a
    token. A path admitted here would defeat the whole reason §7.1.1
    excludes them -- it would need a normalization form, a case rule, a
    separator rule, and a collision policy to be a correct key, would let
    a hostile name inflate the cost of a lookup, and would carry an
    attacker-controlled string past the bound :class:`ModuleIdentity`
    applies to exactly that kind of value.
    """
    if not isinstance(value, str) or not value:
        return False
    if len(value) > _MAX_SOURCE_TOKEN_LENGTH:
        return False
    return all(character in _SOURCE_TOKEN_CHARACTERS for character in value)


def _is_index(value) -> bool:
    """Whether ``value`` is a non-negative table index. ``bool`` is
    excluded even though it is an ``int`` subclass: a stray ``True`` must
    never identify entry 1."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _check_positive_int(value, name: str) -> None:
    """Require a budget or an extent to be a positive integer count.

    ``bool`` and ``float`` are refused for the same reason an address is
    (§2.6): a budget is a count of the thing it bounds, and a
    non-integral one cannot be compared against a consumption that is --
    a limit of ``1.5`` is reached by a second read and then reported as a
    limit two reads never crossed. ``True`` is refused rather than read
    as a budget of one.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive int, got {value!r}")


def _is_address(value) -> bool:
    return _is_index(value) and value < _ADDRESS_SPACE


def _validate_source_identity(source_kind: SourceKind, source_identity) -> None:
    """§7.1.1: each source kind contributes one stable identity, and the
    shape is fixed per kind rather than left to the caller.

    ``source_kind`` names a category and cannot tell two sources of that
    category apart, so the identity is what separates them -- and a
    profile cache keys on the pair. Accepting any integer or string for
    any kind would let a module-list entry take the PEB's constant, let
    two different sources collide on one key, and let an
    attacker-controlled path in as an identity. Paths and names stay
    evidence, carried by :class:`ModuleIdentity`; they never identify a
    source to a cache.
    """
    if source_kind is SourceKind.PEB_IMAGE_BASE:
        if source_identity == PEB_SOURCE_IDENTITY:
            return
        expected = f"the constant {PEB_SOURCE_IDENTITY!r} -- a process has one PEB"
    elif source_kind is SourceKind.MODULE_LIST_ENTRY:
        if _is_index(source_identity):
            return
        expected = "the entry's non-negative index in ModuleListStream"
    else:
        if (isinstance(source_identity, tuple) and len(source_identity) == 2
                and (_is_token(source_identity[0]) or _is_index(source_identity[0]))
                and _is_address(source_identity[1])):
            return
        expected = ("a (scanning pass id, region base address) pair -- the pass id a "
                    "token or an index, the base a 64-bit address")
    raise ValueError(
        f"source_identity for {source_kind.value} must be {expected} (§7.1.1), "
        f"got {source_identity!r}")


def collect_pe_image_profile(
    read,
    actual_base: int,
    *,
    source_kind: SourceKind,
    source_identity,
    module_identity: "ModuleIdentity | None" = None,
    requested_stage: PeStage = PeStage.SECTIONS,
    requested_bytes: int = PE_HEADER_READ_MAX,
    capture: "CapturedSlice | None" = None,
    max_read_operations: int = PE_HEADER_READ_OPERATIONS_MAX,
) -> PeImageProfile:
    """Collect one image's :class:`PeImageProfile` at ``actual_base``.

    ``read(addr, size) -> bytes`` is the only I/O performed, and it is
    treated as untrusted throughout: it may raise, return nothing, return
    a non-bytes-like object, or come up short, and none of that escapes.
    A caller reading a dump passes a callback over
    ``read_region_spanning()`` so a header legitimately split across two
    contiguous captured segments is a complete header rather than an
    unreadable one (§6.3).

    ``capture`` is the :class:`~dumpex.core.va_range.CapturedSlice` for the
    requested span, when the caller has a segment table to resolve one
    against. Supplying it is what lets the profile keep a collection gap
    (``captured < requested``) apart from a read failure over bytes that
    were present (``read < captured``); without it those two byte facts
    are simply not established, and the profile says so with ``None``
    rather than by guessing.

    ``requested_stage`` selects both how far acquisition goes and which
    components the profile's own state is folded over (§5.4.1), so a
    stage-1 request that answered its question completely stays
    distinguishable from a stage-3 request that failed.

    Never raises for hostile or truncated image bytes: an unrepresentable
    value yields a state, not an exception. A caller error -- an
    out-of-range base, an unsupported source kind, a source identity that
    §7.1.1 forbids -- does raise, because that is a defect in the calling
    code rather than a fact about the image.
    """
    if not isinstance(actual_base, int) or isinstance(actual_base, bool):
        raise ValueError(f"actual_base must be an int, got {type(actual_base).__name__}")
    source_kind = SourceKind(source_kind)
    if source_kind not in MEMORY_SOURCE_KINDS:
        raise ValueError(
            f"{source_kind.value} is indexed by file offset and carries its own "
            "provenance type (§5.1.1); this collector works in the target process's "
            "virtual address space")
    _validate_source_identity(source_kind, source_identity)
    requested_stage = _check_stage(requested_stage)
    if module_identity is not None and not isinstance(module_identity, ModuleIdentity):
        # A profile that called itself immutable while holding a caller's
        # list would be neither immutable nor bounded: the caller could
        # keep mutating it afterwards, and nothing would have applied
        # §10.3.1's length bound to whatever it contains.
        raise ValueError(
            f"module_identity must be a ModuleIdentity, got "
            f"{type(module_identity).__name__}")
    _check_positive_int(requested_bytes, "requested_bytes")
    _check_positive_int(max_read_operations, "max_read_operations")

    requested = VirtualRange(actual_base, requested_bytes)
    if capture is not None and capture.requested != requested:
        raise ValueError(
            "capture.requested must be the span this collection requests "
            f"({requested}), got {capture.requested}")

    acquisition = _Acquisition(
        read, actual_base, requested_bytes, max_read_operations,
        captured_bytes=None if capture is None else capture.captured_bytes)
    collector = _Collector(acquisition, requested_stage)
    collector.run()

    read_bytes = acquisition.read_len
    read_slice = None
    if capture is not None:
        # No clamp is needed here, and none is applied. A reader is under
        # no obligation to respect the segment table it was built from, so
        # the captured prefix bounds what the acquisition takes in
        # (`_Acquisition._ceiling`), not what this line reports: a clamp
        # at this point would shorten the provenance object over bytes
        # already decoded into header facts.
        read_slice = capture.read_input(read_bytes)

    facts = collector.facts
    directories = tuple(collector.directories)
    components = ComponentStates(
        dos_header=collector.states["dos_header"],
        coff_header=collector.states["coff_header"],
        optional_header=collector.states["optional_header"],
        directory_array=collector.states["directory_array"],
        directory_descriptors=collector.states["directory_descriptors"],
        section_table=collector.states["section_table"],
    )
    return PeImageProfile(
        source_kind=source_kind,
        source_identity=source_identity,
        module_identity=module_identity or ModuleIdentity.absent(),
        actual_base=actual_base,
        requested=requested,
        capture=capture,
        read=read_slice,
        read_bytes=read_bytes,
        read_target_bytes=acquisition.target,
        requested_stage=requested_stage,
        highest_completed_stage=collector.highest_completed_stage(),
        bounded_stop=acquisition.stop,
        has_mz=facts.get("has_mz"),
        e_lfanew=facts.get("e_lfanew"),
        has_pe_sig=facts.get("has_pe_sig"),
        machine=facts.get("machine"),
        machine_name=facts.get("machine_name"),
        number_of_sections=facts.get("number_of_sections"),
        time_date_stamp=facts.get("time_date_stamp"),
        pointer_to_symbol_table=facts.get("pointer_to_symbol_table"),
        number_of_symbols=facts.get("number_of_symbols"),
        size_of_optional_header=facts.get("size_of_optional_header"),
        coff_characteristics=facts.get("coff_characteristics"),
        is_pe32_plus=facts.get("is_pe32_plus"),
        address_of_entry_point=facts.get("address_of_entry_point"),
        base_of_code=facts.get("base_of_code"),
        preferred_image_base=facts.get("preferred_image_base"),
        section_alignment=facts.get("section_alignment"),
        file_alignment=facts.get("file_alignment"),
        size_of_image=facts.get("size_of_image"),
        size_of_headers=facts.get("size_of_headers"),
        checksum=facts.get("checksum"),
        subsystem=facts.get("subsystem"),
        dll_characteristics=facts.get("dll_characteristics"),
        declared_directory_count_raw=facts.get("declared_directory_count_raw"),
        declared_directory_count=facts.get("declared_directory_count"),
        readable_directory_count=facts.get("readable_directory_count"),
        unprojected_directory_count=facts.get("unprojected_directory_count"),
        directories=directories,
        sections=tuple(collector.sections),
        components=components,
        unexamined=collector._merged_unexamined(),
        relocation=_relocation_context(
            facts, actual_base, directories[_BASERELOC_DIRECTORY_INDEX]),
    )
