"""Behaviour of the staged, capture-aware PE image profile collector.

Every case here is one rule of
`docs/developer/pe_image_profile_contract.md` evaluated against
`dumpex.core.pe_profile` over synthetic bytes: the five component states
and what may and may not reach each of them, the three directory counts,
the sixteen descriptors, staged acquisition and its bounded stops, byte
provenance, and the boundary this module keeps with the shipped
`parse_pe_header()` vocabulary.
"""
from dataclasses import replace
import struct
import tracemalloc

import pytest

from dumpex.core.pe_utils import parse_pe_header, _MAX_SECTIONS
from dumpex.core.process_info import MAIN_IMAGE_PE_READ_MAX
from dumpex.core.va_range import (
    CapturedSegment, VirtualRange, slice_captured,
)
from dumpex.core.pe_profile import (
    DIRECTORY_NAMES,
    MAX_DIRECTORY_COUNT,
    MAX_E_LFANEW,
    MAX_STRING_BYTES,
    PEB_SOURCE_IDENTITY,
    PE_HEADER_READ_MAX,
    BoundedStop,
    ComponentState,
    ModuleIdentity,
    PeStage,
    SourceKind,
    collect_pe_image_profile,
    in_scope_components,
)

BASE = 0x140000000

MAGIC_PE32 = 0x10b
MAGIC_PE32_PLUS = 0x20b

_FIXED_PORTION = {MAGIC_PE32: 96, MAGIC_PE32_PLUS: 112}

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

TEXT = {"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
        "rawsize": 0x2000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}


def build_image(*, e_lfanew=0x80, mz=b"MZ", pe_signature=b"PE\x00\x00",
                machine=0x8664, sections=(TEXT,), time_date_stamp=0x12345678,
                coff_characteristics=0x0022, size_of_optional_header=None,
                magic=MAGIC_PE32_PLUS, entry_point=0x1000,
                image_base=BASE, base_of_code=0x1000, section_alignment=0x1000,
                file_alignment=0x200, size_of_image=0x5000, size_of_headers=0x400,
                checksum=0, subsystem=2, dll_characteristics=0x0040,
                number_of_rva_and_sizes=MAX_DIRECTORY_COUNT, directories=None,
                trailing=0x200, number_of_sections=None):
    """A PE image's header bytes, every structurally interesting field a
    keyword so a case can make exactly one of them hostile.

    `size_of_optional_header` defaults to a header exactly large enough
    for its format's fixed portion plus sixteen descriptors, so a case
    that shortens it is shortening a header that was otherwise whole.
    `directories` is a list of `(value, size)` pairs; the rest of the
    declared array is written as zeroes.
    """
    fixed_portion = _FIXED_PORTION.get(magic, 112)
    if size_of_optional_header is None:
        size_of_optional_header = fixed_portion + MAX_DIRECTORY_COUNT * 8
    if number_of_sections is None:
        number_of_sections = len(sections)

    dos = bytearray(max(e_lfanew, 0x40))
    dos[0:len(mz)] = mz
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    buf = bytearray(dos[:e_lfanew] if e_lfanew >= 0x40 else dos)
    buf += pe_signature
    buf += struct.pack("<HHIIIHH", machine, number_of_sections, time_date_stamp,
                       0, 0, size_of_optional_header, coff_characteristics)

    optional = bytearray(size_of_optional_header)

    def put(offset, fmt, value):
        if offset + struct.calcsize(fmt) <= len(optional):
            struct.pack_into(fmt, optional, offset, value)

    put(0, "<H", magic)
    put(16, "<I", entry_point)
    put(20, "<I", base_of_code)
    if magic == MAGIC_PE32:
        put(28, "<I", image_base & 0xFFFFFFFF)
    else:
        put(24, "<Q", image_base)
    put(32, "<I", section_alignment)
    put(36, "<I", file_alignment)
    put(56, "<I", size_of_image)
    put(60, "<I", size_of_headers)
    put(64, "<I", checksum)
    put(68, "<H", subsystem)
    put(70, "<H", dll_characteristics)
    put(fixed_portion - 4, "<I", number_of_rva_and_sizes)
    for index, (value, size) in enumerate(directories or ()):
        put(fixed_portion + index * 8, "<I", value)
        put(fixed_portion + index * 8 + 4, "<I", size)
    buf += optional

    for section in sections:
        record = bytearray(40)
        record[0:8] = section["name"][:8].ljust(8, b"\x00")
        struct.pack_into("<IIII", record, 8, section["vsize"], section["vaddr"],
                         section["rawsize"], section["rawptr"])
        struct.pack_into("<I", record, 36, section["chars"])
        buf += record

    return bytes(buf) + b"\x00" * trailing


def reader_over(data: bytes, base: int = BASE):
    """A `read(addr, size)` callback over one flat image, returning only
    the bytes that are actually there."""
    def read(addr, size):
        offset = addr - base
        if offset < 0:
            return b""
        return data[offset:offset + size]
    return read


def collect(data, base=BASE, **kwargs):
    kwargs.setdefault("source_kind", SourceKind.PEB_IMAGE_BASE)
    kwargs.setdefault("source_identity", "peb")
    return collect_pe_image_profile(reader_over(data, base), base, **kwargs)


def states(profile):
    """The in-scope component states as a plain `{name: state}` mapping."""
    return dict(profile.components.in_scope(profile.requested_stage))


def unexamined_covers(profile, start_offset, end_offset):
    """Whether `[start_offset, end_offset)` of the image is entirely
    inside the profile's unexamined set.

    Ranges are merged where they adjoin (§5.2), so one component's
    remainder and the next component's untouched bytes legitimately arrive
    as a single span; a membership test against an exact range would be
    testing the merge rather than the coverage.
    """
    wanted = VirtualRange.from_endpoints(BASE + start_offset, BASE + end_offset)
    return any(span.contains_range(wanted) for span in profile.unexamined)


# ── A whole image, and what "complete" means ────────────────────────────


def test_a_whole_image_completes_every_in_scope_component():
    profile = collect(build_image())
    assert states(profile) == {
        "dos_header": ComponentState.COMPLETE,
        "coff_header": ComponentState.COMPLETE,
        "optional_header": ComponentState.COMPLETE,
        "directory_array": ComponentState.COMPLETE,
        "directory_descriptors": ComponentState.COMPLETE,
        "section_table": ComponentState.COMPLETE,
    }
    assert profile.state is ComponentState.COMPLETE
    assert profile.highest_completed_stage is PeStage.SECTIONS
    assert profile.bounded_stop is None
    assert profile.unexamined == ()


def test_every_p0_field_is_decoded_from_its_own_offset():
    profile = collect(build_image(
        machine=0x014c, magic=MAGIC_PE32, image_base=0x400000,
        entry_point=0x1234, base_of_code=0x1000, section_alignment=0x2000,
        file_alignment=0x400, size_of_image=0x9000, size_of_headers=0x600,
        checksum=0xABCD, subsystem=3, dll_characteristics=0x0140,
        time_date_stamp=0x5F000000, coff_characteristics=0x0102))
    assert (profile.machine, profile.machine_name) == (0x014c, "I386")
    assert profile.is_pe32_plus is False
    assert profile.time_date_stamp == 0x5F000000
    assert profile.coff_characteristics == 0x0102
    assert profile.address_of_entry_point == 0x1234
    assert profile.base_of_code == 0x1000
    assert profile.preferred_image_base == 0x400000
    assert profile.section_alignment == 0x2000
    assert profile.file_alignment == 0x400
    assert profile.size_of_image == 0x9000
    assert profile.size_of_headers == 0x600
    assert profile.checksum == 0xABCD
    assert profile.subsystem == 3
    assert profile.dll_characteristics == 0x0140
    assert profile.number_of_sections == 1


def test_the_section_table_carries_every_declared_field():
    writable = dict(TEXT, name=b".data", vaddr=0x4000,
                    chars=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
    profile = collect(build_image(sections=(TEXT, writable)))
    text, data = profile.sections
    assert (text.section_index, text.name) == (0, ".text")
    assert (text.is_executable, text.is_writable, text.is_readable) == (True, False, True)
    assert (data.section_index, data.name) == (1, ".data")
    assert (data.is_executable, data.is_writable, data.is_readable) == (False, True, True)
    assert text.virtual_address == TEXT["vaddr"]
    assert text.size_of_raw_data == TEXT["rawsize"]
    assert text.pointer_to_raw_data == TEXT["rawptr"]


def test_a_profile_built_twice_from_the_same_bytes_is_identical():
    data = build_image(sections=(TEXT, dict(TEXT, name=b".rdata", vaddr=0x4000)),
                       directories=[(0x2000, 0x50)] * 16)
    assert collect(data) == collect(data)


# ── §2.1 / §2.2: identity, and the two bases ────────────────────────────


def test_the_source_kind_is_never_promoted_by_a_matching_base():
    profile = collect(build_image(image_base=BASE),
                      source_kind=SourceKind.MODULE_LIST_ENTRY, source_identity=3)
    assert profile.source_kind is SourceKind.MODULE_LIST_ENTRY
    assert profile.actual_base == BASE
    assert profile.relocation.relocation_delta == 0


def test_the_preferred_base_and_the_actual_base_are_separate_facts():
    profile = collect(build_image(image_base=0x180000000), base=BASE)
    assert profile.preferred_image_base == 0x180000000
    assert profile.actual_base == BASE
    assert profile.relocation.relocation_delta == BASE - 0x180000000


def test_a_disk_reference_is_refused_rather_than_read_as_virtual_addresses():
    with pytest.raises(ValueError, match="file offset"):
        collect(build_image(), source_kind=SourceKind.DISK_REFERENCE, source_identity=0)


@pytest.mark.parametrize("kind,identity", [
    (SourceKind.PEB_IMAGE_BASE, PEB_SOURCE_IDENTITY),
    (SourceKind.MODULE_LIST_ENTRY, 0),
    (SourceKind.MODULE_LIST_ENTRY, 41),
    (SourceKind.MEMORY_CANDIDATE, ("scan-1", 0x7FF000000000)),
    (SourceKind.MEMORY_CANDIDATE, (7, 0)),
])
def test_each_source_kind_takes_the_identity_shape_its_own_row_gives(kind, identity):
    profile = collect(build_image(), source_kind=kind, source_identity=identity)
    assert profile.source_identity == identity


@pytest.mark.parametrize("kind,identity", [
    # A kind may not take another kind's identity: `source_kind` names a
    # category and the identity is what separates two sources inside it,
    # so a shared shape is a shared key.
    (SourceKind.PEB_IMAGE_BASE, 0),
    (SourceKind.PEB_IMAGE_BASE, "peb-2"),
    (SourceKind.PEB_IMAGE_BASE, ("scan-1", 0)),
    (SourceKind.MODULE_LIST_ENTRY, PEB_SOURCE_IDENTITY),
    (SourceKind.MODULE_LIST_ENTRY, -1),
    (SourceKind.MODULE_LIST_ENTRY, True),
    (SourceKind.MODULE_LIST_ENTRY, ("scan-1", 0)),
    (SourceKind.MEMORY_CANDIDATE, PEB_SOURCE_IDENTITY),
    (SourceKind.MEMORY_CANDIDATE, 3),
    (SourceKind.MEMORY_CANDIDATE, ("scan-1",)),
    (SourceKind.MEMORY_CANDIDATE, ("scan-1", 0, 0)),
    (SourceKind.MEMORY_CANDIDATE, ("scan-1", -1)),
    (SourceKind.MEMORY_CANDIDATE, ("scan-1", 1 << 64)),
    (SourceKind.MEMORY_CANDIDATE, (None, 0)),
])
def test_an_identity_of_the_wrong_shape_for_its_kind_is_refused(kind, identity):
    with pytest.raises(ValueError, match="source_identity"):
        collect(build_image(), source_kind=kind, source_identity=identity)


@pytest.mark.parametrize("identity", [
    r"C:\Windows\System32\ntdll.dll",   # a path is not a token
    "ntdll.dll/../evil",                # nor is anything carrying a separator
    "s" * 65,                           # nor is an unbounded string
    "scan 1",                           # nor is anything outside the charset
])
def test_an_attacker_controlled_string_never_becomes_a_source_identity(identity):
    # §7.1.1 keeps paths and names out of anything a cache keys on. A
    # string admitted here would carry an attacker-controlled value past
    # the bound `ModuleIdentity` applies to exactly that kind of value.
    with pytest.raises(ValueError, match="source_identity"):
        collect(build_image(), source_kind=SourceKind.MEMORY_CANDIDATE,
                source_identity=(identity, BASE))


def test_a_path_length_identity_cannot_reach_the_profile_at_all():
    long_path = "C:\\" + "a" * MAX_STRING_BYTES + "\\x.dll"
    with pytest.raises(ValueError, match="source_identity"):
        collect(build_image(), source_kind=SourceKind.MODULE_LIST_ENTRY,
                source_identity=long_path)
    # The same string is legitimate evidence, and there it is bounded.
    identity = ModuleIdentity.of(long_path, "path")
    assert identity.truncated is True
    assert len(identity.value.encode("utf-8")) <= MAX_STRING_BYTES


# ── §2.1.1 / §10.3.1: module identity is a typed, bounded value ─────────


def test_an_unnamed_image_carries_an_identity_object_holding_a_null_value():
    profile = collect(build_image(), source_kind=SourceKind.MEMORY_CANDIDATE,
                      source_identity=("scan-1", BASE))
    assert profile.module_identity == ModuleIdentity(value=None, form=None, truncated=False)


def test_absence_has_exactly_one_encoding():
    assert ModuleIdentity.of(None, "path") == ModuleIdentity.absent()
    with pytest.raises(ValueError):
        ModuleIdentity(value=None, form="path")
    with pytest.raises(ValueError):
        ModuleIdentity(value="C:\\x.dll", form=None)
    with pytest.raises(ValueError):
        ModuleIdentity(value=None, truncated=True)


def test_a_null_value_is_not_an_empty_string():
    empty = ModuleIdentity.of("", "name")
    assert empty.value == "" and empty.form == "name"
    assert empty != ModuleIdentity.absent()


def test_a_long_identity_keeps_a_prefix_and_says_it_was_shortened():
    identity = ModuleIdentity.of("A" * (MAX_STRING_BYTES + 10), "path")
    assert identity.truncated is True
    assert identity.value == "A" * MAX_STRING_BYTES


def test_the_bound_is_utf8_bytes_and_never_splits_a_code_point():
    # Each of these is two UTF-8 bytes, so the limit lands exactly between
    # two of them only when the count is even; an odd cut keeps a shorter
    # prefix rather than half a character.
    identity = ModuleIdentity.of("é" * MAX_STRING_BYTES, "name")
    assert identity.truncated is True
    assert len(identity.value.encode("utf-8")) <= MAX_STRING_BYTES
    assert identity.value == "é" * (MAX_STRING_BYTES // 2)


def test_a_short_identity_is_not_marked_truncated():
    identity = ModuleIdentity.of("C:\\Windows\\System32\\ntdll.dll", "path")
    assert (identity.form, identity.truncated) == ("path", False)


# ── §3.1 / §5.3.1: the DOS header's determined defect ───────────────────


@pytest.mark.parametrize("available", [2, 4, 0x20, 0x40])
def test_a_wrong_mz_is_malformed_however_little_followed_it(available):
    profile = collect(build_image(mz=b"ZM")[:available])
    assert profile.components.dos_header is ComponentState.MALFORMED
    assert profile.has_mz is False
    assert profile.state is ComponentState.MALFORMED


@pytest.mark.parametrize("available", [0, 1])
def test_a_signature_read_in_part_establishes_nothing(available):
    profile = collect(build_image()[:available])
    assert profile.components.dos_header is ComponentState.UNAVAILABLE
    assert profile.has_mz is None


def test_a_dos_header_cut_before_e_lfanew_is_partial_with_a_named_remainder():
    profile = collect(build_image()[:0x30])
    assert profile.components.dos_header is ComponentState.PARTIAL
    assert profile.has_mz is True
    assert profile.e_lfanew is None
    assert unexamined_covers(profile, 0x30, 0x40)


def test_an_e_lfanew_below_four_is_malformed_from_bytes_that_were_all_read():
    profile = collect(build_image(e_lfanew=2))
    assert profile.components.dos_header is ComponentState.MALFORMED
    assert profile.e_lfanew == 2


# ── §2.6 / §6.2: an over-budget e_lfanew is a stop, never a defect ──────


def test_an_over_budget_e_lfanew_stops_the_acquisition_without_accusing_the_image():
    profile = collect(build_image(e_lfanew=MAX_E_LFANEW + 0x10), requested_bytes=1 << 16)
    assert profile.components.dos_header is ComponentState.COMPLETE
    assert profile.components.coff_header is ComponentState.UNAVAILABLE
    assert profile.state is ComponentState.UNAVAILABLE
    assert profile.bounded_stop == BoundedStop("e_lfanew", MAX_E_LFANEW, MAX_E_LFANEW + 0x10)


def test_the_shipped_parser_calls_that_same_image_a_deterministic_rejection():
    # The two vocabularies diverge here by construction (§11.6): the
    # shipped flag answers "will re-reading these bytes help?", the
    # profile answers "is the image defective?".
    data = build_image(e_lfanew=MAX_E_LFANEW + 0x10)
    shipped = parse_pe_header(data)
    assert (shipped["valid"], shipped["insufficient_data"]) == (False, False)
    assert collect(data, requested_bytes=1 << 16).state is ComponentState.UNAVAILABLE


# ── §3.2: the PE signature and the COFF header ──────────────────────────


def test_a_wrong_pe_signature_is_malformed_before_the_coff_fields_are_missed():
    profile = collect(build_image(pe_signature=b"XX\x00\x00")[:0x84])
    assert profile.components.coff_header is ComponentState.MALFORMED
    assert profile.has_pe_sig is False


def test_a_signature_read_in_part_leaves_the_component_partial():
    profile = collect(build_image()[:0x82])
    assert profile.components.coff_header is ComponentState.PARTIAL
    assert profile.has_pe_sig is None


def test_no_signature_byte_read_leaves_the_component_unavailable():
    profile = collect(build_image()[:0x80])
    assert profile.components.coff_header is ComponentState.UNAVAILABLE
    assert profile.has_pe_sig is None


def test_a_coff_header_cut_mid_field_is_partial_with_a_named_remainder():
    profile = collect(build_image()[:0x8C])
    assert profile.components.coff_header is ComponentState.PARTIAL
    assert profile.machine == 0x8664
    assert profile.size_of_optional_header is None
    assert unexamined_covers(profile, 0x8C, 0x98)


@pytest.mark.parametrize("count", [0, _MAX_SECTIONS + 1, 0xFFFF])
def test_a_section_count_no_image_can_declare_is_malformed(count):
    profile = collect(build_image(number_of_sections=count))
    assert profile.components.coff_header is ComponentState.MALFORMED
    assert profile.number_of_sections == count


def test_a_malformed_section_count_leaves_the_table_unlocatable_not_malformed():
    profile = collect(build_image(number_of_sections=200))
    assert profile.components.coff_header is ComponentState.MALFORMED
    assert profile.components.section_table is ComponentState.UNAVAILABLE
    assert profile.sections == ()


def test_an_unnamed_machine_value_is_reported_not_rejected():
    # `POWERPC` is a legitimate machine this contract has no name for.
    # The raw value is kept, only the name is null, and the rest of the
    # COFF header decodes like any other image's.
    data = build_image(machine=0x01f0)
    profile = collect(data)
    assert (profile.machine, profile.machine_name) == (0x01f0, None)
    assert profile.components.coff_header is ComponentState.COMPLETE
    assert profile.state is ComponentState.COMPLETE
    # The shipped parser stops there instead, which is the second named
    # divergence between the two vocabularies (§11.7).
    shipped = parse_pe_header(data)
    assert shipped["valid"] is False
    assert "unrecognized Machine" in shipped["reason"]
    assert shipped["is_pe32_plus"] is None


# ── §3.3.1: every optional-header field is bounded by its declared size ─


def test_a_field_past_the_declared_optional_header_is_never_read():
    # The shipped parser reads each field at its fixed offset regardless
    # of where the optional header was declared to end, so it returns
    # section-header bytes as `image_base` and a section's
    # `Characteristics` as `size_of_image` (§11.2.1.1). The profile reads
    # neither: past the declared size the bytes are section table.
    data = build_image(size_of_optional_header=20)
    shipped = parse_pe_header(data)
    assert shipped["image_base"] == 0x200000000074      # spans two section headers
    assert shipped["size_of_image"] == TEXT["chars"]    # the section's Characteristics

    profile = collect(data)
    assert profile.address_of_entry_point == 0x1000
    assert profile.preferred_image_base is None
    assert profile.size_of_image is None
    assert profile.relocation.relocation_delta is None


def test_a_header_too_small_for_the_format_its_magic_names_is_malformed():
    profile = collect(build_image(size_of_optional_header=20))
    assert profile.components.optional_header is ComponentState.MALFORMED
    # A malformed component is a state, not an erasure of its contents.
    assert profile.is_pe32_plus is True
    assert profile.address_of_entry_point == 0x1000


@pytest.mark.parametrize("magic,size", [(MAGIC_PE32, 95), (MAGIC_PE32_PLUS, 111)])
def test_the_threshold_is_the_formats_own_fixed_portion(magic, size):
    below = collect(build_image(magic=magic, size_of_optional_header=size))
    assert below.components.optional_header is ComponentState.MALFORMED
    at = collect(build_image(magic=magic, size_of_optional_header=size + 1,
                             number_of_rva_and_sizes=0))
    assert at.components.optional_header is ComponentState.COMPLETE


@pytest.mark.parametrize("size", [0, 1])
def test_a_header_too_small_to_hold_magic_leaves_the_profile_no_pointer_width(size):
    profile = collect(build_image(size_of_optional_header=size))
    assert profile.components.optional_header is ComponentState.UNAVAILABLE
    assert profile.is_pe32_plus is None
    assert profile.components.directory_array is ComponentState.UNAVAILABLE


def test_an_unrecognized_magic_is_malformed_and_selects_no_offsets():
    profile = collect(build_image(magic=0x30b))
    assert profile.components.optional_header is ComponentState.MALFORMED
    assert profile.is_pe32_plus is None
    assert profile.components.directory_array is ComponentState.UNAVAILABLE
    assert profile.declared_directory_count_raw is None
    assert all(d.state is ComponentState.UNAVAILABLE for d in profile.directories)


def test_an_optional_header_cut_mid_field_is_partial_with_a_named_remainder():
    profile = collect(build_image()[:0x98 + 40])
    assert profile.components.optional_header is ComponentState.PARTIAL
    assert profile.address_of_entry_point == 0x1000
    assert profile.size_of_image is None
    assert unexamined_covers(profile, 0x98 + 40, 0x98 + 72)


# ── §4.5: three counts, never folded into one ───────────────────────────


def test_a_declared_count_past_projection_scope_is_scope_not_a_defect():
    profile = collect(build_image(number_of_rva_and_sizes=200,
                                  size_of_optional_header=1712))
    assert profile.declared_directory_count_raw == 200
    assert profile.declared_directory_count == MAX_DIRECTORY_COUNT
    assert profile.readable_directory_count == MAX_DIRECTORY_COUNT
    assert profile.unprojected_directory_count == 184
    assert profile.components.directory_array is ComponentState.COMPLETE
    assert profile.bounded_stop is None


def test_an_array_that_does_not_fit_the_header_declaring_it_is_malformed():
    profile = collect(build_image(number_of_rva_and_sizes=200,
                                  size_of_optional_header=240))
    assert profile.components.directory_array is ComponentState.MALFORMED
    assert profile.state is ComponentState.MALFORMED


def test_the_capacity_bound_never_turns_a_contradiction_into_sixteen_denials():
    # `NumberOfRvaAndSizes = 16` in a PE32+ header declaring exactly 112
    # bytes puts the array where the section table starts. Folding the
    # capacity into the declared count would report all sixteen
    # directories `declared_absent` -- the opposite of what the image
    # said (§4.5's worked example).
    profile = collect(build_image(number_of_rva_and_sizes=16,
                                  size_of_optional_header=112))
    assert profile.declared_directory_count_raw == 16
    assert profile.declared_directory_count == 16
    assert profile.readable_directory_count == 0
    assert profile.components.directory_array is ComponentState.MALFORMED
    assert all(d.state is ComponentState.UNAVAILABLE for d in profile.directories)
    assert all(d.bytes_read == 0 for d in profile.directories)
    assert all(d.present is None for d in profile.directories)


def test_the_first_descriptor_never_comes_back_as_a_section_name():
    # Applying the array-level bound is what keeps the header's own
    # declared sizes from placing descriptors on top of the section table
    # (§11.2.1.2). The shipped parser reads them there and reports a
    # complete directory table; the profile reads none of it.
    data = build_image(number_of_rva_and_sizes=16, size_of_optional_header=112)
    shipped = parse_pe_header(data)
    assert shipped["directories_complete"] is True
    assert shipped["data_directories"][0] == struct.unpack("<II", b".text\x00\x00\x00")

    profile = collect(data)
    assert all(d.value is None and d.size is None for d in profile.directories)


def test_a_count_of_zero_declares_the_array_absent():
    profile = collect(build_image(number_of_rva_and_sizes=0))
    assert profile.declared_directory_count == 0
    assert profile.components.directory_array is ComponentState.DECLARED_ABSENT
    assert all(d.state is ComponentState.DECLARED_ABSENT for d in profile.directories)
    assert all(d.present is False for d in profile.directories)
    # A positively declared absence is an answered component, so it never
    # weakens the profile's own state.
    assert profile.components.directory_descriptors is ComponentState.COMPLETE
    assert profile.state is ComponentState.COMPLETE


def test_an_unread_count_leaves_both_counts_null_rather_than_zero():
    profile = collect(build_image()[:0x98 + 100])
    assert profile.declared_directory_count_raw is None
    assert profile.declared_directory_count is None
    assert profile.components.directory_array is ComponentState.UNAVAILABLE
    assert all(d.state is ComponentState.UNAVAILABLE for d in profile.directories)


# ── §4.1 / §4.3: the sixteen descriptors ────────────────────────────────


def test_all_sixteen_indices_are_always_present_in_index_order():
    profile = collect(build_image()[:0x40])
    assert len(profile.directories) == MAX_DIRECTORY_COUNT
    assert tuple(d.index for d in profile.directories) == tuple(range(16))
    assert tuple(d.name for d in profile.directories) == DIRECTORY_NAMES


def test_only_the_security_directory_is_indexed_by_file_offset():
    profile = collect(build_image())
    kinds = {d.index: d.value_kind for d in profile.directories}
    assert kinds.pop(4) == "file_offset"
    assert set(kinds.values()) == {"rva"}


def test_a_declared_directory_is_complete_and_a_zero_one_is_declared_absent():
    directories = [(0, 0)] * 16
    directories[1] = (0x3000, 0x28)
    profile = collect(build_image(directories=directories))
    imports = profile.directory(1)
    assert (imports.state, imports.present) == (ComponentState.COMPLETE, True)
    assert (imports.value, imports.size, imports.bytes_read) == (0x3000, 0x28, 8)
    exports = profile.directory(0)
    assert (exports.state, exports.present) == (ComponentState.DECLARED_ABSENT, False)


def test_a_zero_value_with_a_non_zero_size_is_still_declared_absent():
    directories = [(0, 0)] * 16
    directories[2] = (0, 0x100)
    profile = collect(build_image(directories=directories))
    assert profile.directory(2).state is ComponentState.DECLARED_ABSENT
    assert profile.directory(2).present is False


def test_a_non_zero_value_with_a_zero_size_is_still_present():
    directories = [(0, 0)] * 16
    directories[6] = (0x5000, 0)
    profile = collect(build_image(directories=directories))
    assert profile.directory(6).state is ComponentState.COMPLETE
    assert profile.directory(6).present is True


@pytest.mark.parametrize("extra,expected_state,expected_present", [
    (0, ComponentState.UNAVAILABLE, None),
    (3, ComponentState.PARTIAL, None),
    (4, ComponentState.PARTIAL, True),
    (7, ComponentState.PARTIAL, True),
    (8, ComponentState.COMPLETE, True),
])
def test_a_half_read_descriptor_is_partial_and_can_already_answer_presence(
        extra, expected_state, expected_present):
    directories = [(0x9000, 0x40)] * 16
    array_offset = 0x98 + 112
    profile = collect(build_image(directories=directories)[:array_offset + extra])
    descriptor = profile.directory(0)
    assert descriptor.bytes_read == extra
    assert descriptor.state is expected_state
    assert descriptor.present is expected_present
    assert descriptor.size == (0x40 if extra == 8 else None)


def test_a_partly_read_array_is_partial_with_the_shortfall_named():
    directories = [(0x9000, 0x40)] * 16
    array_offset = 0x98 + 112
    profile = collect(build_image(directories=directories)[:array_offset + 20])
    assert profile.components.directory_array is ComponentState.PARTIAL
    assert unexamined_covers(profile, array_offset + 20, array_offset + 128)


# ── §4.3.1: the three per-index format constraints ──────────────────────


@pytest.mark.parametrize("index,value,size", [
    (7, 0x1000, 0), (7, 0, 1), (7, 0x1000, 0x20),
    (8, 0x1000, 0x08), (8, 0, 0x08),
    (15, 0x1000, 0), (15, 0, 1),
])
def test_a_reserved_descriptor_holding_a_forbidden_value_is_malformed(index, value, size):
    directories = [(0, 0)] * 16
    directories[index] = (value, size)
    profile = collect(build_image(directories=directories))
    assert profile.directory(index).state is ComponentState.MALFORMED
    assert profile.directory(index).value == value
    assert profile.directory(index).size == size


def test_globalptr_keeps_a_real_rva_when_only_its_size_is_zero():
    directories = [(0, 0)] * 16
    directories[8] = (0x7000, 0)
    profile = collect(build_image(directories=directories))
    assert profile.directory(8).state is ComponentState.COMPLETE
    assert profile.directory(8).present is True


def test_a_constraint_is_only_read_over_a_descriptor_the_image_declared():
    # The count says the array ends at index 6, so the bytes at index 7's
    # offset are not a descriptor at all. Reading a violated constraint
    # there would report a defect from bytes the image never claimed.
    directories = [(0, 0)] * 16
    directories[7] = (0x1000, 0x20)
    profile = collect(build_image(directories=directories, number_of_rva_and_sizes=7))
    assert profile.directory(7).state is ComponentState.DECLARED_ABSENT
    assert profile.directory(7).present is False


def test_a_descriptor_that_is_not_fully_read_is_never_malformed():
    directories = [(0, 0)] * 16
    directories[7] = (0x1000, 0x20)
    array_offset = 0x98 + 112
    data = build_image(directories=directories)[:array_offset + 7 * 8 + 4]
    profile = collect(data)
    assert profile.directory(7).state is ComponentState.PARTIAL


@pytest.mark.parametrize("index", [i for i in range(16) if i not in (7, 8, 15)])
def test_no_other_index_can_reach_malformed(index):
    directories = [(0, 0)] * 16
    directories[index] = (0x1000, 0x20)
    profile = collect(build_image(directories=directories))
    assert profile.directory(index).state is ComponentState.COMPLETE


# ── §2.5: the Security Directory is never a process address ─────────────


def test_the_security_directory_is_reported_and_never_resolved():
    directories = [(0, 0)] * 16
    directories[4] = (0x12340, 0x1B8)
    profile = collect(build_image(directories=directories))
    security = profile.directory(4)
    assert (security.value, security.size) == (0x12340, 0x1B8)
    assert security.value_kind == "file_offset"
    assert security.state is ComponentState.COMPLETE
    assert not hasattr(security, "rva")
    # Nothing in the profile carries the resolved address a caller would
    # get from adding it to the base.
    assert BASE + 0x12340 not in {span.base_address for span in profile.unexamined}


def test_a_count_denying_index_four_declares_it_absent_from_the_counts_bytes():
    profile = collect(build_image(number_of_rva_and_sizes=4))
    assert profile.directory(4).state is ComponentState.DECLARED_ABSENT
    assert profile.directory(4).bytes_read == 0


# ── §3.5: relocation context, derived and never folded ──────────────────


def test_each_relocation_fact_is_established_on_its_own_fields_bytes():
    directories = [(0, 0)] * 16
    directories[5] = (0x6000, 0x200)
    profile = collect(build_image(directories=directories, coff_characteristics=0x0022,
                                  dll_characteristics=0x0040, image_base=0x140000000))
    relocation = profile.relocation
    assert relocation.relocs_stripped is False
    assert relocation.dynamic_base is True
    assert relocation.basereloc_present is True
    assert relocation.basereloc_descriptor_state is ComponentState.COMPLETE
    assert relocation.relocation_delta == 0


def test_a_defect_elsewhere_in_the_source_component_erases_nothing():
    profile = collect(build_image(number_of_sections=200, coff_characteristics=0x0001))
    assert profile.components.coff_header is ComponentState.MALFORMED
    assert profile.relocation.relocs_stripped is True


def test_an_unread_flag_is_null_never_a_default():
    profile = collect(build_image()[:0x8C])
    assert profile.relocation.relocs_stripped is None
    assert profile.relocation.dynamic_base is None
    assert profile.relocation.basereloc_present is None


def test_a_half_read_index_five_has_already_settled_presence():
    directories = [(0, 0)] * 16
    directories[5] = (0x6000, 0x200)
    array_offset = 0x98 + 112
    profile = collect(build_image(directories=directories)[:array_offset + 5 * 8 + 4])
    assert profile.relocation.basereloc_descriptor_state is ComponentState.PARTIAL
    assert profile.relocation.basereloc_present is True


def test_an_uncaptured_count_leaves_presence_null_however_many_bytes_follow():
    profile = collect(build_image()[:0x98 + 100])
    assert profile.relocation.basereloc_present is None
    assert profile.relocation.basereloc_descriptor_state is ComponentState.UNAVAILABLE


# ── §3.4 / §6: the section table and the acquisition budget ─────────────


def test_a_section_table_cut_mid_entry_is_partial_with_the_shortfall_named():
    sections = tuple(dict(TEXT, name=b".s%d" % i, vaddr=0x1000 * (i + 1)) for i in range(4))
    data = build_image(sections=sections)
    table_offset = 0x98 + 240
    profile = collect(data[:table_offset + 90])
    assert profile.components.section_table is ComponentState.PARTIAL
    assert len(profile.sections) == 2
    assert unexamined_covers(profile, table_offset + 90, table_offset + 160)


def test_a_table_no_byte_of_which_was_read_is_unavailable():
    sections = (TEXT, dict(TEXT, name=b".data", vaddr=0x4000))
    table_offset = 0x98 + 240
    profile = collect(build_image(sections=sections)[:table_offset])
    assert profile.components.section_table is ComponentState.UNAVAILABLE
    assert profile.sections == ()


def wide_table_image():
    """A legal image whose declared section table runs past the default
    4096-byte acquisition budget."""
    sections = tuple(dict(TEXT, name=b".s%02d" % i, vaddr=0x1000 * (i + 1))
                     for i in range(96))
    data = build_image(sections=sections, trailing=0)
    assert len(data) > PE_HEADER_READ_MAX
    return data


# §6.3: crossing a captured-segment boundary is not a shortfall. Every
# byte the header needs is present, so the header is whole however many
# segments the dump split it into.


@pytest.mark.parametrize("split", [0x20, 0x90, 0x100, 0x188])
def test_a_header_split_across_contiguous_segments_completes(split):
    data = build_image()

    def read(addr, size):
        # A reader that stops at every segment boundary, the way a
        # protection change partway through a header splits one.
        offset = addr - BASE
        limit = split if offset < split else len(data)
        return data[offset:min(offset + size, limit)]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb")
    assert profile.state is ComponentState.COMPLETE
    assert profile.bounded_stop is None


def test_a_wide_table_split_across_segments_completes_under_a_wide_request():
    data = wide_table_image()

    def read(addr, size):
        offset = addr - BASE
        limit = next((edge for edge in (0x90, 0x400, 0x900) if offset < edge), len(data))
        return data[offset:min(offset + size, limit)]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
        requested_bytes=len(data))
    assert profile.components.section_table is ComponentState.COMPLETE
    assert len(profile.sections) == 96


# §6.1/§6.2: the default budget stays 4096, and reaching it is a bounded
# stop -- `partial` where the limit lands inside a component, or
# `unavailable` where it lands before one, and never `malformed`.


def test_the_default_request_is_the_frozen_four_kilobyte_budget():
    assert collect(build_image()).requested.size == PE_HEADER_READ_MAX


def test_a_table_past_the_default_budget_is_partial_with_its_budget_attributed():
    profile = collect(wide_table_image())
    assert profile.components.section_table is ComponentState.PARTIAL
    assert profile.bounded_stop == BoundedStop(
        "pe_header_bytes", PE_HEADER_READ_MAX, PE_HEADER_READ_MAX)
    assert profile.state is ComponentState.PARTIAL
    # A budget is a fact about dumpex, so it never accuses the image.
    assert ComponentState.MALFORMED not in states(profile).values()


def test_a_budget_landing_before_a_component_leaves_it_unavailable_not_partial():
    # The limit falls exactly on the section table's first byte, so
    # nothing of that component was read.
    table_offset = 0x98 + 240
    profile = collect(wide_table_image(), requested_bytes=table_offset)
    assert profile.components.section_table is ComponentState.UNAVAILABLE
    assert profile.bounded_stop.scope == "pe_header_bytes"
    assert profile.state is ComponentState.UNAVAILABLE
    assert ComponentState.MALFORMED not in states(profile).values()


# A caller may ask for more, and the same table then completes. The wider
# span is the caller's explicit request, carried on the profile so a
# future cache keys on it (§7.1) rather than inheriting it as a default.


def test_the_same_table_completes_when_the_caller_asks_for_a_wider_span():
    data = wide_table_image()
    profile = collect(data, requested_bytes=len(data))
    assert profile.components.section_table is ComponentState.COMPLETE
    assert len(profile.sections) == 96
    assert profile.bounded_stop is None
    assert profile.state is ComponentState.COMPLETE
    assert profile.requested.size == len(data)


def test_a_wider_span_is_the_callers_request_and_never_a_new_default():
    data = wide_table_image()
    wide = collect(data, requested_bytes=len(data))
    default = collect(data)
    assert wide.requested != default.requested
    assert default.requested.size == PE_HEADER_READ_MAX
    assert default.components.section_table is ComponentState.PARTIAL


def test_a_read_operation_budget_bounds_a_reader_that_only_trickles():
    data = build_image()

    def read(addr, size):
        return data[addr - BASE:addr - BASE + 1]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
        max_read_operations=8)
    assert profile.bounded_stop == BoundedStop("pe_header_read_operations", 8, 8)
    assert profile.read_bytes == 8


# ── §5.4: the two folds ─────────────────────────────────────────────────


def test_a_stage_one_request_folds_only_what_it_asked_for():
    profile = collect(build_image()[:0x98], requested_stage=PeStage.COFF)
    assert profile.state is ComponentState.COMPLETE
    assert profile.highest_completed_stage is PeStage.COFF
    assert set(states(profile)) == {"dos_header", "coff_header"}


def test_a_component_outside_the_requested_stage_is_not_part_of_the_answer():
    profile = collect(build_image(), requested_stage=PeStage.COFF)
    assert profile.components.section_table is None
    assert profile.components.optional_header is None
    assert profile.sections == ()


def test_a_completed_short_request_stays_distinguishable_from_a_failed_long_one():
    short = collect(build_image()[:0x98], requested_stage=PeStage.COFF)
    long = collect(build_image()[:0x98], requested_stage=PeStage.SECTIONS)
    assert short.state is ComponentState.COMPLETE
    assert long.state is ComponentState.UNAVAILABLE
    assert short.requested_stage != long.requested_stage


def test_malformed_outranks_a_gap_sitting_beside_it():
    profile = collect(build_image(magic=0x30b)[:0x98 + 4])
    scoped = states(profile)
    assert ComponentState.MALFORMED in scoped.values()
    assert ComponentState.UNAVAILABLE in scoped.values()
    assert profile.state is ComponentState.MALFORMED


def test_the_rollup_never_replaces_the_components_that_did_decode():
    profile = collect(build_image(magic=0x30b))
    assert profile.state is ComponentState.MALFORMED
    assert profile.components.coff_header is ComponentState.COMPLETE
    assert profile.machine_name == "AMD64"
    assert profile.size_of_optional_header == 240


@pytest.mark.parametrize("stage,expected", [
    (PeStage.DOS, ("dos_header",)),
    (PeStage.COFF, ("dos_header", "coff_header")),
    (PeStage.OPTIONAL, ("dos_header", "coff_header", "optional_header",
                        "directory_array", "directory_descriptors")),
    (PeStage.SECTIONS, ("dos_header", "coff_header", "optional_header",
                        "directory_array", "directory_descriptors", "section_table")),
])
def test_the_in_scope_set_is_the_cumulative_yields_of_the_stages(stage, expected):
    assert in_scope_components(stage) == expected


def test_the_descriptors_fold_as_one_unit_never_as_sixteen_members():
    profile = collect(build_image())
    scoped = states(profile)
    assert len(scoped) == 6
    assert "directory_descriptors" in scoped


# ── §5.1: three independent byte facts ──────────────────────────────────


def _capture(base, requested_bytes, captured_bytes):
    requested = VirtualRange(base, requested_bytes)
    segments = ([CapturedSegment(VirtualRange(base, captured_bytes), file_offset=0x1000)]
                if captured_bytes else [])
    return slice_captured(requested, segments)


def test_a_collection_gap_and_a_read_failure_stay_separate_facts():
    data = build_image()
    capture = _capture(BASE, PE_HEADER_READ_MAX, 0x300)

    def read(addr, size):
        # The dump backs 0x300 bytes; this read hands back only 0x150 of
        # them, which is fewer than the ladder needs.
        offset = addr - BASE
        return data[offset:min(offset + size, 0x150)]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
        capture=capture)
    assert profile.capture.captured_bytes == 0x300
    assert profile.read.read_bytes == 0x150
    # The gap the dump left and the shortfall the read produced are two
    # facts with two different remedies, and neither is folded into the
    # other.
    assert profile.capture.uncaptured_suffix.size == PE_HEADER_READ_MAX - 0x300
    assert profile.read.is_io_short is True
    assert profile.read.is_short is True


def test_a_healthy_collection_over_a_full_capture_is_not_a_read_failure():
    # The dump backs the whole 4096-byte request and the reader hands back
    # everything asked for. The ladder still stops at the end of the
    # header, which is not a shortfall of any kind.
    data = build_image() + b"\x00" * (PE_HEADER_READ_MAX - len(build_image()))
    profile = collect_pe_image_profile(
        reader_over(data), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", capture=_capture(BASE, PE_HEADER_READ_MAX,
                                                PE_HEADER_READ_MAX))
    assert profile.state is ComponentState.COMPLETE
    assert profile.capture.captured_bytes == PE_HEADER_READ_MAX
    assert profile.read_bytes == profile.read_target_bytes
    assert profile.read_bytes < profile.capture.captured_bytes
    # The shared byte fact says "shorter than the capture", which is true
    # and is not a failure. The profile's own target is what settles it.
    assert profile.read.is_io_short is True
    assert profile.target_io_short is False


def test_a_read_that_came_up_short_of_what_the_stages_asked_for_is_a_failure():
    data = build_image()

    def read(addr, size):
        offset = addr - BASE
        return data[offset:min(offset + size, 0x150)]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
        capture=_capture(BASE, PE_HEADER_READ_MAX, PE_HEADER_READ_MAX))
    assert profile.read_bytes == 0x150
    assert profile.read_target_bytes > profile.read_bytes
    assert profile.target_io_short is True


def test_a_bounded_stop_is_never_reported_as_a_read_failure():
    data = wide_table_image()
    profile = collect_pe_image_profile(
        reader_over(data), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", capture=_capture(BASE, PE_HEADER_READ_MAX,
                                                PE_HEADER_READ_MAX))
    assert profile.bounded_stop is not None
    assert profile.read_target_bytes > PE_HEADER_READ_MAX
    assert profile.target_io_short is False


def test_the_target_is_what_the_stages_asked_for_not_what_the_budget_allowed():
    # Recorded as asked, before the byte budget clamps it, so a request
    # the budget refused stays visible as a request.
    data = wide_table_image()
    profile = collect(data)
    table_end = 0x98 + 240 + 96 * 40
    assert profile.read_target_bytes == table_end
    assert profile.read_bytes == PE_HEADER_READ_MAX


def test_a_stage_one_request_asks_for_less_than_a_stage_three_one():
    data = build_image()
    assert (collect(data, requested_stage=PeStage.COFF).read_target_bytes
            < collect(data, requested_stage=PeStage.SECTIONS).read_target_bytes)


def test_absent_provenance_is_null_not_a_claim_that_nothing_was_captured():
    profile = collect(build_image())
    assert profile.capture is None and profile.read is None
    assert profile.read_bytes > 0


def test_a_capture_for_a_different_span_is_refused():
    with pytest.raises(ValueError, match="capture.requested"):
        collect(build_image(), capture=_capture(BASE, 0x800, 0x800))


# ── §5.2 / §10.2: unexamined ranges are canonical ───────────────────────


def test_unexamined_ranges_ascend_and_are_merged_where_they_adjoin():
    profile = collect(build_image()[:0x30])
    bases = [span.base_address for span in profile.unexamined]
    assert bases == sorted(bases)
    for earlier, later in zip(profile.unexamined, profile.unexamined[1:]):
        assert earlier.end_address < later.base_address


def test_a_malformed_component_still_names_the_bytes_nothing_looked_at():
    profile = collect(build_image(pe_signature=b"XX\x00\x00")[:0x84])
    assert profile.components.coff_header is ComponentState.MALFORMED
    assert unexamined_covers(profile, 0x84, 0x98)


def test_a_whole_image_leaves_nothing_unexamined():
    assert collect(build_image()).unexamined == ()


# ── §10.3: hostile input never escapes as an exception ──────────────────


@pytest.mark.parametrize("hostile", [
    lambda addr, size: (_ for _ in ()).throw(RuntimeError("reader exploded")),
    lambda addr, size: None,
    lambda addr, size: 4096,
    lambda addr, size: "not bytes",
    lambda addr, size: b"",
])
def test_a_reader_that_misbehaves_yields_a_state_not_an_exception(hostile):
    profile = collect_pe_image_profile(
        hostile, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb")
    assert profile.state is ComponentState.UNAVAILABLE
    assert profile.read_bytes == 0
    assert profile.has_mz is None


def test_a_reader_returning_more_than_it_was_asked_for_is_clipped():
    data = build_image()

    def read(addr, size):
        return data[addr - BASE:] + b"\xff" * 8192

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb")
    assert profile.read_bytes <= PE_HEADER_READ_MAX
    assert profile.state is ComponentState.COMPLETE


def test_a_section_name_of_hostile_bytes_is_decoded_never_raised_on():
    hostile = dict(TEXT, name=b"\xff\xfe\x80\x01\x02")
    profile = collect(build_image(sections=(hostile,)))
    assert profile.sections[0].name == "ÿþ\x80\x01\x02"
    assert profile.components.section_table is ComponentState.COMPLETE


def test_a_base_at_the_top_of_the_address_space_is_refused_not_wrapped():
    with pytest.raises(Exception):
        collect(build_image(), base=(1 << 64) - 0x10)


# ── The frozen constants, bound to what the codebase already ships ──────


def test_the_header_read_budget_is_the_one_the_codebase_already_uses():
    assert PE_HEADER_READ_MAX == MAIN_IMAGE_PE_READ_MAX


def test_the_projection_scope_is_the_sixteen_named_indices():
    assert MAX_DIRECTORY_COUNT == len(DIRECTORY_NAMES) == 16


# ── Agreement with the shipped parser where both are defined ────────────


def test_a_well_formed_image_agrees_with_the_shipped_parser_field_for_field():
    directories = [(0, 0)] * 16
    directories[1] = (0x3000, 0x28)
    directories[5] = (0x6000, 0x200)
    data = build_image(directories=directories,
                       sections=(TEXT, dict(TEXT, name=b".data", vaddr=0x4000)))
    shipped = parse_pe_header(data)
    profile = collect(data)

    assert shipped["valid"] is True and profile.state is ComponentState.COMPLETE
    assert (shipped["has_mz"], shipped["has_pe_sig"]) == (profile.has_mz, profile.has_pe_sig)
    assert shipped["e_lfanew"] == profile.e_lfanew
    assert shipped["machine"] == profile.machine
    assert shipped["machine_name"] == profile.machine_name
    assert shipped["time_date_stamp"] == profile.time_date_stamp
    assert shipped["is_pe32_plus"] == profile.is_pe32_plus
    assert shipped["number_of_sections"] == profile.number_of_sections
    assert shipped["size_of_image"] == profile.size_of_image
    assert shipped["address_of_entry_point"] == profile.address_of_entry_point
    assert shipped["image_base"] == profile.preferred_image_base
    assert shipped["declared_directory_count"] == profile.declared_directory_count
    assert shipped["data_directories"] == [
        (d.value, d.size) for d in profile.directories]
    assert [s["name"] for s in shipped["sections"]] == [s.name for s in profile.sections]
    assert [s["virtual_address"] for s in shipped["sections"]] == [
        s.virtual_address for s in profile.sections]


# ── Guards: a caller error raises, an image never does ──────────────────


def test_an_optional_header_with_magic_unread_decodes_no_format_selected_field():
    profile = collect(build_image()[:0x98 + 1])
    assert profile.components.optional_header is ComponentState.PARTIAL
    assert profile.is_pe32_plus is None
    assert profile.preferred_image_base is None
    assert profile.address_of_entry_point is None


def test_a_stage_two_request_stops_before_the_section_table():
    profile = collect(build_image(), requested_stage=PeStage.OPTIONAL)
    assert profile.state is ComponentState.COMPLETE
    assert profile.highest_completed_stage is PeStage.OPTIONAL
    assert profile.components.section_table is None
    assert profile.sections == ()


def test_a_boolean_is_not_a_source_identity_token():
    with pytest.raises(ValueError, match="source_identity"):
        collect(build_image(), source_identity=True)


def test_an_unknown_module_identity_form_is_refused():
    with pytest.raises(ValueError, match="module_identity.form"):
        ModuleIdentity(value="ntdll.dll", form="basename")


def test_asking_for_a_component_that_does_not_exist_is_a_key_error():
    with pytest.raises(KeyError):
        collect(build_image()).components.state_of("nope")


@pytest.mark.parametrize("kwargs,match", [
    ({"actual_base": "0x140000000"}, "actual_base"),
    ({"requested_bytes": 0}, "requested_bytes"),
    ({"max_read_operations": 0}, "max_read_operations"),
])
def test_a_caller_error_raises_rather_than_producing_a_profile(kwargs, match):
    base = kwargs.pop("actual_base", BASE)
    with pytest.raises(ValueError, match=match):
        collect_pe_image_profile(
            reader_over(build_image()), base, source_kind=SourceKind.PEB_IMAGE_BASE,
            source_identity="peb", **kwargs)


def test_a_component_extent_that_would_overflow_the_address_space_names_no_range():
    # A legal `e_lfanew` at the very top of the space places the COFF
    # header past the end of it. §2.6's arithmetic is checked, so nothing
    # is recorded rather than a wrapped range naming bytes at another
    # address.
    top_base = (1 << 64) - 0x1010
    data = build_image(e_lfanew=MAX_E_LFANEW)
    profile = collect_pe_image_profile(
        reader_over(data, top_base), top_base, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", requested_bytes=0x100)
    assert profile.components.dos_header is ComponentState.COMPLETE
    assert profile.components.coff_header is ComponentState.UNAVAILABLE
    assert all(span.end_address <= 1 << 64 for span in profile.unexamined)


def test_a_reader_handing_back_an_unusable_buffer_is_a_failed_read():
    def read(addr, size):
        buffer = memoryview(bytearray(size))
        buffer.release()
        return buffer

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb")
    assert profile.read_bytes == 0
    assert profile.state is ComponentState.UNAVAILABLE


@pytest.mark.parametrize("mutation,match", [
    ({"directories": ()}, "directory descriptors"),
    ({"sections": ()}, None),
])
def test_a_profile_enforces_its_own_structural_order(mutation, match):
    profile = collect(build_image(sections=(TEXT, dict(TEXT, name=b".data",
                                                       vaddr=0x4000))))
    if mutation.get("directories") == ():
        with pytest.raises(ValueError, match="directory descriptors"):
            replace(profile, directories=profile.directories[:15])
        with pytest.raises(ValueError, match="index order"):
            replace(profile, directories=profile.directories[::-1])
    else:
        with pytest.raises(ValueError, match="section-table order"):
            replace(profile, sections=profile.sections[::-1])


def test_a_profile_refuses_unexamined_ranges_that_are_not_canonical():
    profile = collect(build_image()[:0x30])
    span = profile.unexamined[0]
    with pytest.raises(ValueError, match="unexamined ranges"):
        replace(profile, unexamined=(span, span))


# ── §5.4.3: the worked examples of the fold ─────────────────────────────


def test_a_structurally_perfect_image_folds_to_complete_over_six_components():
    # Indices 7 and 15 are required by the format to be zero, so they are
    # `declared_absent` members. A member state never appears in the
    # profile's own column: the unit fold answers them, and what enters
    # the outer fold is one `complete` `directory_descriptors`.
    directories = [(0x1000 * (i + 2), 0x40) for i in range(16)]
    directories[7] = (0, 0)        # ARCHITECTURE is reserved in full
    directories[8] = (0xA000, 0)   # GLOBALPTR carries an RVA and no size
    directories[15] = (0, 0)       # RESERVED is reserved in full
    profile = collect(build_image(directories=directories))
    assert profile.directory(7).state is ComponentState.DECLARED_ABSENT
    assert profile.directory(15).state is ComponentState.DECLARED_ABSENT
    assert profile.components.directory_descriptors is ComponentState.COMPLETE
    assert list(states(profile).values()) == [ComponentState.COMPLETE] * 6
    assert profile.state is ComponentState.COMPLETE


def test_a_state_leaking_outside_the_requested_stage_is_refused():
    # "The question was not asked" and "the question was asked and got no
    # answer" are different facts. A single leaked `UNAVAILABLE` outside
    # the stage would turn a completed short request into a failed long
    # one, so the boundary is enforced rather than documented.
    profile = collect(build_image(), requested_stage=PeStage.COFF)
    with pytest.raises(ValueError, match="outside the requested stage"):
        replace(profile, components=replace(
            profile.components, section_table=ComponentState.UNAVAILABLE))


def test_a_missing_state_inside_the_requested_stage_is_refused():
    profile = collect(build_image())
    with pytest.raises(ValueError, match="inside the requested stage"):
        replace(profile, components=replace(profile.components, section_table=None))


# ── The degenerate case: no capture provenance at all ───────────────────


def test_without_capture_provenance_an_unmet_target_is_undetermined():
    # Nothing establishes whether the missing bytes were never captured or
    # were captured and not returned, and those two have different
    # remedies. The answer is neither, and no field stands in for the
    # evidence `capture=None` says was not supplied.
    data = build_image()

    def read(addr, size):
        offset = addr - BASE
        return data[offset:min(offset + size, 0x150)]

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb")
    assert profile.capture is None and profile.read is None
    assert profile.read_bytes < profile.read_target_bytes
    assert profile.target_io_short is None


def test_without_capture_provenance_a_met_target_is_still_determined():
    # A target that was met needs no capture to settle: every byte the
    # stages asked for arrived, whatever the segment table would have
    # said about the rest.
    profile = collect(build_image())
    assert profile.capture is None
    assert profile.read_bytes == profile.read_target_bytes
    assert profile.target_io_short is False


def test_a_capture_gap_alone_is_not_an_io_shortfall():
    # The dump never captured the bytes the ladder wanted, and the read
    # returned everything the dump does hold. That is a collection gap,
    # not a read failure.
    data = build_image()
    profile = collect_pe_image_profile(
        reader_over(data[:0x150]), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", capture=_capture(BASE, PE_HEADER_READ_MAX, 0x150))
    assert profile.read_bytes == 0x150 == profile.capture.captured_bytes
    assert profile.read_bytes < profile.read_target_bytes
    assert profile.target_io_short is False
    assert profile.capture.uncaptured_suffix.size == PE_HEADER_READ_MAX - 0x150


# ── §5.1: a capture ceiling bounds the bytes, not just the provenance ───


def test_bytes_the_capture_denies_never_reach_a_component():
    # A reader is under no obligation to respect the segment table it was
    # built from. Shortening only the `ReadSlice` afterwards would leave
    # the surplus already decoded, promoting bytes the dump never captured
    # into complete PE facts.
    data = build_image()
    profile = collect_pe_image_profile(
        reader_over(data), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", capture=_capture(BASE, PE_HEADER_READ_MAX, 64))
    assert profile.read_bytes == 64
    assert profile.read.read_bytes == 64
    assert profile.components.dos_header is ComponentState.COMPLETE
    assert profile.components.coff_header is ComponentState.UNAVAILABLE
    assert profile.components.section_table is ComponentState.UNAVAILABLE
    assert profile.sections == ()
    assert profile.state is ComponentState.UNAVAILABLE


@pytest.mark.parametrize("captured", [0, 1, 0x40, 0x98, 0x150, 0x188])
def test_the_read_never_exceeds_what_the_capture_backs(captured):
    data = build_image()
    profile = collect_pe_image_profile(
        reader_over(data), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb",
        capture=_capture(BASE, PE_HEADER_READ_MAX, captured))
    assert profile.read_bytes <= captured
    assert profile.read_bytes <= profile.capture.captured_bytes
    assert profile.capture.captured_bytes <= profile.requested.size


def test_a_capture_ceiling_is_a_gap_and_never_a_bounded_stop():
    # Reaching the end of the captured prefix is the dump not holding the
    # bytes. Attributing it to a budget would report a limit of this tool
    # over bytes that were never there.
    data = build_image()
    profile = collect_pe_image_profile(
        reader_over(data), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb", capture=_capture(BASE, PE_HEADER_READ_MAX, 0x150))
    assert profile.read_bytes == 0x150
    assert profile.bounded_stop is None
    assert profile.components.section_table is ComponentState.UNAVAILABLE
    assert ComponentState.MALFORMED not in states(profile).values()


def test_a_full_capture_still_lets_the_byte_budget_bind_and_attribute():
    # `captured == requested` means the whole request was captured, so
    # running past it is running past the request -- which is the budget,
    # and it is attributed.
    profile = collect_pe_image_profile(
        reader_over(wide_table_image()), BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
        source_identity="peb",
        capture=_capture(BASE, PE_HEADER_READ_MAX, PE_HEADER_READ_MAX))
    assert profile.bounded_stop == BoundedStop(
        "pe_header_bytes", PE_HEADER_READ_MAX, PE_HEADER_READ_MAX)
    assert profile.components.section_table is ComponentState.PARTIAL


def test_an_oversized_reader_under_a_capture_cannot_inflate_the_read():
    data = build_image()

    def read(addr, size):
        return data[addr - BASE:] + b"\xff" * 8192

    profile = collect_pe_image_profile(
        read, BASE, source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
        capture=_capture(BASE, PE_HEADER_READ_MAX, 0x40))
    assert profile.read_bytes == 0x40
    assert profile.components.coff_header is ComponentState.UNAVAILABLE


# ── Immutability and the bounds that make it mean something ────────────


@pytest.mark.parametrize("identity", [["mutable"], "ntdll.dll", {"value": None}, 0])
def test_a_caller_object_that_is_not_an_identity_never_enters_a_profile(identity):
    # A profile holding a caller's list would be neither immutable -- the
    # caller can keep mutating it -- nor bounded, since nothing applied
    # §10.3.1 to whatever it contains.
    with pytest.raises(ValueError, match="module_identity"):
        collect(build_image(), module_identity=identity)


def test_replacing_a_profiles_identity_with_a_mutable_object_is_refused():
    profile = collect(build_image())
    with pytest.raises(ValueError, match="module_identity"):
        replace(profile, module_identity=["mutable"])


@pytest.mark.parametrize("value", [b"ntdll.dll", 7, ["ntdll.dll"]])
def test_an_identity_value_that_is_not_a_string_is_refused(value):
    with pytest.raises(ValueError, match="module_identity.value"):
        ModuleIdentity(value=value, form="name")


@pytest.mark.parametrize("truncated", [1, "yes", None])
def test_an_identity_truncated_flag_that_is_not_a_bool_is_refused(truncated):
    with pytest.raises(ValueError, match="module_identity.truncated"):
        ModuleIdentity(value="ntdll.dll", form="name", truncated=truncated)


@pytest.mark.parametrize("value", [
    "a" * (MAX_STRING_BYTES + 1),        # one character over, in bytes too
    "é" * (MAX_STRING_BYTES // 2 + 1),   # inside the character count, over in bytes
])
def test_an_identity_longer_than_the_bound_cannot_be_constructed(value):
    # Constructing one directly must not be a way around §10.3.1: it would
    # carry an attacker-sized string into a value the profile calls
    # bounded, with `truncated` falsely reading False.
    with pytest.raises(ValueError, match="UTF-8 bytes"):
        ModuleIdentity(value=value, form="path")
    # The supported route keeps a prefix and says that it did.
    bounded = ModuleIdentity.of(value, "path")
    assert bounded.truncated is True
    assert len(bounded.value.encode("utf-8")) <= MAX_STRING_BYTES


def test_a_value_at_exactly_the_bound_is_accepted_and_not_marked_truncated():
    identity = ModuleIdentity.of("a" * MAX_STRING_BYTES, "path")
    assert identity.truncated is False
    assert len(identity.value.encode("utf-8")) == MAX_STRING_BYTES
    assert ModuleIdentity(value=identity.value, form="path") == identity


def test_bounding_a_string_never_allocates_at_the_attackers_size():
    # Encoding first and cutting afterwards would allocate a buffer the
    # size of the attacker's own string -- larger, since a hostile code
    # point encodes to four bytes -- to produce a 4096-byte result, which
    # is the allocation the bound exists to prevent. The character prefix
    # is taken before anything is encoded, so the cost is bounded at four
    # bytes per kept character however long the source is.
    huge = "\U0001F600" * (MAX_STRING_BYTES * 16)    # four UTF-8 bytes each
    whole_encoding = len(huge) * 4                   # what encoding it first would cost

    tracemalloc.start()
    try:
        identity = ModuleIdentity.of(huge, "path")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert identity.truncated is True
    assert len(identity.value.encode("utf-8")) <= MAX_STRING_BYTES
    assert peak < whole_encoding // 2


@pytest.mark.parametrize("value", [1.5, True, 0, -1, "4096", None])
def test_a_budget_that_is_not_a_positive_integer_is_refused(value):
    # A limit that is not an integer count of what it bounds can be
    # exceeded by a consumption that is: `limit 1.5` with `consumed 2`
    # attributes the halt to a boundary nothing crossed.
    with pytest.raises(ValueError, match="max_read_operations"):
        collect(build_image(), max_read_operations=value)
    with pytest.raises(ValueError, match="requested_bytes"):
        collect(build_image(), requested_bytes=value)


@pytest.mark.parametrize("limit,consumed", [(1.5, 2), (True, 1), ("8", 8), (-1, 0)])
def test_a_bounded_stop_refuses_a_limit_that_is_not_a_count(limit, consumed):
    with pytest.raises(ValueError, match="BoundedStop"):
        BoundedStop("pe_header_read_operations", limit, consumed)


def test_every_bounded_stop_a_collection_produces_carries_integer_counts():
    for profile in (collect(wide_table_image()),
                    collect(build_image(e_lfanew=MAX_E_LFANEW + 0x10),
                            requested_bytes=1 << 16),
                    collect_pe_image_profile(
                        lambda addr, size: build_image()[addr - BASE:addr - BASE + 1],
                        BASE, source_kind=SourceKind.PEB_IMAGE_BASE,
                        source_identity="peb", max_read_operations=8)):
        stop = profile.bounded_stop
        assert stop is not None
        assert type(stop.budget_limit) is int and type(stop.budget_consumed) is int
        assert stop.budget_limit > 0 and stop.budget_consumed >= 0


def test_an_over_budget_e_lfanew_records_how_far_past_the_budget_it_asked():
    # `budget_consumed` is where the acquisition stood when the budget
    # fired, not a value clamped to the limit: for this stop it is the
    # offset the image declared, and clamping it would discard the one
    # number saying how far past the budget the image asked to go.
    declared = MAX_E_LFANEW + 0x10
    profile = collect(build_image(e_lfanew=declared), requested_bytes=1 << 16)
    assert profile.bounded_stop == BoundedStop("e_lfanew", MAX_E_LFANEW, declared)


@pytest.mark.parametrize("scope", ["pe_header_bytes", "pe_header_read_operations"])
def test_a_byte_or_operation_budget_stops_exactly_on_its_own_limit(scope):
    if scope == "pe_header_bytes":
        profile = collect(wide_table_image())
    else:
        profile = collect_pe_image_profile(
            lambda addr, size: build_image()[addr - BASE:addr - BASE + 1], BASE,
            source_kind=SourceKind.PEB_IMAGE_BASE, source_identity="peb",
            max_read_operations=8)
    stop = profile.bounded_stop
    assert stop.scope == scope
    assert stop.budget_consumed == stop.budget_limit


# ── The stage is a selector, not an incidental argument ────────────────


@pytest.mark.parametrize("stage", [True, False, 1.0, 0.0, "1", None, 4, -1, 3.5])
def test_a_stage_that_is_not_a_stage_is_refused_rather_than_coerced(stage):
    # `PeStage(value)` alone accepts `True` and `1.0` and returns COFF for
    # both, which would silently change how far acquisition goes and which
    # components the profile's state is folded over.
    with pytest.raises(ValueError, match="requested_stage"):
        collect(build_image(), requested_stage=stage)
    with pytest.raises(ValueError, match="stage"):
        in_scope_components(stage)


@pytest.mark.parametrize("stage", list(PeStage) + [0, 1, 2, 3])
def test_a_stage_or_a_plain_integer_naming_one_is_accepted(stage):
    profile = collect(build_image(), requested_stage=stage)
    assert profile.requested_stage is PeStage(stage)
    assert in_scope_components(stage) == in_scope_components(PeStage(stage))


def test_the_integer_a_bool_equals_names_a_stage_with_a_narrower_scope():
    # `PeStage(1)` denotes COFF, and a COFF request folds a strictly
    # smaller component set than a SECTIONS one. That is what makes
    # refusing a bool a matter of the answer's meaning rather than of
    # tolerating a sloppy argument.
    assert PeStage(1) is PeStage.COFF
    scoped = collect(build_image(), requested_stage=PeStage.COFF)
    assert scoped.components.section_table is None
    assert len(in_scope_components(PeStage.COFF)) < len(in_scope_components(PeStage.SECTIONS))


# ── A bounded stop cannot record a budget that could not have stopped ──


@pytest.mark.parametrize("stop", [
    ("pe_header_bytes", 0, 0),                  # a zero budget declines everything
    ("pe_header_read_operations", 0, 0),
    ("e_lfanew", 0, 1),
    ("pe_header_bytes", 4096, 0),               # stopped before the budget was reached
    ("pe_header_bytes", 4096, 4095),
    ("pe_header_bytes", 4096, 4097),            # work done past a budget meant to stop it
    ("pe_header_bytes", 4096, 5000),
    ("pe_header_read_operations", 8, 0),
    ("pe_header_read_operations", 8, 7),
    ("pe_header_read_operations", 8, 9),
    ("pe_header_read_operations", 8, 100),
    ("e_lfanew", 4096, 4096),                   # an offset inside the budget needs no stop
    ("e_lfanew", 4096, 0),
])
def test_a_bounded_stop_that_could_not_have_happened_is_refused(stop):
    with pytest.raises(ValueError, match="BoundedStop"):
        BoundedStop(*stop)


@pytest.mark.parametrize("stop", [
    ("pe_header_bytes", 4096, 4096),
    ("pe_header_read_operations", 8, 8),
    ("e_lfanew", 4096, 4112),
    ("some_future_budget", 10, 3),   # an unlisted scope states its own relation
])
def test_a_bounded_stop_a_budget_could_have_produced_is_accepted(stop):
    assert BoundedStop(*stop).scope == stop[0]


def test_the_collector_refuses_the_zero_budget_a_stop_could_never_describe():
    with pytest.raises(ValueError, match="requested_bytes"):
        collect(build_image(), requested_bytes=0)
    with pytest.raises(ValueError, match="max_read_operations"):
        collect(build_image(), max_read_operations=0)
