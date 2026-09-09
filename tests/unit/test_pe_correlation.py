"""Behaviour of the pure main-image PE correlation layer.

Every case here is one rule of §8.3 or §8.8 of
`docs/developer/pe_image_profile_contract.md` evaluated against
`dumpex.core.pe_correlation` over a synthetic
`dumpex.core.pe_profile.PeImageProfile` and synthetic
`dumpex.core.va_range` evidence views: the three-valued rule, the frozen
five observations, the size cross-checks, the per-section and
per-descriptor observations, the entry-point memory context, and the
interpretation rules that keep a benign image -- ASLR, packed, WOW64, a
partial dump -- out of `conflict`.
"""
import struct

import pytest

from dumpex.core.pe_profile import (
    PeStage, SourceKind, collect_pe_image_profile,
)
from dumpex.core.va_range import (
    CapturedEnumeration, CapturedRegion, CapturedSegment, VirtualRange,
)
from dumpex.core.pe_correlation import (
    MAX_DISTINCT_PROTECTIONS, ModuleListImage, ObservationState,
    correlate_main_image,
)

PREFERRED = 0x140000000

MAGIC_PE32 = 0x10b
MAGIC_PE32_PLUS = 0x20b
_FIXED = {MAGIC_PE32: 96, MAGIC_PE32_PLUS: 112}

SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000

RELOCS_STRIPPED = 0x0001
DYNAMIC_BASE = 0x0040

TEXT = {"name": b".text", "vaddr": 0x1000, "vsize": 0x2000,
        "rawptr": 0x400, "rawsize": 0x2000, "chars": SCN_EXECUTE | SCN_READ}
DATA = {"name": b".data", "vaddr": 0x3000, "vsize": 0x1000,
        "rawptr": 0x2400, "rawsize": 0x1000, "chars": SCN_READ | SCN_WRITE}

# A standard benign directory layout: IMPORT inside .text, BASERELOC
# inside .data, everything else declared absent. An image with this and
# `coff_characteristics` unstripped is legitimately relocatable, so a
# non-zero delta stays `consistent`.
BENIGN_DIRECTORIES = (
    ((0, 0), (0x1400, 0x50)) + ((0, 0),) * 3 + ((0x3800, 0x80),) + ((0, 0),) * 10)


def build_image(*, e_lfanew=0x80, machine=0x8664, magic=MAGIC_PE32_PLUS,
                sections=(TEXT, DATA), time_date_stamp=0x5A6B7C8D,
                coff_characteristics=0x0022, dll_characteristics=DYNAMIC_BASE,
                image_base=PREFERRED, entry_point=0x1000, section_alignment=0x1000,
                file_alignment=0x200, size_of_image=0x5000, size_of_headers=0x400,
                checksum=0, subsystem=3, number_of_rva_and_sizes=16,
                directories=None, number_of_sections=None, size_of_optional_header=None,
                trailing=0x400):
    """One PE image's header bytes with every structurally interesting
    field a keyword, so a case makes exactly one of them hostile.
    ``directories`` is a list of ``(value, size)`` pairs from index 0;
    ``None`` uses :data:`BENIGN_DIRECTORIES`."""
    if directories is None:
        directories = BENIGN_DIRECTORIES
    fixed = _FIXED[magic]
    if size_of_optional_header is None:
        size_of_optional_header = fixed + 16 * 8
    if number_of_sections is None:
        number_of_sections = len(sections)

    dos = bytearray(max(e_lfanew, 0x40))
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    buf = bytearray(dos[:e_lfanew] if e_lfanew >= 0x40 else dos)
    buf += b"PE\x00\x00"
    buf += struct.pack("<HHIIIHH", machine, number_of_sections, time_date_stamp,
                       0, 0, size_of_optional_header, coff_characteristics)

    opt = bytearray(size_of_optional_header)

    def put(offset, fmt, value):
        if offset + struct.calcsize(fmt) <= len(opt):
            struct.pack_into(fmt, opt, offset, value)

    put(0, "<H", magic)
    put(16, "<I", entry_point)
    put(20, "<I", 0x1000)
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
    put(fixed - 4, "<I", number_of_rva_and_sizes)
    for index, (value, size) in enumerate(directories):
        put(fixed + index * 8, "<I", value)
        put(fixed + index * 8 + 4, "<I", size)
    buf += opt

    for section in sections:
        record = bytearray(40)
        record[0:8] = section["name"][:8].ljust(8, b"\x00")
        struct.pack_into("<IIII", record, 8, section["vsize"], section["vaddr"],
                         section["rawsize"], section["rawptr"])
        struct.pack_into("<I", record, 36, section["chars"])
        buf += record

    return bytes(buf) + b"\x00" * trailing


def profile_at(base, *, capture_bytes=None, stage=PeStage.SECTIONS, **kwargs):
    data = build_image(**kwargs)

    def read(addr, size):
        offset = addr - base
        if offset < 0:
            return b""
        limit = len(data) if capture_bytes is None else min(len(data), capture_bytes)
        return data[offset:min(offset + size, limit)]

    return collect_pe_image_profile(
        read, base, source_kind=SourceKind.MODULE_LIST_ENTRY, source_identity=0,
        requested_stage=stage)


def regions(*specs):
    """A region enumeration from ``(base, size, alloc, prot)`` tuples;
    ``state``/``type`` default to a committed image mapping."""
    views = tuple(
        CapturedRegion(range=VirtualRange(b, s), allocation_base=a,
                       state="MEM_COMMIT", type="MEM_IMAGE", protection=p)
        for b, s, a, p in specs)
    return CapturedEnumeration(views, 0)


def segments(*specs):
    """A segment enumeration from ``(base, size)`` tuples, file offsets
    assigned in order."""
    views = []
    offset = 0
    for b, s in specs:
        views.append(CapturedSegment(range=VirtualRange(b, s), file_offset=offset))
        offset += s
    return CapturedEnumeration(tuple(views), 0)


def whole_image_evidence(base, image_size=0x5000):
    return dict(
        regions=regions((base, image_size, base, "PAGE_EXECUTE_READ")),
        segments=segments((base, image_size)),
        module_list_image=ModuleListImage(base_address=base, size=image_size,
                                          time_date_stamp=0x5A6B7C8D, check_sum=0),
    )


BASE = 0x7FF600000000


# ── a whole benign image ───────────────────────────────────────────────


def test_a_benign_image_produces_no_conflict():
    profile = profile_at(BASE)
    result = correlate_main_image(profile, **whole_image_evidence(BASE))

    assert result.conflicts() == ()
    assert result.coverage.conflict == 0
    assert result.coverage.total == len(result.all_observations())


def test_the_frozen_five_are_all_present_and_named():
    result = correlate_main_image(profile_at(BASE), **whole_image_evidence(BASE))
    assert [o.name for o in result.all_observations()[:5]] == [
        "base_vs_preferred", "relocation_expected", "machine_vs_format",
        "entry_point_in_section", "size_vs_image_extent"]


def test_two_runs_over_the_same_inputs_are_identical():
    profile = profile_at(BASE)
    evidence = whole_image_evidence(BASE)
    first = correlate_main_image(profile, **evidence)
    second = correlate_main_image(profile, **evidence)
    assert first == second


# ── base_vs_preferred (§8.3) ───────────────────────────────────────────


def test_base_vs_preferred_records_the_delta_and_never_conflicts():
    result = correlate_main_image(profile_at(BASE), **whole_image_evidence(BASE))
    observation = result.base_vs_preferred
    assert observation.state is ObservationState.CONSISTENT
    assert observation.operands["relocation_delta"] == BASE - PREFERRED


def test_base_vs_preferred_is_unavailable_without_a_preferred_base():
    # A one-byte optional header leaves ImageBase unreadable.
    profile = profile_at(BASE, size_of_optional_header=1)
    observation = correlate_main_image(profile).base_vs_preferred
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "preferred_image_base_null"


# ── relocation_expected (§8.3.1, §2.2) ─────────────────────────────────


def test_benign_aslr_is_consistent_when_relocation_evidence_supports_it():
    profile = profile_at(BASE, directories=((0, 0),) * 5 + ((0x4000, 0x80),),
                         coff_characteristics=0x0022)
    observation = correlate_main_image(profile, **whole_image_evidence(BASE)).relocation_expected
    assert observation.state is ObservationState.CONSISTENT


@pytest.mark.parametrize("coff, dirs, expected", [
    (0x0022 | RELOCS_STRIPPED, ((0x4000, 0x80),), ObservationState.CONFLICT),
    (0x0022, (), ObservationState.CONFLICT),                       # BASERELOC absent
    (0x0022, ((0x4000, 0x80),), ObservationState.CONSISTENT),
])
def test_relocation_expected_over_a_non_zero_delta(coff, dirs, expected):
    directories = ((0, 0),) * 5 + dirs if dirs else ((0, 0),) * 16
    profile = profile_at(BASE, coff_characteristics=coff, directories=directories)
    observation = correlate_main_image(profile).relocation_expected
    assert observation.state is expected


def test_a_zero_delta_is_consistent_on_the_delta_alone():
    profile = profile_at(PREFERRED, coff_characteristics=0x0022 | RELOCS_STRIPPED)
    observation = correlate_main_image(profile).relocation_expected
    assert observation.state is ObservationState.CONSISTENT
    assert observation.reason == "zero_delta"


# ── machine_vs_format (§8.4) ───────────────────────────────────────────


@pytest.mark.parametrize("machine, magic, expected", [
    (0x8664, MAGIC_PE32_PLUS, ObservationState.CONSISTENT),
    (0x8664, MAGIC_PE32, ObservationState.CONFLICT),
    (0x014c, MAGIC_PE32, ObservationState.CONSISTENT),
    (0x014c, MAGIC_PE32_PLUS, ObservationState.CONFLICT),
    (0x0ebc, MAGIC_PE32, ObservationState.CONSISTENT),      # unconstrained, width known
    (0x5045, MAGIC_PE32_PLUS, ObservationState.UNAVAILABLE),  # a value with no name
])
def test_machine_vs_format(machine, magic, expected):
    kwargs = dict(machine=machine, magic=magic)
    if magic == MAGIC_PE32:
        kwargs["size_of_optional_header"] = _FIXED[MAGIC_PE32] + 16 * 8
    profile = profile_at(BASE, **kwargs)
    observation = correlate_main_image(profile).machine_vs_format
    assert observation.state is expected


def test_an_unnamed_machine_is_unavailable_not_a_conflict():
    observation = correlate_main_image(
        profile_at(BASE, machine=0x5045)).machine_vs_format
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "machine_has_no_width"


# ── entry_point_in_section (§8.5) ──────────────────────────────────────


def test_a_zero_entry_point_is_consistent_without_the_section_table():
    profile = profile_at(BASE, entry_point=0, stage=PeStage.OPTIONAL)
    observation = correlate_main_image(profile).entry_point_in_section
    assert observation.state is ObservationState.CONSISTENT
    assert observation.reason == "zero_entry_point"


def test_an_entry_point_inside_a_decoded_section_is_consistent():
    observation = correlate_main_image(profile_at(BASE)).entry_point_in_section
    assert observation.state is ObservationState.CONSISTENT
    assert observation.operands["containing_section_index"] == 0


def test_an_entry_point_outside_every_section_of_a_complete_table_is_a_conflict():
    profile = profile_at(BASE, entry_point=0x40000)
    observation = correlate_main_image(profile).entry_point_in_section
    assert observation.state is ObservationState.CONFLICT


def test_an_entry_point_outside_an_incomplete_table_is_unavailable():
    profile = profile_at(BASE, entry_point=0x40000, capture_bytes=0x1A0,
                         stage=PeStage.SECTIONS)
    observation = correlate_main_image(profile).entry_point_in_section
    assert observation.state is ObservationState.UNAVAILABLE


def test_an_entry_point_in_a_nonstandard_named_section_is_not_a_conflict():
    packed = {"name": b"UPX1", "vaddr": 0x1000, "vsize": 0x3000,
              "rawptr": 0x400, "rawsize": 0x3000,
              "chars": SCN_EXECUTE | SCN_READ | SCN_WRITE}
    profile = profile_at(BASE, sections=(packed,))
    result = correlate_main_image(profile, **whole_image_evidence(BASE))
    assert result.entry_point_in_section.state is ObservationState.CONSISTENT
    assert result.conflicts() == ()


# ── entry-point memory context (§8.8) ─────────────────────────────────


def test_the_entry_point_context_resolves_the_checked_va_and_region():
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(profile, **whole_image_evidence(base))
    ctx = result.entry_point
    assert ctx.entry_point_va == base + 0x1000
    assert ctx.va_overflow is False
    assert ctx.containing_section_index == 0
    assert ctx.capture_state == "complete"
    assert ctx.region_protection == "PAGE_EXECUTE_READ"


def test_the_entry_point_context_is_context_only_and_adds_no_conflict():
    # A non-executable entry page is carried, not flagged.
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x5000, base, "PAGE_READONLY")),
        segments=segments((base, 0x5000)))
    assert result.entry_point.region_protection == "PAGE_READONLY"
    assert result.entry_point_in_section.state is ObservationState.CONSISTENT
    assert result.conflicts() == ()


# ── size_vs_image_extent (§8.6) ──────────────────────────────────────


def test_size_matches_a_single_region_reservation():
    base = BASE
    result = correlate_main_image(profile_at(base), **whole_image_evidence(base))
    observation = result.size_vs_image_extent
    assert observation.state is ObservationState.CONSISTENT
    assert observation.reason == "size_within_base_region"


def test_size_fits_a_multi_region_reservation():
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x1000, base, "PAGE_READONLY"),
                        (base + 0x1000, 0x4000, base, "PAGE_EXECUTE_READ")),
        segments=segments((base, 0x5000)))
    observation = result.size_vs_image_extent
    assert observation.state is ObservationState.CONSISTENT
    assert observation.reason == "size_within_reservation"


def test_a_size_past_the_whole_reservation_is_a_conflict():
    base = BASE
    profile = profile_at(base, size_of_image=0x9000)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x5000, base, "PAGE_EXECUTE_READ")),
        segments=segments((base, 0x5000)))
    assert result.size_vs_image_extent.state is ObservationState.CONFLICT


def test_a_missing_region_table_is_unavailable_not_a_defect():
    result = correlate_main_image(profile_at(BASE), regions=None,
                                  segments=segments((BASE, 0x5000)))
    observation = result.size_vs_image_extent
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "regions_unavailable"


def test_a_lossy_region_table_is_unavailable():
    base = BASE
    lossy = CapturedEnumeration(regions((base, 0x5000, base, "PAGE_EXECUTE_READ")).views, 1)
    result = correlate_main_image(profile_at(base), regions=lossy,
                                  segments=segments((base, 0x5000)))
    assert result.size_vs_image_extent.reason == "regions_lossy"


def test_a_base_that_is_not_a_reservation_start_is_unavailable():
    # Hollowed-like: the profile base sits inside a reservation that began
    # elsewhere.
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x5000, base - 0x10000, "PAGE_EXECUTE_READ")),
        segments=segments((base, 0x5000)))
    observation = result.size_vs_image_extent
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "base_not_reservation_start"


def test_a_partial_dump_is_a_short_capture_not_a_conflict():
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x5000, base, "PAGE_EXECUTE_READ")),
        segments=segments((base, 0x2000)))       # only part of the image written
    observation = result.size_vs_image_extent
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "short_capture"


def test_a_missing_segment_table_is_unavailable():
    base = BASE
    result = correlate_main_image(
        profile_at(base),
        regions=regions((base, 0x5000, base, "PAGE_EXECUTE_READ")), segments=None)
    assert result.size_vs_image_extent.reason == "segments_unavailable"


# ── size_vs_modulelist (§8.8) ────────────────────────────────────────


def test_size_matches_the_loader_record():
    base = BASE
    result = correlate_main_image(profile_at(base), **whole_image_evidence(base))
    assert result.size_vs_modulelist.state is ObservationState.CONSISTENT


def test_size_matches_the_loader_record_after_alignment():
    base = BASE
    profile = profile_at(base, size_of_image=0x5000, section_alignment=0x1000)
    module = ModuleListImage(base_address=base, size=0x4001)
    observation = correlate_main_image(profile, module_list_image=module).size_vs_modulelist
    assert observation.state is ObservationState.CONSISTENT
    assert observation.reason == "size_matches_modulelist_aligned"


def test_a_size_the_loader_disagrees_with_is_a_conflict():
    base = BASE
    profile = profile_at(base, size_of_image=0x5000)
    module = ModuleListImage(base_address=base, size=0x9000)
    assert correlate_main_image(profile, module_list_image=module) \
        .size_vs_modulelist.state is ObservationState.CONFLICT


def test_no_loader_record_is_unavailable():
    observation = correlate_main_image(profile_at(BASE)).size_vs_modulelist
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "no_modulelist_entry"


def test_an_unknown_section_alignment_withholds_a_raw_mismatch():
    base = BASE
    profile = profile_at(base, size_of_image=0x5000, section_alignment=0)
    module = ModuleListImage(base_address=base, size=0x5001)
    observation = correlate_main_image(profile, module_list_image=module).size_vs_modulelist
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "section_alignment_null"


# ── size_vs_section_extent (§8.8) ────────────────────────────────────


def test_a_size_that_covers_every_section_is_consistent():
    observation = correlate_main_image(profile_at(BASE)).size_vs_section_extent
    assert observation.state is ObservationState.CONSISTENT


def test_a_section_reaching_past_the_size_is_a_conflict():
    profile = profile_at(BASE, size_of_image=0x2000)   # .data at 0x3000 escapes
    assert correlate_main_image(profile).size_vs_section_extent.state \
        is ObservationState.CONFLICT


def test_an_incomplete_section_table_that_still_fits_is_unavailable():
    profile = profile_at(BASE, capture_bytes=0x1A0)
    observation = correlate_main_image(profile).size_vs_section_extent
    assert observation.state is ObservationState.UNAVAILABLE


# ── per-section observations (§8.8) ──────────────────────────────────


def test_overlapping_sections_conflict_and_a_lone_section_does_not():
    overlap = [
        {"name": b".text", "vaddr": 0x1000, "vsize": 0x2000, "rawptr": 0x400,
         "rawsize": 0x2000, "chars": SCN_EXECUTE | SCN_READ},
        {"name": b".data", "vaddr": 0x2000, "vsize": 0x2000, "rawptr": 0x2400,
         "rawsize": 0x2000, "chars": SCN_READ | SCN_WRITE},
    ]
    result = correlate_main_image(profile_at(BASE, sections=overlap, size_of_image=0x6000))
    assert [s.overlap.state for s in result.sections] == \
        [ObservationState.CONFLICT, ObservationState.CONFLICT]

    lone = correlate_main_image(profile_at(BASE, sections=(TEXT,)))
    assert lone.sections[0].overlap.state is ObservationState.CONSISTENT


def test_a_section_past_the_image_bound_conflicts():
    profile = profile_at(BASE, size_of_image=0x3800)   # .data ends at 0x4000
    result = correlate_main_image(profile)
    assert result.sections[1].image_bound.state is ObservationState.CONFLICT
    assert result.sections[0].image_bound.state is ObservationState.CONSISTENT


def test_a_section_whose_rva_math_overflows_the_address_space_conflicts():
    huge = {"name": b".big", "vaddr": 0xFFFFF000, "vsize": 0xFFFFFFFF,
            "rawptr": 0x400, "rawsize": 0x200, "chars": SCN_READ}
    profile = profile_at((1 << 64) - 0x10000, sections=(huge,),
                         image_base=(1 << 64) - 0x10000)
    result = correlate_main_image(profile)
    assert result.sections[0].range_overflow.state is ObservationState.CONFLICT


def test_section_live_protection_is_context_and_writecopy_is_normal():
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x3000, base, "PAGE_EXECUTE_WRITECOPY"),
                        (base + 0x3000, 0x2000, base, "PAGE_READWRITE")),
        segments=segments((base, 0x5000)))
    text = result.sections[0]
    assert text.live_protections == ("PAGE_EXECUTE_WRITECOPY",)
    assert result.conflicts() == ()


def test_section_correlation_follows_the_declared_rwx_bits():
    result = correlate_main_image(profile_at(BASE))
    text, data = result.sections
    assert (text.declared_executable, text.declared_writable) == (True, False)
    assert (data.declared_executable, data.declared_writable) == (False, True)


def test_distinct_protections_are_capped():
    base = BASE
    profile = profile_at(base, sections=({**TEXT, "vsize": 0x4000},), size_of_image=0x5000)
    many = [(base + i * 0x100, 0x100, base, f"PROT_{i:02d}")
            for i in range(MAX_DISTINCT_PROTECTIONS + 8)]
    result = correlate_main_image(profile, regions=regions(*many),
                                  segments=segments((base, 0x5000)))
    assert len(result.sections[0].live_protections) <= MAX_DISTINCT_PROTECTIONS


# ── per-descriptor observations (§8.8, §2.5) ─────────────────────────


def test_a_directory_inside_the_image_is_consistent_with_its_section():
    # IMPORT (index 1) at an RVA inside .text.
    profile = profile_at(BASE, directories=((0, 0), (0x1400, 0x50)))
    result = correlate_main_image(profile)
    imports = result.directories[1]
    assert imports.image_bound.state is ObservationState.CONSISTENT
    assert imports.containing_section_index == 0


def test_a_directory_past_the_image_bound_conflicts():
    profile = profile_at(BASE, directories=((0x9000, 0x40),))
    export = correlate_main_image(profile).directories[0]
    assert export.image_bound.state is ObservationState.CONFLICT


def test_the_security_directory_gets_no_memory_bounds_or_capture_claim():
    profile = profile_at(BASE, directories=((0, 0),) * 4 + ((0x99999, 0x200),))
    security = correlate_main_image(profile, **whole_image_evidence(BASE)).directories[4]
    assert security.value_kind == "file_offset"
    assert security.image_bound.state is ObservationState.UNAVAILABLE
    assert security.image_bound.reason == "file_offset_semantics"
    assert security.containing_section_index is None
    assert security.capture_state is None


def test_a_declared_absent_directory_makes_no_bounds_claim():
    observation = correlate_main_image(profile_at(BASE)).directories[7].image_bound
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "directory_declared_absent"


# ── identity comparisons (§8.8) ─────────────────────────────────────


def test_a_matching_timestamp_is_consistent_and_a_mismatch_conflicts():
    base = BASE
    match = ModuleListImage(base_address=base, time_date_stamp=0x5A6B7C8D)
    assert correlate_main_image(profile_at(base), module_list_image=match) \
        .identity[0].state is ObservationState.CONSISTENT

    mismatch = ModuleListImage(base_address=base, time_date_stamp=0x11111111)
    assert correlate_main_image(profile_at(base), module_list_image=mismatch) \
        .identity[0].state is ObservationState.CONFLICT


def test_a_timestamp_with_no_second_source_is_unavailable():
    observation = correlate_main_image(profile_at(BASE)).identity[0]
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "no_second_source"


def test_a_zero_header_checksum_is_not_compared():
    base = BASE
    module = ModuleListImage(base_address=base, check_sum=0x1234)
    observation = correlate_main_image(profile_at(base, checksum=0),
                                       module_list_image=module).identity[1]
    assert observation.state is ObservationState.UNAVAILABLE
    assert observation.reason == "header_checksum_absent"


def test_machine_identity_is_represented_but_always_unavailable():
    observation = correlate_main_image(profile_at(BASE)).identity[2]
    assert observation.name == "identity_machine"
    assert observation.state is ObservationState.UNAVAILABLE


def test_a_wow64_image_correlates_without_a_machine_conflict():
    base = 0x400000
    profile = profile_at(base, machine=0x014c, magic=MAGIC_PE32,
                         image_base=base, size_of_optional_header=_FIXED[MAGIC_PE32] + 16 * 8)
    result = correlate_main_image(profile, **whole_image_evidence(base))
    assert result.machine_vs_format.state is ObservationState.CONSISTENT
    assert result.identity[2].state is ObservationState.UNAVAILABLE
    assert result.conflicts() == ()


# ── coverage, boundaries, robustness ────────────────────────────────


def test_coverage_is_a_plain_tally_not_a_status():
    result = correlate_main_image(profile_at(BASE), **whole_image_evidence(BASE))
    coverage = result.coverage
    assert coverage.total == coverage.consistent + coverage.conflict + coverage.unavailable
    assert coverage.evaluated == coverage.consistent + coverage.conflict
    assert not hasattr(coverage, "status")


def test_a_disk_reference_profile_cannot_be_correlated():
    profile = profile_at(BASE)
    object.__setattr__(profile, "source_kind", SourceKind.DISK_REFERENCE)
    with pytest.raises(ValueError, match="no actual_base"):
        correlate_main_image(profile)


def test_a_module_record_for_a_different_base_is_refused():
    profile = profile_at(BASE)
    with pytest.raises(ValueError, match="actual_base"):
        correlate_main_image(profile, module_list_image=ModuleListImage(base_address=BASE + 1))


def test_a_malformed_profile_never_raises_the_layer():
    # A wrong PE signature -> malformed coff_header, most facts null.
    data = build_image()
    data = data[:0x80] + b"XX\x00\x00" + data[0x84:]
    profile = collect_pe_image_profile(
        lambda a, s: data[a - BASE:a - BASE + s] if a >= BASE else b"",
        BASE, source_kind=SourceKind.MODULE_LIST_ENTRY, source_identity=0)
    result = correlate_main_image(profile, **whole_image_evidence(BASE))
    assert result.machine_vs_format.state is ObservationState.UNAVAILABLE
    assert isinstance(result.coverage.total, int)


def test_module_list_image_at_base_reduces_a_raw_module():
    class RawModule:
        baseaddress = BASE
        size = 0x5000
        timestamp = 0x5A6B7C8D
        checksum = 0x99

    reduced = ModuleListImage.at_base([RawModule()], BASE)
    assert (reduced.size, reduced.time_date_stamp, reduced.check_sum) == (0x5000, 0x5A6B7C8D, 0x99)
    assert ModuleListImage.at_base([RawModule()], BASE + 1) is None


def test_module_list_image_at_base_drops_a_malformed_field():
    class RawModule:
        baseaddress = BASE
        size = "not an int"
        timestamp = -1
        checksum = None

    reduced = ModuleListImage.at_base([RawModule()], BASE)
    assert (reduced.size, reduced.time_date_stamp, reduced.check_sum) == (None, None, None)


def test_an_entry_point_va_that_overflows_the_address_space_is_marked():
    top = (1 << 64) - 0x2000
    profile = profile_at(top, image_base=top, entry_point=0x8000,
                         sections=({"name": b".t", "vaddr": 0x200, "vsize": 0x100,
                                    "rawptr": 0x200, "rawsize": 0x100,
                                    "chars": SCN_EXECUTE | SCN_READ},),
                         size_of_image=0x9000)
    result = correlate_main_image(profile)
    assert result.entry_point.va_overflow is True
    assert result.entry_point.entry_point_va is None


def test_all_observations_is_deterministic_and_matches_the_tally():
    result = correlate_main_image(profile_at(BASE), **whole_image_evidence(BASE))
    flat = result.all_observations()
    assert flat == result.all_observations()          # stable
    assert len(flat) == 5 + 2 + 3 + 3 * len(result.sections) + 16
    assert result.coverage.total == len(flat)
    assert result.coverage.consistent == sum(
        1 for o in flat if o.state is ObservationState.CONSISTENT)


def test_a_directory_capture_state_reflects_a_partial_dump():
    base = BASE
    profile = profile_at(base, directories=((0, 0), (0x1400, 0x50)))
    result = correlate_main_image(
        profile, regions=regions((base, 0x5000, base, "PAGE_READONLY")),
        segments=segments((base, 0x1000)))       # only the first page written
    imports = result.directories[1]
    assert imports.capture_state == "none"        # 0x1400 is past the captured page


# ── a lossy table is not per-address context ───────────────────────────


def _lossy(enumeration):
    return CapturedEnumeration(enumeration.views, 1)


def test_a_lossy_region_table_withholds_every_per_address_context():
    base = BASE
    profile = profile_at(base)
    result = correlate_main_image(
        profile,
        regions=_lossy(regions((base, 0x5000, base, "PAGE_EXECUTE_READ"))),
        segments=segments((base, 0x5000)))
    assert result.size_vs_image_extent.reason == "regions_lossy"
    assert all(s.live_protections == () for s in result.sections)
    assert result.entry_point.region_protection is None
    assert result.entry_point.region_state is None


def test_a_lossy_segment_table_withholds_every_capture_state():
    base = BASE
    profile = profile_at(base, directories=((0, 0), (0x1400, 0x50)))
    result = correlate_main_image(
        profile,
        regions=regions((base, 0x5000, base, "PAGE_EXECUTE_READ")),
        segments=_lossy(segments((base, 0x5000))))
    assert result.size_vs_image_extent.reason == "segments_lossy"
    assert all(s.capture_state is None for s in result.sections)
    assert result.directories[1].capture_state is None
    assert result.entry_point.capture_state is None


# ── a zero entry point is not the image base ──────────────────────────


def test_a_zero_entry_point_has_no_va_and_no_memory_context():
    base = BASE
    profile = profile_at(base, entry_point=0)
    result = correlate_main_image(profile, **whole_image_evidence(base))
    ctx = result.entry_point
    assert ctx.entry_point_rva == 0
    assert ctx.entry_point_va is None
    assert ctx.va_overflow is False
    assert (ctx.capture_state, ctx.region_state, ctx.region_protection) == (None, None, None)


# ── size_vs_section_extent compares raw values, not alignment-rounded ──


def test_a_section_ending_below_size_but_above_its_alignment_is_not_a_conflict():
    section = {"name": b".text", "vaddr": 0x1000, "vsize": 0x801,
               "rawptr": 0x400, "rawsize": 0x1000, "chars": SCN_EXECUTE | SCN_READ}
    profile = profile_at(BASE, sections=(section,), size_of_image=0x1900,
                         section_alignment=0x1000)
    observation = correlate_main_image(profile).size_vs_section_extent
    assert observation.state is ObservationState.CONSISTENT
    assert observation.operands["section_extent"] == 0x1801


# ── an overlap conflict retains its counterpart ──────────────────────


def test_an_overlap_conflict_names_the_other_section_and_the_range():
    overlap = [
        {"name": b".a", "vaddr": 0x1000, "vsize": 0x3000, "rawptr": 0x400,
         "rawsize": 0x3000, "chars": SCN_EXECUTE | SCN_READ},
        {"name": b".b", "vaddr": 0x2000, "vsize": 0x2000, "rawptr": 0x3400,
         "rawsize": 0x2000, "chars": SCN_READ | SCN_WRITE},
    ]
    result = correlate_main_image(profile_at(BASE, sections=overlap, size_of_image=0x6000))
    first = result.sections[0].overlap
    assert first.state is ObservationState.CONFLICT
    assert first.operands["overlaps_section_index"] == 1
    assert first.operands["overlap_start"] == 0x2000
    assert first.operands["overlap_end"] == 0x4000


# ── sources name the evidence actually evaluated ─────────────────────


def test_an_observation_that_uses_the_actual_base_names_its_provenance():
    # ``profile_at`` builds a module-list-sourced profile.
    result = correlate_main_image(profile_at(BASE), **whole_image_evidence(BASE))
    assert "profile.source:module_list_entry" in result.base_vs_preferred.sources
    assert "profile.source:module_list_entry" in result.size_vs_image_extent.sources
    assert "profile.source:module_list_entry" in result.sections[0].range_overflow.sources


def test_a_zero_delta_names_only_the_bases_it_compared():
    profile = profile_at(PREFERRED, coff_characteristics=0x0022 | RELOCS_STRIPPED)
    observation = correlate_main_image(profile).relocation_expected
    assert observation.reason == "zero_delta"
    assert observation.sources == ("profile.source:module_list_entry", "profile.optional_header")


def test_a_zero_entry_point_names_only_the_optional_header():
    result = correlate_main_image(profile_at(BASE, entry_point=0), **whole_image_evidence(BASE))
    assert result.entry_point_in_section.reason == "zero_entry_point"
    assert result.entry_point_in_section.sources == ("profile.optional_header",)


def test_a_null_size_of_image_names_no_memory_source():
    profile = profile_at(BASE, size_of_optional_header=56)   # SizeOfImage at +56 unreadable
    observation = correlate_main_image(profile, **whole_image_evidence(BASE)).size_vs_image_extent
    assert observation.reason == "size_of_image_null"
    assert observation.sources == ("profile.optional_header",)
