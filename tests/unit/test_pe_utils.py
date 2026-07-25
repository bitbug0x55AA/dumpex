"""
Direct, hunter-independent unit tests for dumpex.core.pe_utils's PE
relocation normalization — no minidump/hunt object graph involved, just
synthetic PE bytes and the parsing/relocation functions themselves.
"""
import struct

from tests.fixtures.fakes import build_pe_header, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ

from dumpex.core.pe_utils import (
    parse_pe_header, apply_base_relocations, _rva_to_file_offset,
    IMAGE_REL_BASED_HIGHLOW,
)


def _patch_basereloc_directory(header, reloc_vaddr, reloc_size):
    """
    Patch NumberOfRvaAndSizes + the BASERELOC data directory entry into a
    build_pe_header() PE32+ header (offset 112 + 5*8 in the optional
    header — e_lfanew is fixed at 0x80 by build_pe_header()).
    """
    header = bytearray(header)
    opt_off = header.index(b'PE\x00\x00') + 24
    struct.pack_into('<I', header, opt_off + 108, 16)
    struct.pack_into('<II', header, opt_off + 112 + 5 * 8, reloc_vaddr, reloc_size)
    return bytes(header)


# ── an unrecognized relocation type must force the whole normalization ────
# to "malformed", not silently leave that address un-normalized while
# reporting status="applied" (targeted test confirmed: entries with types
# other than ABSOLUTE/HIGHLOW/DIR64 were counted in unsupported_types but
# didn't change `status` — "UNSUPPORTED_TYPE applied 0 [7]" in the
# reproduction).

def test_unsupported_relocation_type_forces_malformed():
    preferred_base = 0x140000000
    text_vaddr, text_size = 0x1000, 0x2000
    reloc_vaddr = 0x4000
    UNSUPPORTED_TYPE = 5   # IMAGE_REL_BASED_MIPS_JMPADDR -- not emitted by
                            # x86/x64 linkers and not decoded here.

    text_bytes = bytearray((i * 3) % 251 for i in range(text_size))
    page_rva = text_vaddr & ~0xFFF
    offset_in_page = (text_vaddr + 0x40) - page_rva
    entry = (UNSUPPORTED_TYPE << 12) | offset_in_page
    reloc_data = struct.pack('<II', page_rva, 8 + 2) + struct.pack('<H', entry)

    sections = [
        {"name": b".text", "vaddr": text_vaddr, "vsize": text_size, "rawptr": 0x400,
         "rawsize": text_size, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
        {"name": b".reloc", "vaddr": reloc_vaddr, "vsize": len(reloc_data),
         "rawptr": 0x400 + text_size, "rawsize": len(reloc_data), "chars": IMAGE_SCN_MEM_READ},
    ]
    header = build_pe_header(sections, timestamp=0x55555555, size_of_image=0x6000,
                              image_base=preferred_base)
    header = _patch_basereloc_directory(header, reloc_vaddr, len(reloc_data))

    file_bytes = bytearray(header)
    file_bytes += b'\x00' * (sections[0]["rawptr"] - len(file_bytes))
    file_bytes += bytes(text_bytes)
    file_bytes += reloc_data
    file_bytes = bytes(file_bytes)

    pe = parse_pe_header(file_bytes)
    assert pe["valid"], pe["reason"]

    result = apply_base_relocations(file_bytes, pe, delta=0x50000)
    assert result.status == "malformed"
    assert UNSUPPORTED_TYPE in result.unsupported_types
    assert result.applied_count == 0


# ── a fixup target inside a section's virtual-only tail (past its on- ─────
# disk size_of_raw_data, within virtual_size) must not be translated to
# some other file offset and modified — that RVA has no real file bytes
# behind it at all ("VIRTUAL_TAIL_TRANSLATION 0x500 applied 1" in the
# reproduction).

def test_relocation_target_in_virtual_tail_not_translated():
    preferred_base = 0x140000000
    text_vaddr    = 0x1000
    text_rawsize  = 0x400   # only 0x400 bytes actually on disk
    text_vsize    = 0x900   # declared virtual_size extends well past that
    reloc_vaddr   = 0x4000

    text_bytes = bytearray((i * 3) % 251 for i in range(text_rawsize))

    # Target RVA at text_vaddr+0x500: inside virtual_size (0x900) but past
    # size_of_raw_data (0x400) -- the zero-padded virtual tail.
    target_rva = text_vaddr + 0x500
    page_rva = target_rva & ~0xFFF
    offset_in_page = target_rva - page_rva
    entry = (IMAGE_REL_BASED_HIGHLOW << 12) | offset_in_page
    reloc_data = struct.pack('<II', page_rva, 8 + 2) + struct.pack('<H', entry)

    sections = [
        {"name": b".text", "vaddr": text_vaddr, "vsize": text_vsize, "rawptr": 0x400,
         "rawsize": text_rawsize, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
        {"name": b".reloc", "vaddr": reloc_vaddr, "vsize": len(reloc_data),
         "rawptr": 0x400 + text_rawsize, "rawsize": len(reloc_data), "chars": IMAGE_SCN_MEM_READ},
    ]
    header = build_pe_header(sections, timestamp=0x66666666, size_of_image=0x6000,
                              image_base=preferred_base)
    header = _patch_basereloc_directory(header, reloc_vaddr, len(reloc_data))

    file_bytes = bytearray(header)
    file_bytes += b'\x00' * (sections[0]["rawptr"] - len(file_bytes))
    file_bytes += bytes(text_bytes)
    file_bytes += reloc_data
    file_bytes = bytes(file_bytes)

    pe = parse_pe_header(file_bytes)
    assert pe["valid"], pe["reason"]

    result = apply_base_relocations(file_bytes, pe, delta=0x50000)
    assert result.status == "malformed"
    assert result.applied_count == 0
    assert result.data == file_bytes, "no bytes should have been modified"


# ── relocation-only difference (ASLR-relocated, content unchanged) must ───
# NOT be detected once normalized ──────────────────────────────────────────

def test_relocation_only_diff_normalizes_to_identical_bytes():
    from dumpex.core.pe_utils import IMAGE_REL_BASED_DIR64

    preferred_base = 0x140000000
    actual_base    = 0x140050000   # loaded 0x50000 above preferred -> real ASLR-style delta
    text_vaddr, text_size = 0x1000, 0x2000
    reloc_vaddr = 0x4000

    text_bytes = bytearray((i * 3) % 251 for i in range(text_size))
    abs_ptr_off = 0x40
    struct.pack_into('<Q', text_bytes, abs_ptr_off, preferred_base + 0x2000)

    page_rva = text_vaddr & ~0xFFF
    offset_in_page = (text_vaddr + abs_ptr_off) - page_rva
    entry = (IMAGE_REL_BASED_DIR64 << 12) | offset_in_page
    reloc_data = struct.pack('<II', page_rva, 8 + 2) + struct.pack('<H', entry)

    sections = [
        {"name": b".text", "vaddr": text_vaddr, "vsize": text_size, "rawptr": 0x400,
         "rawsize": text_size, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ},
        {"name": b".reloc", "vaddr": reloc_vaddr, "vsize": len(reloc_data),
         "rawptr": 0x400 + text_size, "rawsize": len(reloc_data), "chars": IMAGE_SCN_MEM_READ},
    ]
    header = build_pe_header(sections, timestamp=0x33333333, size_of_image=0x6000,
                              image_base=preferred_base)
    header = _patch_basereloc_directory(header, reloc_vaddr, len(reloc_data))

    file_bytes = bytearray(header)
    file_bytes += b'\x00' * (sections[0]["rawptr"] - len(file_bytes))
    file_bytes += bytes(text_bytes)
    file_bytes += reloc_data
    file_bytes = bytes(file_bytes)

    pe = parse_pe_header(file_bytes)
    assert pe["valid"], pe["reason"]

    delta = actual_base - preferred_base
    result = apply_base_relocations(file_bytes, pe, delta=delta)
    assert result.status == "applied"
    assert result.applied_count == 1

    # Memory would contain the SAME content, except the one absolute
    # pointer relocated by `delta`, exactly as the real Windows loader
    # would do -- i.e. genuinely unmodified code.
    expected_mem_text = bytearray(text_bytes)
    struct.pack_into('<Q', expected_mem_text, abs_ptr_off, preferred_base + 0x2000 + delta)
    normalized_text = result.data[sections[0]["rawptr"]:sections[0]["rawptr"] + text_size]
    assert normalized_text == bytes(expected_mem_text)


# ── direct unit check on _rva_to_file_offset's raw-data-extent gating ─────

def test_rva_to_file_offset_rejects_virtual_tail():
    sections = [{"virtual_address": 0x1000, "size_of_raw_data": 0x400,
                 "virtual_size": 0x900, "pointer_to_raw_data": 0x400}]
    # Inside the raw-data extent -> translatable.
    assert _rva_to_file_offset(sections, 0x1000 + 0x10) == 0x400 + 0x10
    # Inside virtual_size but past size_of_raw_data (the zero-padded
    # tail) -> must be unmapped, not aliased to some other file offset.
    assert _rva_to_file_offset(sections, 0x1000 + 0x500) is None
    # width validation: a 4-byte read straddling the raw-data boundary
    # doesn't fit even though its start byte is in-bounds.
    assert _rva_to_file_offset(sections, 0x1000 + 0x400 - 2, width=4) is None
    assert _rva_to_file_offset(sections, 0x1000 + 0x400 - 4, width=4) == 0x400 + 0x400 - 4


def test_apply_base_relocations_not_needed_when_delta_zero():
    header = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                "rawptr": 0x400, "rawsize": 0x200,
                                "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                              size_of_image=0x2000)
    pe = parse_pe_header(header)
    result = apply_base_relocations(header, pe, delta=0)
    assert result.status == "not_needed"
    assert result.data == header


def test_apply_base_relocations_unavailable_on_unsupported_machine():
    ARM64_MACHINE = 0xaa64
    header = build_pe_header([{"name": b".text", "vaddr": 0x1000, "vsize": 0x200,
                                "rawptr": 0x400, "rawsize": 0x200,
                                "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
                              machine=ARM64_MACHINE, size_of_image=0x2000)
    pe = parse_pe_header(header)
    assert pe["valid"]
    result = apply_base_relocations(header, pe, delta=0x1000)
    assert result.status == "unavailable"
    assert result.data == header
