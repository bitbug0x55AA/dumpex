"""PE / FILETIME formatting utilities."""
import struct
import datetime
from dataclasses import dataclass, field
from dumpex.ui.colors import RED, YELLOW, DIM

# ── PE structural validation ─────────────────────────────────────────────
# Used by hunt/injection/ (structural "is this really a PE header" check,
# replacing a bare MZ-prefix scan) and hunt/stomping/ (section table for
# disk-declared-vs-live-memory comparison). Deliberately hand-rolled rather
# than depending on pefile: only the handful of fixed-offset fields these
# two hunts actually need, parsed defensively (never raises) since the
# input is untrusted process memory that may be truncated, corrupted, or
# adversarially crafted to look almost-but-not-quite like a PE.

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ    = 0x40000000
IMAGE_SCN_MEM_WRITE   = 0x80000000

# COFF Machine field values worth recognizing — an unrecognized value is
# itself evidence against "this is a genuine PE header" (a real linker
# never emits anything else here).
_KNOWN_MACHINES = {
    0x014c: "I386", 0x0200: "IA64", 0x01c0: "ARM", 0x01c4: "ARMNT",
    0x8664: "AMD64", 0xaa64: "ARM64", 0x0ebc: "EBC",
}

_MAX_SECTIONS = 96   # PE spec allows up to 96 sections; anything beyond
                      # that in a section-table walk is corrupt/adversarial


def parse_pe_header(data: bytes) -> dict:
    """
    Structurally validate a PE image starting at `data[0]` (presumed MZ).
    Never raises — malformed/truncated input just yields valid=False with
    whatever partial facts were recoverable plus a `reason` string.

    This is deliberately stricter than "starts with MZ": it walks the DOS
    header, the PE signature, the COFF file header (Machine /
    NumberOfSections sanity-checked against known values), the optional
    header (PE32 vs PE32+ Magic), and the full section table. A region
    that merely happens to contain the two bytes 'MZ' — coincidentally or
    as a decoy — fails here and is reported as such, rather than being
    counted as a confirmed hidden/injected PE module.

    Returns a dict:
      valid                    bool  — True only if header + FULL section
                                        table parsed successfully
      has_mz, has_pe_sig       bool
      e_lfanew                int | None
      machine                 int | None   (raw COFF Machine value)
      machine_name            str  | None  (None if unrecognized)
      is_pe32_plus             bool | None (PE32+ vs PE32 optional header)
      number_of_sections       int | None
      size_of_image            int | None
      address_of_entry_point   int | None  (RVA)
      image_base               int | None  (as declared in the header —
                                        NOT necessarily where it's actually
                                        mapped; compare against the actual
                                        region VA at the call site)
      sections                 list[dict]  — see below
      reason                   str   — why valid is False (empty if valid)
      insufficient_data        bool  — True iff `reason` is a genuine
                                        capture-length gap (some
                                        structurally-required offset ran
                                        past `len(data)`) rather than a
                                        deterministic structural rejection
                                        reached from bytes that WERE all
                                        present (bad signature/Machine/
                                        NumberOfSections/Magic). False
                                        whenever `valid` is True. A caller
                                        deciding "is more data worth
                                        fetching, or is this genuinely not
                                        a PE" reads this instead of
                                        pattern-matching `reason`'s
                                        free-text, which is not a closed
                                        vocabulary and (e.g. 'no MZ
                                        signature') does not reliably
                                        name a length-only cause.

    Each section dict: {name, virtual_address, virtual_size,
    pointer_to_raw_data, size_of_raw_data, characteristics,
    is_executable, is_writable, is_readable} — the last three decoded
    from `characteristics` (IMAGE_SCN_MEM_EXECUTE/WRITE/READ) since every
    caller needs them and re-decoding the bitmask at each call site would
    just be repeated, easy-to-typo bit-math.
    """
    result = {
        'valid': False, 'has_mz': False, 'has_pe_sig': False,
        'e_lfanew': None, 'machine': None, 'machine_name': None,
        'time_date_stamp': None,
        'is_pe32_plus': None, 'number_of_sections': None,
        'size_of_image': None, 'address_of_entry_point': None,
        'image_base': None, 'sections': [], 'data_directories': [], 'reason': '',
        'declared_directory_count': None, 'directories_complete': False,
        'insufficient_data': False,
    }
    # Signature checked FIRST, independent of length: two present bytes
    # that are simply not 'MZ' is a deterministic rejection regardless of
    # how much data followed them -- checking length first would let a
    # short, genuinely-non-PE capture masquerade as insufficient_data.
    if len(data) >= 2 and data[:2] != b'MZ':
        result['reason'] = 'no MZ signature'
        return result
    if len(data) < 0x40:
        # Either too short to even hold two signature bytes, or the
        # signature matched but the rest of the fixed DOS header (up to
        # and including e_lfanew at 0x3C) was not captured -- both are
        # genuine capture-length gaps.
        result['reason'] = 'truncated DOS header'
        result['insufficient_data'] = True
        return result
    result['has_mz'] = True

    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    except struct.error:
        result['reason'] = 'truncated DOS header (no e_lfanew)'
        result['insufficient_data'] = True
        return result
    result['e_lfanew'] = e_lfanew

    # e_lfanew is attacker/loader controlled in principle; bound it to a
    # plausible range before trusting it as an offset into `data`. The
    # implausible-value case (< 4 or > 0x1000) is a deterministic
    # rejection of the header's OWN declared offset, independent of how
    # much of `data` was captured; only the "declared offset is plausible
    # but its own 24-byte window runs past what was captured" case is a
    # genuine capture-length gap.
    if e_lfanew < 4 or e_lfanew > 0x1000:
        result['reason'] = f'e_lfanew out of plausible range (0x{e_lfanew:x})'
        return result
    if e_lfanew + 24 > len(data):
        result['reason'] = f'e_lfanew out of plausible range (0x{e_lfanew:x})'
        result['insufficient_data'] = True
        return result
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        result['reason'] = 'no PE\\0\\0 signature at e_lfanew'
        return result
    result['has_pe_sig'] = True

    coff_off = e_lfanew + 4
    try:
        machine, num_sections, time_date_stamp, _symtab, _numsym, opt_hdr_size, _chars = \
            struct.unpack_from('<HHIIIHH', data, coff_off)
    except struct.error:
        result['reason'] = 'truncated COFF file header'
        result['insufficient_data'] = True
        return result
    result['machine'] = machine
    result['machine_name'] = _KNOWN_MACHINES.get(machine)
    result['time_date_stamp'] = time_date_stamp
    result['number_of_sections'] = num_sections

    if machine not in _KNOWN_MACHINES:
        result['reason'] = f'unrecognized Machine field (0x{machine:04x})'
        return result
    if num_sections == 0 or num_sections > _MAX_SECTIONS:
        result['reason'] = f'implausible NumberOfSections ({num_sections})'
        return result

    opt_off = coff_off + 20
    if opt_off + 2 > len(data):
        result['reason'] = 'truncated optional header'
        result['insufficient_data'] = True
        return result
    magic = struct.unpack_from('<H', data, opt_off)[0]

    if magic == 0x10b:      # PE32
        result['is_pe32_plus'] = False
        ep_off, base_off, base_size, size_off = opt_off + 16, opt_off + 28, 4, opt_off + 56
    elif magic == 0x20b:    # PE32+
        result['is_pe32_plus'] = True
        ep_off, base_off, base_size, size_off = opt_off + 16, opt_off + 24, 8, opt_off + 56
    else:
        result['reason'] = f'invalid optional header Magic (0x{magic:04x})'
        return result

    if ep_off + 4 > len(data) or base_off + base_size > len(data) or size_off + 4 > len(data):
        result['reason'] = 'truncated optional header (fixed fields)'
        result['insufficient_data'] = True
        return result

    result['address_of_entry_point'] = struct.unpack_from('<I', data, ep_off)[0]
    result['image_base'] = (struct.unpack_from('<I', data, base_off)[0] if base_size == 4
                             else struct.unpack_from('<Q', data, base_off)[0])
    result['size_of_image'] = struct.unpack_from('<I', data, size_off)[0]

    # Data Directories (RVA, Size) pairs — NumberOfRvaAndSizes precedes the
    # array itself; offsets differ between PE32 and PE32+ because the
    # Windows-specific fields ahead of it (Stack/Heap Reserve/Commit) are
    # 4 bytes wide in PE32 and 8 bytes wide in PE32+. Only used so far for
    # IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5), by dumpex/hunt/stomping/'s
    # relocation-normalized disk diff — parsed here, not per-caller, since
    # every caller needs the same offsets and the same PE32/PE32+ branch.
    num_rva_sizes_off, dir_off = ((92, 96) if base_size == 4 else (108, 112))
    num_rva_sizes_off += opt_off
    dir_off += opt_off
    data_directories = []
    declared_directory_count = None
    if num_rva_sizes_off + 4 <= len(data):
        # `min(..., 16)` is the actual count parse_pe_header() will try to
        # read (NumberOfRvaAndSizes itself is dump/attacker-controlled and
        # unbounded) -- declared_directory_count records THIS capped value,
        # not the raw field, so a later len(data_directories) ==
        # declared_directory_count comparison means what it says. Left as
        # `None` (never `0`) when the field's own 4 bytes were not
        # captured at all: `0` would itself be a positive "this image
        # declares no data directories" claim (issue #39 / contract
        # §3.5.2), and the guard above not being satisfied means nothing
        # was actually read here to support that claim.
        declared_directory_count = min(struct.unpack_from('<I', data, num_rva_sizes_off)[0], 16)
        for i in range(declared_directory_count):
            entry_off = dir_off + i * 8
            if entry_off + 8 > len(data):
                break
            rva, size = struct.unpack_from('<II', data, entry_off)
            data_directories.append((rva, size))
    result['data_directories'] = data_directories
    result['declared_directory_count'] = declared_directory_count
    result['directories_complete'] = (declared_directory_count is not None
                                       and len(data_directories) == declared_directory_count)

    sec_off = coff_off + 20 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        name = data[base:base + 8].rstrip(b'\x00').decode('latin1', errors='replace')
        vsize, vaddr, rawsize, rawptr = struct.unpack_from('<IIII', data, base + 8)
        characteristics = struct.unpack_from('<I', data, base + 36)[0]
        sections.append({
            'name': name, 'virtual_address': vaddr, 'virtual_size': vsize,
            'pointer_to_raw_data': rawptr, 'size_of_raw_data': rawsize,
            'characteristics': characteristics,
            'is_executable': bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
            'is_writable':   bool(characteristics & IMAGE_SCN_MEM_WRITE),
            'is_readable':   bool(characteristics & IMAGE_SCN_MEM_READ),
        })
    result['sections'] = sections

    # A structurally valid PE needs the FULL declared section table
    # recoverable, not just the fixed-size headers before it — a truncated
    # read (data cut off mid-table) is a partial parse, not a validated one.
    if len(sections) == num_sections:
        result['valid'] = True
    elif not result['reason']:
        result['reason'] = f'section table truncated ({len(sections)}/{num_sections} recovered)'
        result['insufficient_data'] = True

    return result


def expected_protection_name(is_readable: bool, is_writable: bool, is_executable: bool) -> str:
    """Map a PE section's declared R/W/X characteristics onto the Windows
    page-protection constant a freshly, unmodified-loaded section would
    carry (before any COW promotion)."""
    if is_executable and is_writable:
        return 'PAGE_EXECUTE_READWRITE'
    if is_executable and is_readable:
        return 'PAGE_EXECUTE_READ'
    if is_executable:
        return 'PAGE_EXECUTE'
    if is_writable:
        return 'PAGE_READWRITE'
    if is_readable:
        return 'PAGE_READONLY'
    return 'PAGE_NOACCESS'



# Live protection states a declared executable-but-not-writable ("RX")
# section can legitimately carry with NO loader intervention beyond
# normal mapping. PAGE_EXECUTE_WRITECOPY belongs here — Windows commonly
# maps RX image sections copy-on-write (so the loader/debugger CAN patch
# a byte, e.g. for a breakpoint or hot-patch prologue, without corrupting
# the shared mapping other processes use) even when nothing was ever
# actually written. A prior version of this check matched any protection
# NAME containing the substring "WRITE", which made PAGE_EXECUTE_WRITECOPY
# indistinguishable from PAGE_EXECUTE_READWRITE and flagged every
# completely ordinary, unmodified DLL as "stomped".
NORMAL_IMAGE_PROTECTIONS = frozenset({
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_WRITECOPY",
})


def section_protection_deviates(actual_protect_name: str, section: dict) -> bool:
    """
    True when LIVE memory protection on a section the on-disk PE header
    declares executable-but-not-writable is something OTHER than the
    normal, unmodified-mapping set (NORMAL_IMAGE_PROTECTIONS) — most
    notably PAGE_EXECUTE_READWRITE, which grants direct write access with
    no copy-on-write semantics and has no legitimate reason to exist on a
    section the loader mapped read/execute-only.

    This is deliberately a WEAKER, structural-only signal than "this
    section was stomped": PAGE_EXECUTE_WRITECOPY is explicitly excluded
    (see NORMAL_IMAGE_PROTECTIONS) because it is normal, unmodified-loader
    behavior, not evidence of anything. A True result here is a LEAD —
    "this section's protection differs from what an untouched mapping
    would show" — not proof the section's CONTENT actually changed.
    Callers must corroborate with verified content evidence (an on-disk
    reference diff, or similar) before treating this as a detection.
    """
    if not section['is_executable'] or section['is_writable']:
        return False
    name = actual_protect_name or ''
    return name not in NORMAL_IMAGE_PROTECTIONS


# ── Base relocation normalization ────────────────────────────────────────
# Used by hunt/stomping/'s on-disk-vs-memory content diff: a module
# loaded at a different address than its preferred ImageBase (ASLR, or a
# base collision forcing the loader to relocate it) has every absolute
# address the linker baked into that build's on-disk bytes patched at
# load time via the .reloc table. Without undoing that, a section that
# was NEVER touched by anything except normal loading can still show
# byte-for-byte differences from its on-disk original — a false positive
# for "stomping" that has nothing to do with tampering.

IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_REL_BASED_ABSOLUTE = 0    # padding entry, not a real fixup
IMAGE_REL_BASED_HIGHLOW  = 3    # 32-bit fixup
IMAGE_REL_BASED_DIR64    = 10   # 64-bit fixup

# The HIGHLOW/DIR64 handling below is a COMPLETE normalization only for
# these two machine types: x86 and x64 linkers exclusively use HIGHLOW/
# DIR64 (plus ABSOLUTE padding) for base relocations. ARM/ARM64 binaries
# use additional, differently-encoded relocation types (MOVW/MOVT pairs,
# Thumb variants, ADRP/ADD instruction-embedded fixups) that this function
# does not decode — walking the table and applying only the entries that
# happen to look like HIGHLOW/DIR64 would leave the rest un-normalized and
# silently understate how different two truly-relocated ARM images are.
# Any relocation requirement (delta != 0) on an unlisted machine type is
# therefore refused outright (status="unavailable"), not partially done.
_RELOCATION_SUPPORTED_MACHINES = {0x014c, 0x8664}   # I386, AMD64


@dataclass
class RelocationResult:
    """
    Result of apply_base_relocations() — deliberately NOT a bare bytes
    return, so a caller can tell "normalization succeeded" apart from
    "normalization was skipped/failed and these bytes are UNCHANGED from
    the input" without inspecting the bytes themselves. Treating the
    latter as if it were the former was a real bug: a corrupt or
    unavailable relocation table produced ordinary-looking (unmodified)
    output bytes, which a caller comparing them against memory would
    trust as a validly-normalized comparison when it never was one.

    status:
      "applied"     — delta != 0 and the relocation table was walked to
                       completion; `data` has fixups applied.
      "not_needed"  — delta == 0 (module loaded at its preferred base);
                       `data` is returned unchanged, which is correct.
      "unavailable" — delta != 0 but there was no BASERELOC directory to
                       use (absent/empty), or the machine type isn't one
                       this function fully supports (see
                       _RELOCATION_SUPPORTED_MACHINES). `data` is
                       UNCHANGED — a comparison against it is NOT a
                       normalized comparison.
      "malformed"   — delta != 0, a BASERELOC directory exists, but the
                       table itself (or an entry's target RVA) was
                       truncated/out-of-bounds partway through, OR an
                       entry used a relocation type this function doesn't
                       decode (neither ABSOLUTE/HIGHLOW/DIR64 — see
                       unsupported_types below). `data` reflects whatever
                       was successfully applied before the problem was
                       hit — the caller MUST NOT trust it as a complete
                       normalization; treat exactly like "unavailable".
    applied_count: number of HIGHLOW/DIR64 fixups actually applied.
    unsupported_types: sorted list of relocation type values encountered
      that were neither ABSOLUTE (padding, expected) nor HIGHLOW/DIR64.
      Any entry of this kind means the table could NOT be fully decoded,
      so it always forces status="malformed" too (an un-normalized
      address left in `data` would otherwise look identical to a
      correctly-normalized one to a byte-diffing caller) — this field is
      purely diagnostic detail about WHICH type broke the walk, not a
      softer outcome than "malformed".
    """
    data: bytes
    status: str
    applied_count: int = 0
    unsupported_types: list = field(default_factory=list)


def _rva_to_file_offset(sections: list, rva: int, width: int = 0) -> "int|None":
    """
    Translate a Relative Virtual Address to a byte offset inside the PE
    FILE, via the section table.

    Only RVAs inside a section's actual ON-DISK raw-data extent
    (virtual_address .. +size_of_raw_data) are translatable. A section's
    virtual_size can extend past its size_of_raw_data — e.g. a
    zero-padded .bss-like tail the LOADER fills in at load time — and
    that virtual-only tail has no corresponding file bytes at all.
    Matching against virtual_size (the old behavior) would map an RVA in
    that tail to pointer_to_raw_data + (rva - virtual_address), a file
    offset with no real relationship to the RVA: it either lands past
    this section's actual raw data (silently aliasing a neighboring
    section's bytes or padding) or, for a small enough offset, happens to
    look like a plausible-but-wrong location. Either way it is not "the
    file offset this RVA corresponds to", so such an RVA must translate
    to None (unmapped), not a wrong-but-in-range answer.

    `width`, if given, additionally requires the whole [rva, rva+width)
    span to fit inside the raw-data extent, not just the starting byte —
    used for both a fixup's 4/8-byte target and the reloc directory's own
    span, so a target straddling the raw-data boundary is rejected rather
    than partially translated.
    """
    for s in sections:
        raw_size = s['size_of_raw_data']
        if raw_size <= 0:
            continue
        if s['virtual_address'] <= rva < s['virtual_address'] + raw_size:
            offset_in_section = rva - s['virtual_address']
            if width and offset_in_section + width > raw_size:
                return None
            return s['pointer_to_raw_data'] + offset_in_section
    return None


def apply_base_relocations(data: bytes, pe: dict, delta: int) -> RelocationResult:
    """
    Apply a load-time base-relocation delta to a COPY of `data` (a PE FILE
    image — i.e. `data` is indexed by FILE offset, the same indexing
    parse_pe_header()'s section table uses) so that RVAs the loader would
    have fixed up at load time reflect what memory SHOULD contain once
    relocated by `delta` = actual_load_base - preferred_image_base
    (pe['image_base'], from parsing `data`'s own header).

    Only relocation types mainstream Windows x86/x64 linkers emit are
    applied: IMAGE_REL_BASED_HIGHLOW (32-bit fixups) and
    IMAGE_REL_BASED_DIR64 (64-bit fixups); IMAGE_REL_BASED_ABSOLUTE is
    block-alignment padding, not a real fixup, and is skipped. See
    RelocationResult and _RELOCATION_SUPPORTED_MACHINES for exactly when
    that is (and is not) a complete normalization.

    Never raises and never mutates `data` — always returns a
    RelocationResult wrapping a copy (not the same object).
    """
    out = bytearray(data)
    if delta == 0:
        return RelocationResult(data=bytes(out), status="not_needed")

    if pe.get('machine') not in _RELOCATION_SUPPORTED_MACHINES:
        return RelocationResult(data=bytes(out), status="unavailable")

    dirs = pe.get('data_directories') or []
    if len(dirs) <= IMAGE_DIRECTORY_ENTRY_BASERELOC:
        return RelocationResult(data=bytes(out), status="unavailable")
    reloc_rva, reloc_size = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    if not reloc_rva or not reloc_size:
        return RelocationResult(data=bytes(out), status="unavailable")

    reloc_file_off = _rva_to_file_offset(pe['sections'], reloc_rva, width=reloc_size)
    if reloc_file_off is None or reloc_file_off + reloc_size > len(data):
        return RelocationResult(data=bytes(out), status="malformed")

    pos, end = reloc_file_off, reloc_file_off + reloc_size
    applied_count = 0
    unsupported_types: set = set()
    malformed = False
    while pos + 8 <= end:
        try:
            block_rva, block_size = struct.unpack_from('<II', data, pos)
        except struct.error:
            malformed = True
            break
        if block_size < 8 or block_size % 4 != 0 or pos + block_size > end:
            malformed = True
            break
        entry_count = (block_size - 8) // 2
        for i in range(entry_count):
            entry_off = pos + 8 + i * 2
            if entry_off + 2 > len(data):
                malformed = True
                break
            entry = struct.unpack_from('<H', data, entry_off)[0]
            rtype, page_off = entry >> 12, entry & 0xFFF
            if rtype == IMAGE_REL_BASED_ABSOLUTE:
                continue
            if rtype not in (IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_DIR64):
                # An unrecognized fixup type means this table is NOT fully
                # normalizable — silently skipping it (old behavior: kept
                # status="applied" with the type merely noted in
                # unsupported_types) left that address un-normalized while
                # still telling the caller the comparison was trustworthy.
                # That is exactly the same failure mode as an unsupported
                # machine type: mark the whole normalization malformed
                # rather than partially done.
                unsupported_types.add(rtype)
                malformed = True
                continue
            width = 4 if rtype == IMAGE_REL_BASED_HIGHLOW else 8
            target_file_off = _rva_to_file_offset(pe['sections'], block_rva + page_off, width=width)
            if target_file_off is None or target_file_off + width > len(out):
                malformed = True
                continue
            if rtype == IMAGE_REL_BASED_HIGHLOW:
                val = struct.unpack_from('<I', out, target_file_off)[0]
                struct.pack_into('<I', out, target_file_off, (val + delta) & 0xFFFFFFFF)
            else:
                val = struct.unpack_from('<Q', out, target_file_off)[0]
                struct.pack_into('<Q', out, target_file_off, (val + delta) & 0xFFFFFFFFFFFFFFFF)
            applied_count += 1
        if malformed:
            break
        pos += block_size

    # A well-formed BASERELOC directory is a run of blocks that exactly
    # fills the directory — pos stops at `end` only if the last block's
    # declared size accounted for every byte. Exiting the loop early
    # because fewer than 8 bytes remained (pos + 8 > end) without having
    # reached `end` means there is unconsumed trailing residue — a
    # directory whose declared size doesn't match its actual block
    # layout, which is malformed the same way a corrupt block is, not a
    # silently-ignorable few bytes of padding. This also implicitly
    # rejects a directory too small to hold even one block header
    # (reloc_size 1-7): the loop runs zero iterations and pos never
    # reaches end.
    if not malformed and pos != end:
        malformed = True

    return RelocationResult(
        data=bytes(out),
        status="malformed" if malformed else "applied",
        applied_count=applied_count,
        unsupported_types=sorted(unsupported_types),
    )

def _pe_timestamp_to_str(ts: int) -> str:
    """
    Convert a PE TimeDateStamp (Unix epoch, 32-bit) to a UTC string.
    Returns a dimmed note for zero / sentinel values.
    """
    import datetime
    if not ts:
        return DIM("(not set)")
    if ts == 0xFFFFFFFF:
        return DIM("(reproducible build — timestamp suppressed)")
    try:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        if dt.year < 1980 or dt.year > 2040:
            return f"0x{ts:08x}  {YELLOW('(suspicious value)')}"
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return f"0x{ts:08x}  {YELLOW('(out of range)')}"


def _version_str(vi) -> str:
    """
    Format VS_FIXEDFILEINFO into 'major.minor.patch.build' strings.
    Returns None if the block is absent or entirely zero.
    """
    if vi is None:
        return None
    try:
        fv_ms = vi.dwFileVersionMS
        fv_ls = vi.dwFileVersionLS
        pv_ms = vi.dwProductVersionMS
        pv_ls = vi.dwProductVersionLS
        if fv_ms == 0 and fv_ls == 0 and pv_ms == 0 and pv_ls == 0:
            return None
        file_ver    = f"{fv_ms >> 16}.{fv_ms & 0xFFFF}.{fv_ls >> 16}.{fv_ls & 0xFFFF}"
        product_ver = f"{pv_ms >> 16}.{pv_ms & 0xFFFF}.{pv_ls >> 16}.{pv_ls & 0xFFFF}"
        if file_ver == product_ver:
            return file_ver
        return f"{file_ver}  (product: {product_ver})"
    except Exception:
        return None


def _filetime_to_str(ft: int) -> str:
    """
    Convert a Windows FILETIME (100-ns intervals since 1601-01-01) to a
    human-readable UTC string.  Returns "(none)" for zero / unset values.
    """
    import datetime
    if not ft:
        return "(none)"
    try:
        # FILETIME epoch offset to Unix epoch in microseconds
        EPOCH_DIFF_US = 11644473600 * 1_000_000
        us = ft // 10 - EPOCH_DIFF_US
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return f"0x{ft:x}"


def _duration_100ns_to_str(units) -> str:
    """
    Convert a duration expressed in 100-nanosecond intervals — as
    documented for MINIDUMP_THREAD_INFO.KernelTime/UserTime (CPU time
    consumed, NOT a point-in-time timestamp — unlike CreateTime/ExitTime,
    which use the same 100ns unit but as a FILETIME epoch offset) — into a
    human-readable duration string. Printing the raw integer with no unit
    is misleading: it looks like it could be ms or a counter.
    """
    if not units:
        return "0s"
    try:
        return f"{units / 10_000_000:.3f}s  ({units} × 100ns)"
    except Exception:
        return str(units)


# ── Bounded in-memory Import Address Table parsing (issue #39) ──────────
# A bounded, defensive walk of a live process image's standard Import
# Directory (data directory index 1) and IAT Directory (index 12),
# reusing parse_pe_header()'s already-validated header/data-directory
# facts for the SAME image. Unlike parse_pe_header() itself, this does
# NOT take a single `bytes` buffer -- an IAT's DLL/symbol names, its
# Import Name Table (INT), and its IAT array can each sit arbitrarily far
# from the header and from each other -- so every read here goes through
# a caller-supplied `read(addr, size) -> bytes` callback instead of a
# fixed buffer. This keeps pe_utils free of any minidump-specific reader
# coupling and makes the whole walk directly testable against a
# synthetic in-memory image with no MinidumpFile fixture required.
#
# `read` is treated as untrusted: it may return fewer bytes than asked,
# empty bytes, or raise -- none of that is allowed to propagate out of
# parse_iat(), and every call is charged against the module-level byte/
# operation budgets below so a "successful" reader that only ever trickles
# back one byte at a time still cannot hang the walk.

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_IAT    = 12

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_UINT64_MAX = 0xFFFFFFFFFFFFFFFF
_UINT32_MAX = 0xFFFFFFFF

# Frozen budgets (contract §1.8). Two independent CUMULATIVE budgets
# (bytes and read operations) exist alongside the four per-item caps
# because a byte budget alone does not catch a pathological
# many-tiny-reads pattern: thousands of one-byte reads stay far under
# MAX_IAT_BYTES_READ while still hanging the walk.
MAX_IAT_DLLS             = 256          # import descriptors walked
MAX_IAT_ENTRIES_PER_DLL  = 4096         # thunks per descriptor
MAX_IAT_TOTAL_ENTRIES    = 65536        # thunks overall
MAX_IAT_NAME_LENGTH      = 512          # bytes read for one DLL/symbol name
MAX_IAT_BYTES_READ       = 16 * 1024 * 1024   # cumulative bytes across the walk
MAX_IAT_READ_OPERATIONS  = 8192         # individual bounded reads across the walk

_IMPORT_DESCRIPTOR_SIZE = 20   # OriginalFirstThunk, TimeDateStamp,
                                # ForwarderChain, Name, FirstThunk -- each
                                # a 4-byte RVA/value, always 4 bytes wide
                                # regardless of PE32 vs PE32+ (only the
                                # INT/IAT THUNK values themselves widen to
                                # 8 bytes for PE32+).
_DESCRIPTOR_STRUCT = struct.Struct('<IIIII')


@dataclass(frozen=True)
class ImportEntry:
    """One IAT thunk slot, matching the #37 contract's per-entry shape
    (§3.5.3) field-for-field. Addresses are kept as plain ints -- hex
    formatting is an output-layer concern (§1.3 of the contract), not
    this parser's.

    `import_by` is `"name"` or `"ordinal"` for a normally-resolvable
    thunk, or `"unavailable"` when the descriptor's OriginalFirstThunk is
    0: by the time a LIVE process is captured, the loader has already
    overwritten the FirstThunk slot with the resolved function address,
    so whether the original import was by name or by ordinal is
    genuinely no longer recoverable from memory -- reported as
    unavailable rather than guessed (issue #39's "First-release
    boundary": preserve captured IAT targets, never invent a name or
    ordinal for this case)."""
    dll: "str | None"
    import_by: str
    symbol: "str | None"
    ordinal: "int | None"
    iat_slot_va: "int | None"
    resolved_target_va: "int | None"
    slot_in_bounds: "bool | None"


@dataclass(frozen=True)
class IatDiagnostic:
    """A successfully-completed observation about the IAT walk that is
    NOT an evidence gap -- mirrors the #37 contract's diagnostic shape
    (§3.4.4/§3.5.5): it can never affect completeness and carries no
    verdict semantics. Defined locally, rather than importing
    dumpex.core.process_info's own ProcessDiagnostic, so this module has
    no dependency on process_info -- which itself imports pe_utils, so
    the reverse import would be circular. The command layer (#40) is
    expected to translate these into whichever shared diagnostic type it
    ultimately renders."""
    code: str
    severity: str
    message: str
    details: dict = field(default_factory=dict)
    affected_count: "int | None" = None


@dataclass(frozen=True)
class IatTruncation:
    """Attribution for why the walk stopped early -- the #37 contract's
    IAT_ENTRIES_TRUNCATED shape (§3.5.4): `scope` names WHICH of the five
    budgets in §1.8 triggered first, so the command layer can render the
    exact triggering constant instead of a generic "walk stopped"."""
    scope: str
    budget_limit: int
    budget_consumed: int


@dataclass(frozen=True)
class IatParseResult:
    """Normalized IAT table metadata + entries, matching the #37
    contract's `iat` object (§3.5) field-for-field except that addresses
    stay plain ints and truncation/diagnostic attribution stay as typed
    Python values rather than final rendered JSON -- the command layer
    (#40) owns turning this into CoverageLimitation/JSON records.

    `directory_table_incomplete` is true exactly when the command layer
    must account for §3.5.2's IAT_DIRECTORY_TABLE_INCOMPLETE limitation:
    either `import_directory_present` or `table_present` resolved to
    `None` (data-directory presence itself is undetermined).
    `directory_incomplete_affected_count` is that limitation's optional
    `affected_count` (§3.5.2's two cases: a known short-by-N count, or
    `None` when even `declared_directory_count` itself is unknown),
    always `None` when `directory_table_incomplete` is False.

    `descriptor_read_failed_count`/`descriptor_short_read_count`,
    `thunk_read_failed_count`/`thunk_short_read_count`, and
    `name_read_failed_count` are the aggregate `affected_count`s for
    IAT_DESCRIPTOR_READ_FAILED/_SHORT_READ, IAT_THUNK_READ_FAILED/
    _SHORT_READ, and IAT_NAME_READ_FAILED respectively (§6.1) -- each
    fires as its own limitation only when its count is nonzero.
    `unterminated_table`/`cycle_detected`/`bounds_exceeded` map to
    IAT_UNTERMINATED_TABLE/IAT_CYCLE_DETECTED/IAT_BOUNDS_EXCEEDED, each a
    plain boolean since none of the three carries an affected_count in
    the frozen registry."""
    import_directory_present: "bool | None"
    import_directory_va: "int | None"
    import_directory_size: "int | None"
    table_present: "bool | None"
    table_va: "int | None"
    table_size: "int | None"
    has_entries: bool
    dll_count: int
    entry_count: int
    entries: tuple
    diagnostics: tuple
    directory_table_incomplete: bool
    directory_incomplete_affected_count: "int | None"
    directory_read_failed: bool
    directory_short_read: bool
    descriptor_read_failed_count: int
    descriptor_short_read_count: int
    thunk_read_failed_count: int
    thunk_short_read_count: int
    name_read_failed_count: int
    unterminated_table: bool
    cycle_detected: bool
    bounds_exceeded: bool
    truncation: "IatTruncation | None"


class _IatBudget:
    """Tracks the two CUMULATIVE, cross-descriptor budgets (§1.8) that a
    per-item cap (MAX_IAT_DLLS etc.) cannot catch on its own."""
    __slots__ = ("bytes_used", "ops_used", "scope")

    def __init__(self):
        self.bytes_used = 0
        self.ops_used = 0
        self.scope = None   # "iat_bytes_read" | "iat_read_operations" | None

    @property
    def exhausted(self) -> bool:
        return self.scope is not None

    def truncation(self) -> IatTruncation:
        if self.scope == "iat_bytes_read":
            return IatTruncation("iat_bytes_read", MAX_IAT_BYTES_READ, self.bytes_used)
        return IatTruncation("iat_read_operations", MAX_IAT_READ_OPERATIONS, self.ops_used)


def _bounded_read(read, addr: int, want: int, budget: "_IatBudget"):
    """One budgeted call to the caller's `read(addr, size)`. Returns
    `(data: bytes, status)`, status one of:
      "ok"     -- got exactly `want` bytes
      "short"  -- got fewer bytes than `want`, for a reason other than
                  budget exhaustion (the reader itself came up short --
                  e.g. the requested range runs past what was captured)
      "failed" -- read() raised, returned None/non-bytes-like data, or
                  returned no bytes
      "budget" -- one of the two cumulative budgets is already exhausted,
                  or servicing `want` in full would exceed it; `data` may
                  still be non-empty (whatever the budget did allow)
    Never raises, no matter what `read` does -- including a `read` that
    hands back something that isn't actually bytes-like, or that returns
    MORE than the `ask` bytes actually requested: every caller of this
    function immediately struct.unpacks a FIXED-width buffer from `data`,
    and struct.unpack() requires an EXACT-size buffer, so an oversized
    result is clipped here -- the one point every read passes through --
    rather than letting a struct.error escape parse_iat() from deep
    inside the walk.
    """
    if want <= 0:
        return b"", "ok"
    if budget.exhausted:
        return b"", "budget"
    if budget.ops_used + 1 > MAX_IAT_READ_OPERATIONS:
        budget.scope = "iat_read_operations"
        return b"", "budget"
    remaining = MAX_IAT_BYTES_READ - budget.bytes_used
    if remaining <= 0:
        budget.scope = "iat_bytes_read"
        return b"", "budget"
    ask = min(want, remaining)
    budget.ops_used += 1
    try:
        data = read(addr, ask)
    except Exception:
        return b"", "failed"
    # `bytes(data)` alone is not a safe validation: bytes(20) does NOT
    # raise, it silently produces 20 zero bytes -- a `read` that (by bug
    # or adversarially) returns a plain int would then be indistinguishable
    # from a genuine, successful zero-filled read, AND a large enough int
    # would make `bytes(data)` itself allocate an unbounded buffer,
    # defeating the whole point of a byte-budgeted reader. Only an
    # object that is ALREADY bytes-like is accepted; anything else is a
    # failed read, never coerced.
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return b"", "failed"
    try:
        # memoryview + cast("B") + slice-BEFORE-copy: clipping via a view
        # first, then materializing only the (at most `ask`-byte) result
        # with .tobytes(), avoids copying an entire oversized bytearray/
        # memoryview just to throw most of it away. This is also the one
        # place a bytes-like-but-unusable object is caught -- e.g. a
        # released memoryview raises ValueError ("operation forbidden on
        # released memoryview object") on essentially any operation,
        # including a bare bytes() call, which must never be allowed to
        # escape uncaught from here.
        data = memoryview(data).cast("B")[:ask].tobytes()
    except Exception:
        return b"", "failed"
    budget.bytes_used += len(data)
    if not data:
        return b"", "failed"
    if ask < want:
        # The byte budget allowed fewer bytes than this field/name
        # actually needs -- budget exhaustion, not a short read the
        # source itself produced.
        budget.scope = "iat_bytes_read"
        return data, "budget"
    if len(data) < ask:
        return data, "short"
    return data, "ok"


def _read_bounded_name(read, addr: int, budget: "_IatBudget"):
    """Read a null-terminated byte string at `addr`, bounded at
    MAX_IAT_NAME_LENGTH bytes. Returns `(name: str | None, status)`:
    status "ok" when a terminator was found, "unterminated" when the
    whole MAX_IAT_NAME_LENGTH-byte cap was read with no NUL in it (a name
    that long is unavailable, not truncated-but-kept -- this codebase
    does not fabricate partial evidence), or one of _bounded_read()'s own
    "failed"/"budget" statuses when nothing usable came back at all."""
    data, status = _bounded_read(read, addr, MAX_IAT_NAME_LENGTH, budget)
    if not data:
        return None, status
    nul = data.find(b"\x00")
    if nul != -1:
        return data[:nul].decode("latin1", errors="replace"), "ok"
    if status == "short":
        return None, "failed"      # source ran out before any terminator
    return None, "unterminated"    # read the full cap; still no terminator


def _resolve_directory_present(index: int, declared_directory_count, data_directories):
    """§3.5.2's three-state presence resolution for one data-directory
    index, reused verbatim from the frozen contract's own pseudocode:
    `None` when the directory count itself is unknown, `False` when the
    image positively declares no such directory (or a captured zero
    RVA), `True` when a captured non-zero RVA is present, and `None`
    again when the index is declared but its bytes were never captured."""
    if declared_directory_count is None:
        return None
    if index >= declared_directory_count:
        return False
    if index >= len(data_directories):
        return None
    rva, _size = data_directories[index]
    return rva != 0


@dataclass(frozen=True)
class IatOutcome:
    """§3.5.2's frozen consequences of one
    (import_directory_present, table_present) pair."""
    walk_descriptors: bool
    # "IAT_DIRECTORY_TABLE_INCOMPLETE", or None when the pair is fully
    # determined and nothing is missing.
    limitation: "str | None"
    # "IAT_BOUNDS_CHECK_UNAVAILABLE", or None.
    diagnostic: "str | None"


def _select_iat_outcome(import_directory_present, table_present) -> IatOutcome:
    """§3.5.2's outcome matrix, as the ONE place the three consequences of
    a presence pair are decided.

    The three facts were previously decided at three separate sites
    inside parse_iat() -- `import_present is None or table_present is
    None` for the limitation, a bare `if import_present` for the walk,
    and `if import_present and table_present is False` for the diagnostic
    -- each correct, none of them named, and no single expression a
    reader (or a test) could point at and call "the matrix". Collecting
    them here is what lets tests/unit/test_recon_contract_semantics.py
    run §3.5.2's table against shipped behavior instead of matching the
    markdown's wording, which is all that guarded this before.

    Both inputs are nullable booleans and are compared with `is`, never
    bare truthiness: `not import_directory_present` is True for `False`
    and `None` alike, and those two rows of the matrix have different
    outcomes (determined-absent imports are `complete`; undetermined ones
    are `partial`, exit 3).

    Note the walk decision is only half the real condition at its call
    site: parse_iat() also requires a resolvable `import_directory_va`.
    That guard is deliberately NOT folded in here -- it is an address-
    arithmetic failure, not one of §3.5.2's presence states, and the
    matrix stays a pure function of the pair it is defined over.
    """
    if import_directory_present is None:
        # `null | anything`: nothing is claimed, nothing is walked.
        return IatOutcome(False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)
    if import_directory_present is False:
        # Imports are determined absent, so there is nothing to walk and
        # no bounds check to miss. An undetermined index 12 is still its
        # own, narrower gap -- it does not retract the import claim.
        if table_present is None:
            return IatOutcome(False, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)
        return IatOutcome(False, None, None)
    # import_directory_present is True -- descriptors are walked in every
    # remaining row; only the slot-bounds check varies.
    if table_present is None:
        return IatOutcome(True, "IAT_DIRECTORY_TABLE_INCOMPLETE", None)
    if table_present is False:
        # Determined absent: an answered question, so a diagnostic and
        # not a limitation -- coverage is unaffected (§1.6).
        return IatOutcome(True, None, "IAT_BOUNDS_CHECK_UNAVAILABLE")
    return IatOutcome(True, None, None)


def parse_iat(read, image_base: int, pe: dict) -> IatParseResult:
    """Bounded, defensive walk of the standard Import Directory (data
    directory index 1) and IAT Directory (index 12) belonging to the
    image at `image_base`, reusing `pe` -- an already-validated
    parse_pe_header() result for the SAME image -- for its
    data_directories/declared_directory_count/is_pe32_plus facts (issue
    #39: "reuse the validated PE32/PE32+ header facts ... already
    provided by parse_pe_header()"). Never raises, no matter what `read`
    does or what `pe`/`image_base` contain.

    `read(addr, size) -> bytes` is the ONLY I/O this function performs.
    Every RVA is resolved as `image_base + rva` -- memory-image
    addressing, never disk-file RVA-to-offset translation (issue #39's
    explicit scope boundary) -- so a relocated image (loaded somewhere
    other than the header's own declared preferred base) is read
    correctly as long as the caller passes the image's ACTUAL load
    address, not `pe['image_base']`.
    """
    data_directories = pe.get('data_directories') or []
    declared_directory_count = pe.get('declared_directory_count')
    is_pe32_plus = bool(pe.get('is_pe32_plus'))
    thunk_width = 8 if is_pe32_plus else 4
    ordinal_flag = IMAGE_ORDINAL_FLAG64 if is_pe32_plus else IMAGE_ORDINAL_FLAG32
    thunk_struct = struct.Struct('<Q') if is_pe32_plus else struct.Struct('<I')

    import_present = _resolve_directory_present(
        IMAGE_DIRECTORY_ENTRY_IMPORT, declared_directory_count, data_directories)
    table_present = _resolve_directory_present(
        IMAGE_DIRECTORY_ENTRY_IAT, declared_directory_count, data_directories)
    # §3.5.2's matrix, decided once. Every consequence below reads it
    # rather than re-deriving its own condition from the pair.
    outcome = _select_iat_outcome(import_present, table_present)

    entries = []
    directory_read_failed = directory_short_read = False
    descriptor_read_failed = descriptor_short_read = 0
    thunk_read_failed = thunk_short_read = 0
    name_read_failed = 0
    unterminated_table = False
    cycle_detected = False
    bounds_exceeded = False
    truncation = None
    dll_count = 0
    entry_count_total = 0

    visited = set()   # every descriptor/thunk-slot address computed across
                       # the whole walk -- see _visit()'s own docstring for
                       # what counts as a repeat here and why.

    def _addr(base: int, rva: int):
        """`base + rva`, refused (rather than silently wrapped) once it
        exceeds a real 64-bit address -- issue #39's "integer overflow"
        and "out-of-range RVAs" requirements. Never negative either: both
        inputs are non-negative by construction, but a hostile `pe` dict
        handed in by a caller that skipped parse_pe_header() could still
        carry a negative image_base. This is the ONLY place any address
        in this function is computed -- including import_directory_va/
        table_va/table_end below, not just the addresses computed inside
        the walk loop -- so an image_base near UINT64_MAX combined with a
        large declared RVA is caught before it ever produces a garbage
        "valid-looking" address that nothing downstream would think to
        distrust."""
        nonlocal bounds_exceeded
        va = base + rva
        if va < 0 or va > _UINT64_MAX:
            bounds_exceeded = True
            return None
        return va

    def _visit(addr) -> bool:
        """True (and records the cycle) the second time this exact
        address is computed anywhere in the walk. Guards ONLY the
        structural array-walk addresses (descriptor slots, thunk slots) --
        never the one-shot DLL/symbol NAME reads, which legitimately can
        and do share addresses (see the two call sites below). A repeat
        here happens either because a crafted/corrupt image has two
        descriptors declaring the identical OriginalFirstThunk/FirstThunk
        RVA (a real, reachable input -- see this module's own tests), or
        because address arithmetic wrapped around despite _addr()'s own
        overflow guard; either way, re-reading it would add nothing and
        risks looping if something upstream ever starts stepping through
        these addresses non-monotonically. Every call site treats a True
        result as a reason to stop the ENTIRE walk (stop_all=True), not
        just abandon the current descriptor -- evidence of a repeated/
        looping address is evidence the structure itself cannot be
        trusted, so nothing read afterward is trustworthy either."""
        nonlocal cycle_detected
        if addr in visited:
            cycle_detected = True
            return True
        visited.add(addr)
        return False

    import_directory_va = import_directory_size = None
    if import_present:
        rva, size = data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
        import_directory_va = _addr(image_base, rva)
        import_directory_size = size

    table_va = table_size = table_end = None
    if table_present:
        rva, size = data_directories[IMAGE_DIRECTORY_ENTRY_IAT]
        candidate_va = _addr(image_base, rva)
        if candidate_va is not None:
            candidate_end = _addr(candidate_va, size)
            if candidate_end is not None:
                table_va, table_size, table_end = candidate_va, size, candidate_end
            # candidate_end is None: the range's OWN end overflows even
            # though its start didn't -- table_va/table_size/table_end
            # all stay None rather than reporting a start with no valid
            # end (bounds_exceeded is already set by the failed _addr()
            # call above).

    directory_table_incomplete = outcome.limitation is not None
    directory_incomplete_affected_count = None
    if directory_table_incomplete and declared_directory_count is not None:
        short_by = declared_directory_count - len(data_directories)
        directory_incomplete_affected_count = short_by if short_by > 0 else None

    # How many WHOLE descriptor slots the header's own declared
    # import_directory_size actually has room for -- reading a REAL
    # (non-terminator) descriptor past this means reading memory the
    # Import Directory never claimed as its own (issue #39: untrusted
    # process memory must never be treated as if it belonged to a
    # structure just because it happens to sit right after it). `None`
    # when the size itself is unknown (no directory, or the size wasn't
    # captured) -- in that case only MAX_IAT_DLLS bounds the walk.
    import_directory_capacity = (max(0, import_directory_size // _IMPORT_DESCRIPTOR_SIZE)
                                  if import_directory_size is not None else None)

    stop_all = False

    if outcome.walk_descriptors and import_directory_va is not None:
        budget = _IatBudget()
        d_index = 0
        while True:
            if import_directory_capacity is not None and d_index >= import_directory_capacity:
                # Refuse to even ATTEMPT this read: unlike MAX_IAT_DLLS
                # (dumpex's own arbitrary resource cap, where reading one
                # slot past it just to confirm a terminator is safe --
                # it's still unambiguously part of the same image),
                # import_directory_capacity is derived from the header's
                # OWN declared Size for this table. Reading even one byte
                # past it means reading memory the Import Directory never
                # claimed as its own; if that adjacent memory happens to
                # be zero, a peek-then-check approach would silently
                # accept it as a "legitimate" terminator and report a
                # clean, complete table that was never actually bounded
                # by anything the header declared. So this check runs
                # BEFORE any read is issued, with no exception for a
                # would-be terminator.
                unterminated_table = True
                bounds_exceeded = True
                stop_all = True
                break

            d_addr = _addr(import_directory_va, d_index * _IMPORT_DESCRIPTOR_SIZE)
            if d_addr is None:
                stop_all = True
                break
            if _visit(("descriptor", d_addr)):
                stop_all = True
                break

            raw, status = _bounded_read(read, d_addr, _IMPORT_DESCRIPTOR_SIZE, budget)
            if status == "budget":
                truncation = budget.truncation()
                stop_all = True
                break
            if status == "failed":
                # A failure on the very first descriptor means nothing
                # about the Import Directory was ever recovered at all
                # (IAT_DIRECTORY_READ_FAILED); a failure partway through
                # an otherwise-readable array is a per-descriptor gap
                # instead (IAT_DESCRIPTOR_READ_FAILED) -- the two are
                # different claims in the frozen registry (§6.1) and this
                # is the one point in the walk that can tell them apart.
                if d_index == 0:
                    directory_read_failed = True
                else:
                    descriptor_read_failed += 1
                unterminated_table = True
                stop_all = True
                break
            if status == "short":
                if d_index == 0:
                    directory_short_read = True
                else:
                    descriptor_short_read += 1
                unterminated_table = True
                stop_all = True
                break

            orig_first_thunk, _tds, _fwd, name_rva, first_thunk = _DESCRIPTOR_STRUCT.unpack(raw)
            if orig_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break   # the well-formed end of the descriptor array --
                        # this check runs BEFORE the MAX_IAT_DLLS cap
                        # check just below, so a legitimate terminator
                        # sitting exactly at the cap's boundary is never
                        # misreported as truncation: the cap only fires
                        # for a REAL (non-terminator) descriptor found at
                        # or past it. (import_directory_capacity, by
                        # contrast, is checked at the TOP of this loop,
                        # before any read -- see there for why.)

            if d_index >= MAX_IAT_DLLS:
                unterminated_table = True
                truncation = IatTruncation("iat_dlls", MAX_IAT_DLLS, d_index)
                stop_all = True
                break
            # No total-entries cap check here: whether entry_count_total
            # is already at MAX_IAT_TOTAL_ENTRIES says nothing about
            # THIS descriptor on its own -- it may legitimately
            # contribute zero new entries (an empty-imports DLL, or one
            # whose own first thunk is immediately the terminator), which
            # is not truncation. The thunk loop below is what can
            # actually tell: its own total-entries check fires only once
            # a REAL (non-terminator) thunk is found while the cap is
            # already exhausted.

            dll_name = None
            if name_rva:
                # Deliberately NOT run through _visit(): this is a one-shot
                # leaf string read, not a step in an address-stepped array
                # walk, so a repeat here (e.g. two descriptors legitimately
                # importing from the same DLL and a toolchain that interned
                # the name string) is not evidence of a cycle -- flagging it
                # would falsely trip cycle_detected AND silently drop a
                # perfectly readable name.
                n_addr = _addr(image_base, name_rva)
                if n_addr is not None:
                    dll_name, _ = _read_bounded_name(read, n_addr, budget)
                    if dll_name is None:
                        name_read_failed += 1
                    if budget.exhausted:
                        truncation = budget.truncation()
                        stop_all = True
                        break

            using_int = orig_first_thunk != 0
            thunk_source_rva = orig_first_thunk if using_int else first_thunk
            dll_terminated = True   # vacuously "terminated" -- see below

            if thunk_source_rva:
                dll_terminated = False
                t_index = 0
                while True:
                    slot_off = t_index * thunk_width

                    decide_addr = _addr(image_base, thunk_source_rva + slot_off)
                    if decide_addr is None:
                        stop_all = True
                        break
                    if _visit(("thunk", decide_addr)):
                        # A repeated thunk address is evidence the table
                        # itself cannot be trusted (see _visit()'s own
                        # docstring) -- stop the ENTIRE walk here, not
                        # just this descriptor, so a later descriptor's
                        # data is never reported as if it were reliable.
                        stop_all = True
                        break

                    raw_t, t_status = _bounded_read(read, decide_addr, thunk_width, budget)
                    if t_status == "budget":
                        truncation = budget.truncation()
                        stop_all = True
                        break
                    if t_status == "failed":
                        thunk_read_failed += 1
                        unterminated_table = True
                        break
                    if t_status == "short":
                        thunk_short_read += 1
                        unterminated_table = True
                        break

                    thunk_value = thunk_struct.unpack(raw_t)[0]
                    if thunk_value == 0:
                        dll_terminated = True
                        break

                    # Both caps are checked here, AFTER confirming this
                    # slot is a real (non-zero) thunk -- exactly like the
                    # descriptor-array cap above, so a legitimate
                    # terminator sitting exactly at either cap's boundary
                    # is never misreported as truncation.
                    if t_index >= MAX_IAT_ENTRIES_PER_DLL:
                        unterminated_table = True
                        truncation = IatTruncation("iat_entries_per_dll", MAX_IAT_ENTRIES_PER_DLL, t_index)
                        stop_all = True
                        break
                    if entry_count_total >= MAX_IAT_TOTAL_ENTRIES:
                        unterminated_table = True
                        truncation = IatTruncation("iat_total_entries", MAX_IAT_TOTAL_ENTRIES, entry_count_total)
                        stop_all = True
                        break

                    iat_slot_va = None
                    resolved_target_va = None
                    if first_thunk:
                        iat_addr = _addr(image_base, first_thunk + slot_off)
                        if iat_addr is not None:
                            iat_slot_va = iat_addr
                            if using_int:
                                raw_r, r_status = _bounded_read(read, iat_addr, thunk_width, budget)
                                if r_status == "budget":
                                    truncation = budget.truncation()
                                    stop_all = True
                                elif r_status == "failed":
                                    thunk_read_failed += 1
                                elif r_status == "short":
                                    thunk_short_read += 1
                                else:
                                    resolved_target_va = thunk_struct.unpack(raw_r)[0]
                            else:
                                resolved_target_va = thunk_value

                    slot_in_bounds = None
                    # table_present is a structural fact about the RVA
                    # (§3.5.2) and can be True even when table_va/
                    # table_end themselves ended up None because the
                    # header's own declared range overflowed a real
                    # address (see table_va's own construction above) --
                    # that overflow already set bounds_exceeded, so the
                    # check here must also require an actually-usable
                    # range, not just table_present, or this comparison
                    # would crash comparing None to an int.
                    if table_present and table_va is not None and iat_slot_va is not None:
                        slot_in_bounds = table_va <= iat_slot_va < table_end

                    if not using_int:
                        entries.append(ImportEntry(dll_name, "unavailable", None, None,
                                                    iat_slot_va, resolved_target_va, slot_in_bounds))
                    elif thunk_value & ordinal_flag:
                        entries.append(ImportEntry(dll_name, "ordinal", None, thunk_value & 0xFFFF,
                                                    iat_slot_va, resolved_target_va, slot_in_bounds))
                    else:
                        symbol = None
                        if thunk_value <= _UINT32_MAX:
                            # Same reasoning as the DLL-name read above: a
                            # one-shot leaf read, never run through _visit().
                            s_addr = _addr(image_base, thunk_value + 2)   # skip 2-byte Hint
                            if s_addr is not None:
                                symbol, _ = _read_bounded_name(read, s_addr, budget)
                                if symbol is None:
                                    name_read_failed += 1
                        else:
                            name_read_failed += 1   # RVA doesn't even fit a 32-bit field
                        entries.append(ImportEntry(dll_name, "name", symbol, None,
                                                    iat_slot_va, resolved_target_va, slot_in_bounds))

                    entry_count_total += 1
                    t_index += 1
                # Every exit from the loop above already carries its own
                # attribution (a terminator found -> dll_terminated=True;
                # a cap/budget/read failure -> unterminated_table and/or
                # truncation already set at the exact break site) -- no
                # further bookkeeping is needed once it ends.

            dll_count += 1
            d_index += 1

            if stop_all:
                break

    diagnostics = []
    if outcome.diagnostic == "IAT_BOUNDS_CHECK_UNAVAILABLE":
        diagnostics.append(IatDiagnostic(
            code="IAT_BOUNDS_CHECK_UNAVAILABLE", severity="info",
            message="the image declares no IAT directory, so slot bounds could not be checked",
            details={"import_directory_va": import_directory_va}))

    out_of_bounds = [e for e in entries if e.slot_in_bounds is False]
    if out_of_bounds:
        diagnostics.append(IatDiagnostic(
            code="IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS", severity="warning",
            message=f"{len(out_of_bounds)} IAT slot(s) fall outside the declared IAT directory range",
            affected_count=len(out_of_bounds),
            details={"table_va": table_va, "table_size": table_size,
                     "first_out_of_bounds_slot_va": out_of_bounds[0].iat_slot_va}))

    entry_count = len(entries)
    return IatParseResult(
        import_directory_present=import_present,
        import_directory_va=import_directory_va,
        import_directory_size=import_directory_size,
        table_present=table_present,
        table_va=table_va,
        table_size=table_size,
        has_entries=entry_count > 0,
        dll_count=dll_count,
        entry_count=entry_count,
        entries=tuple(entries),
        diagnostics=tuple(diagnostics),
        directory_table_incomplete=directory_table_incomplete,
        directory_incomplete_affected_count=directory_incomplete_affected_count,
        directory_read_failed=directory_read_failed,
        directory_short_read=directory_short_read,
        descriptor_read_failed_count=descriptor_read_failed,
        descriptor_short_read_count=descriptor_short_read,
        thunk_read_failed_count=thunk_read_failed,
        thunk_short_read_count=thunk_short_read,
        name_read_failed_count=name_read_failed,
        unterminated_table=unterminated_table,
        cycle_detected=cycle_detected,
        bounds_exceeded=bounds_exceeded,
        truncation=truncation,
    )


def _dumpflags_str(flags) -> str:
    """Return a compact label for MINIDUMP_THREAD_INFO DumpFlags."""
    if flags is None:
        return ""
    name = flags.name if hasattr(flags, "name") else str(flags)
    # Map verbose enum names to short tags
    TAG = {
        "MINIDUMP_THREAD_INFO_EXITED_THREAD":   "[EXITED]",
        "MINIDUMP_THREAD_INFO_WRITING_THREAD":  "[DUMPER]",
        "MINIDUMP_THREAD_INFO_ERROR_THREAD":    "[ERROR]",
        "MINIDUMP_THREAD_INFO_INVALID_CONTEXT": "[NO_CTX]",
        "MINIDUMP_THREAD_INFO_INVALID_INFO":    "[NO_INFO]",
        "MINIDUMP_THREAD_INFO_INVALID_TEB":     "[NO_TEB]",
    }
    return TAG.get(name, f"[{name}]") if name else ""

