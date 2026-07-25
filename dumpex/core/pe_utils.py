"""PE / FILETIME formatting utilities."""
import struct
import datetime
from dataclasses import dataclass, field
from dumpex.ui.colors import RED, YELLOW, DIM

# ── PE structural validation ─────────────────────────────────────────────
# Used by hunt/injection.py (structural "is this really a PE header" check,
# replacing a bare MZ-prefix scan) and hunt/stomping.py (section table for
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
    }
    if len(data) < 0x40 or data[:2] != b'MZ':
        result['reason'] = 'no MZ signature'
        return result
    result['has_mz'] = True

    try:
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    except struct.error:
        result['reason'] = 'truncated DOS header (no e_lfanew)'
        return result
    result['e_lfanew'] = e_lfanew

    # e_lfanew is attacker/loader controlled in principle; bound it to a
    # plausible range before trusting it as an offset into `data`.
    if e_lfanew < 4 or e_lfanew > 0x1000 or e_lfanew + 24 > len(data):
        result['reason'] = f'e_lfanew out of plausible range (0x{e_lfanew:x})'
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
        return result

    result['address_of_entry_point'] = struct.unpack_from('<I', data, ep_off)[0]
    result['image_base'] = (struct.unpack_from('<I', data, base_off)[0] if base_size == 4
                             else struct.unpack_from('<Q', data, base_off)[0])
    result['size_of_image'] = struct.unpack_from('<I', data, size_off)[0]

    # Data Directories (RVA, Size) pairs — NumberOfRvaAndSizes precedes the
    # array itself; offsets differ between PE32 and PE32+ because the
    # Windows-specific fields ahead of it (Stack/Heap Reserve/Commit) are
    # 4 bytes wide in PE32 and 8 bytes wide in PE32+. Only used so far for
    # IMAGE_DIRECTORY_ENTRY_BASERELOC (index 5), by stomping.py's
    # relocation-normalized disk diff — parsed here, not per-caller, since
    # every caller needs the same offsets and the same PE32/PE32+ branch.
    num_rva_sizes_off, dir_off = ((92, 96) if base_size == 4 else (108, 112))
    num_rva_sizes_off += opt_off
    dir_off += opt_off
    data_directories = []
    if num_rva_sizes_off + 4 <= len(data):
        num_dirs = min(struct.unpack_from('<I', data, num_rva_sizes_off)[0], 16)
        for i in range(num_dirs):
            entry_off = dir_off + i * 8
            if entry_off + 8 > len(data):
                break
            rva, size = struct.unpack_from('<II', data, entry_off)
            data_directories.append((rva, size))
    result['data_directories'] = data_directories

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
# Used by hunt/stomping.py's on-disk-vs-memory content diff: a module
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
                       truncated/out-of-bounds partway through. `data`
                       reflects whatever was successfully applied before
                       the corruption was hit — the caller MUST NOT trust
                       it as a complete normalization; treat exactly like
                       "unavailable".
    applied_count: number of HIGHLOW/DIR64 fixups actually applied.
    unsupported_types: sorted list of relocation type values encountered
      that were neither ABSOLUTE (padding, expected) nor HIGHLOW/DIR64 —
      informational; their presence does NOT by itself change `status`
      away from "applied", since the recognized fixups were still
      correctly applied, but it does mean some addresses in the compared
      range may remain un-normalized.
    """
    data: bytes
    status: str
    applied_count: int = 0
    unsupported_types: list = field(default_factory=list)


def _rva_to_file_offset(sections: list, rva: int) -> "int|None":
    """Translate a Relative Virtual Address to a byte offset inside the PE FILE, via the section table."""
    for s in sections:
        span = max(s['virtual_size'], s['size_of_raw_data'])
        if s['virtual_address'] <= rva < s['virtual_address'] + span:
            return s['pointer_to_raw_data'] + (rva - s['virtual_address'])
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

    reloc_file_off = _rva_to_file_offset(pe['sections'], reloc_rva)
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
        if block_size < 8 or pos + block_size > end:
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
            target_file_off = _rva_to_file_offset(pe['sections'], block_rva + page_off)
            if target_file_off is None:
                malformed = True
                continue
            if rtype == IMAGE_REL_BASED_HIGHLOW and target_file_off + 4 <= len(out):
                val = struct.unpack_from('<I', out, target_file_off)[0]
                struct.pack_into('<I', out, target_file_off, (val + delta) & 0xFFFFFFFF)
                applied_count += 1
            elif rtype == IMAGE_REL_BASED_DIR64 and target_file_off + 8 <= len(out):
                val = struct.unpack_from('<Q', out, target_file_off)[0]
                struct.pack_into('<Q', out, target_file_off, (val + delta) & 0xFFFFFFFFFFFFFFFF)
                applied_count += 1
            else:
                unsupported_types.add(rtype)
        if malformed:
            break
        pos += block_size

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

