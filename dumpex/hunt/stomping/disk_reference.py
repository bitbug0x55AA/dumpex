"""Reference-file lookup, build-identity matching, and the relocation-
normalized on-disk-vs-memory byte diff — the ONLY path to a nonzero
stomping score (see dumpex/hunt/stomping/__init__.py's module docstring).

`diff_section` receives `read_region` as an explicit callable parameter
and never imports the facade module itself — a caller/test can substitute
a fake reader without needing the facade's own `read_region` name to be
monkeypatched and separately re-imported here (mirrors dumpex/hunt/
injection/memory_scan.py's `_hunt_hidden_pe`; see dumpex/hunt/_runtime.py).
"""
import os
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.core.pe_utils import parse_pe_header, apply_base_relocations
from dumpex.hunt.stomping.memory_scan import _module_basename
from dumpex.hunt.stomping.config import REF_FILE_MAX_READ, MAX_DIFF_RANGES_SCAN


def find_reference_file(module, ref_dir: str):
    """
    Look for a locally-supplied reference copy of `module` under ref_dir,
    matched by basename (case-insensitive) — the module's recorded path is
    from the ORIGINAL (Windows) system and essentially never exists
    verbatim on the analysis machine, so exact-path lookup is not
    attempted at all, only a basename match inside the analyst-supplied
    directory. Returns a path or None.
    """
    base = _module_basename(module)
    if not base or not ref_dir:
        return None
    candidate = os.path.join(ref_dir, base)
    if os.path.isfile(candidate):
        return candidate
    try:
        for fname in os.listdir(ref_dir):
            if fname.lower() == base.lower():
                return os.path.join(ref_dir, fname)
    except OSError:
        pass
    return None


def reference_identity_matches(mem_pe: dict, disk_pe: dict) -> "tuple[bool, str]":
    """
    Compare the in-memory module's OWN header facts against the reference
    file's OWN header facts. All three fields are read directly from each
    side's PE header (never assumed) — this is a coarse but cheap-and-
    effective guard against diffing a same-named-but-different build,
    which would otherwise report ordinary version differences (different
    compiler output, different Windows update) as "stomped".

    Does NOT check the PDB GUID/Age (CodeView debug directory) — that
    would need parsing the Debug Data Directory, which this hunter
    doesn't currently do. Machine + SizeOfImage + TimeDateStamp already
    catches the overwhelming majority of "wrong file/version" cases; a
    reference file that happens to share all three with a genuinely
    different build is not something this check can catch, and is called
    out in the Finding's limitations.
    """
    if mem_pe['machine'] != disk_pe['machine']:
        return False, (f"Machine mismatch (memory=0x{mem_pe['machine']:x}, "
                        f"reference=0x{disk_pe['machine']:x})")
    if mem_pe['size_of_image'] != disk_pe['size_of_image']:
        return False, (f"SizeOfImage mismatch (memory=0x{mem_pe['size_of_image']:x}, "
                        f"reference=0x{disk_pe['size_of_image']:x}) — likely a different build")
    if mem_pe['time_date_stamp'] != disk_pe['time_date_stamp']:
        return False, (f"TimeDateStamp mismatch (memory=0x{mem_pe['time_date_stamp']:x}, "
                        f"reference=0x{disk_pe['time_date_stamp']:x}) — reference file is a "
                        f"different build/version")
    return True, ""


def diff_byte_ranges(a: bytes, b: bytes, max_ranges: int = MAX_DIFF_RANGES_SCAN) -> list:
    """
    Return contiguous (offset, length) ranges where `a` and `b` differ,
    over their shared length — actual changed-byte locations, not just a
    single whole-buffer match/mismatch boolean or hash. Bounded only by
    the large MAX_DIFF_RANGES_SCAN safety ceiling (not the much smaller
    MAX_DIFF_RANGES used for display) — callers that need a RIP/EIP hit
    check must scan the FULL list this returns, not a display-truncated
    slice of it.
    """
    ranges = []
    n = min(len(a), len(b))
    i = 0
    while i < n and len(ranges) < max_ranges:
        if a[i] != b[i]:
            start = i
            while i < n and a[i] != b[i]:
                i += 1
            ranges.append((start, i - start))
        else:
            i += 1
    return ranges


def _diff_section_on_disk(ref_path: str, mem_pe: dict, module_base: int, section: dict,
                           mem_bytes: bytes) -> "dict|None":
    """
    Compare a section's on-disk raw bytes (from the analyst-supplied
    reference file, RELOCATION-NORMALIZED to what memory should contain
    at its actual load address) against the corresponding live memory
    bytes.

    Returns None only if the reference file itself couldn't be read at
    all (I/O error). Otherwise returns:
      {"identity_ok": bool, "identity_reason": str,
       "diff_ranges": [(offset, length), ...]  (ALL of them, up to
           MAX_DIFF_RANGES_SCAN — NOT pre-truncated to the display cap),
       "ranges_truncated": bool, "compared_len": int,
       "disk_sha256": str, "mem_sha256": str}
    identity_ok False means the comparison was skipped (version/identity
    mismatch or an invalid reference header) — diff_ranges is empty in
    that case, and callers must treat this as a coverage gap, not "clean".
    compared_len == 0 with identity_ok True means the section's on-disk
    range couldn't actually be read (truncated/short reference file) —
    also a coverage gap, not "clean" and not "changed".
    """
    try:
        size = os.path.getsize(ref_path)
        if size > REF_FILE_MAX_READ:
            return {"identity_ok": False,
                    "identity_reason": f"reference file exceeds {REF_FILE_MAX_READ} byte cap",
                    "diff_ranges": [], "ranges_truncated": False, "compared_len": 0,
                    "disk_sha256": "", "mem_sha256": ""}
        with open(ref_path, "rb") as fh:
            disk_data = fh.read()
    except OSError:
        return None

    disk_pe = parse_pe_header(disk_data)
    if not disk_pe["valid"]:
        return {"identity_ok": False,
                "identity_reason": f"reference file PE header invalid ({disk_pe['reason']})",
                "diff_ranges": [], "ranges_truncated": False, "compared_len": 0,
                "disk_sha256": "", "mem_sha256": ""}

    identity_ok, identity_reason = reference_identity_matches(mem_pe, disk_pe)
    if not identity_ok:
        return {"identity_ok": False, "identity_reason": identity_reason,
                "diff_ranges": [], "ranges_truncated": False, "compared_len": 0,
                "relocation_failed": False, "disk_sha256": "", "mem_sha256": ""}

    # Relocation-normalize: the reference file's bytes reflect its
    # PREFERRED ImageBase; the in-memory module is loaded at module_base,
    # which can differ (ASLR). Applying that delta to the on-disk copy
    # before comparing means an unmodified-but-relocated section reads as
    # identical, not "changed". If a delta is actually needed and the
    # normalization couldn't be completed (unsupported machine type, a
    # malformed/truncated relocation table, ...), comparing the raw bytes
    # would misreport every relocation-touched instruction as "modified" —
    # a false detection, not a coverage gap we can quietly paper over. So
    # a failed normalization must abort the comparison outright rather
    # than fall through to a byte diff against un-normalized data.
    delta = module_base - disk_pe['image_base']
    reloc = apply_base_relocations(disk_data, disk_pe, delta)
    if delta != 0 and reloc.status != "applied":
        return {"identity_ok": True, "identity_reason": "", "diff_ranges": [],
                "ranges_truncated": False, "compared_len": 0,
                "relocation_failed": True, "relocation_status": reloc.status,
                "disk_sha256": "", "mem_sha256": ""}
    disk_data = reloc.data

    # size_of_raw_data (falling back to virtual_size, matching the length
    # the caller used to bound its own memory read) is the authoritative
    # expected comparison length. A live-memory read that came back
    # shorter than this is a coverage gap — comparing only the bytes that
    # happened to be readable would silently shrink the comparison window
    # and could report "no diff" over a section that was never fully
    # examined.
    expected_len = section["size_of_raw_data"] or section["virtual_size"]
    start = section["pointer_to_raw_data"]
    if (expected_len <= 0 or len(mem_bytes) < expected_len
            or start + expected_len > len(disk_data)):
        return {"identity_ok": True, "identity_reason": "", "diff_ranges": [],
                "ranges_truncated": False, "compared_len": 0,
                "relocation_failed": False, "disk_sha256": "", "mem_sha256": ""}

    disk_slice = disk_data[start:start + expected_len]
    mem_slice  = mem_bytes[:expected_len]
    all_ranges = diff_byte_ranges(disk_slice, mem_slice)
    return {
        "identity_ok": True, "identity_reason": "",
        "diff_ranges":      all_ranges,
        "ranges_truncated": len(all_ranges) >= MAX_DIFF_RANGES_SCAN,
        "compared_len":     expected_len,
        "relocation_failed": False,
        "disk_sha256":      hashlib.sha256(disk_slice).hexdigest(),
        "mem_sha256":       hashlib.sha256(mem_slice).hexdigest(),
    }


def diff_section(mf: MinidumpFile, read_region, ref_path: str, mem_pe: dict, module_base: int,
                  section: dict, va_start: int, va_end: int) -> "dict|None":
    """
    Read the section's live memory bytes and diff them against the
    reference file. Returns {"memory_read_failed": True} if the live
    memory read itself failed or came back empty (a coverage gap distinct
    from every _diff_section_on_disk outcome, none of which ever set that
    key) — otherwise the exact _diff_section_on_disk() result shape.
    """
    try:
        mem_bytes = read_region(mf, va_start,
            min(section["size_of_raw_data"] or section["virtual_size"], va_end - va_start))
    except Exception:
        return {"memory_read_failed": True}
    if not mem_bytes:
        return {"memory_read_failed": True}
    return _diff_section_on_disk(ref_path, mem_pe, module_base, section, mem_bytes)
