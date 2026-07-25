"""Module stomping hunter.

Phase-two detection model (revised after two rounds of review)
──────────────────────────────────────────────────────────────
Detection requires a VERIFIED content change, not merely an unusual
protection state — an unusual protection state alone is demoted to a
lead:

  1. Parse each loaded module's OWN PE header out of process memory (the
     header describes how the module was laid out ON DISK — section
     names, sizes, and Characteristics flags — and survives a stomp that
     only overwrites a section's code).
  2. For every section the header marks EXECUTABLE but NOT WRITABLE,
     compare its LIVE memory protection against
     core.pe_utils.NORMAL_IMAGE_PROTECTIONS. A deviation (most notably
     PAGE_EXECUTE_READWRITE) is reported as a LEAD ONLY —
     PAGE_EXECUTE_WRITECOPY is normal, unmodified-loader copy-on-write
     behavior for an untouched section, and an attacker can VirtualProtect
     a section back to RX after stomping it and before a dump is
     captured — so protection state alone proves nothing about content
     either way.
  3. The ONLY path to a nonzero score is a VERIFIED on-disk-vs-memory byte
     diff against an analyst-supplied reference file (--ref-dir):
       - the reference file's own identity (Machine / SizeOfImage /
         TimeDateStamp, all read from ITS OWN PE header) must match the
         in-memory module's header, or the comparison is skipped and
         reported as a coverage gap.
       - the reference file's bytes are RELOCATION-NORMALIZED before
         comparison (core.pe_utils.apply_base_relocations): if the module
         loaded at a different address than its preferred ImageBase
         (ASLR, or a base collision), every absolute address the .reloc
         table lists gets the same delta applied to the on-disk copy that
         the Windows loader applied to the in-memory copy — otherwise an
         UNMODIFIED, merely-relocated section would show byte differences
         that have nothing to do with tampering.
       - the diff reports the actual differing (offset, length) byte
         ranges (ALL of them are scanned for a RIP/EIP hit — only the
         first few are kept for display), not just a whole-section
         match/mismatch hash.
       - score 1: verified, relocation-normalized byte differences exist
         against an identity-matched reference.
         score 2: a thread's CURRENT RIP/EIP lands inside one of the
         actually-differing byte ranges.

  Without --ref-dir, an empty/non-matching --ref-dir, an identity
  mismatch, or any read failure along the way, the verified-content
  check could not run to completion for at least one eligible section —
  coverage_status is "partial" and, with score==0, status is
  INCONCLUSIVE, never a bare "clean" NOT_DETECTED_IN_SCANNED_SCOPE. This
  hunter has exactly one scored signal; if it never ran, a negative
  result is not the same claim as "checked and clean".

Known, explicitly documented limitation: IAT/delay-import ranges and
hotpatch trampolines are NOT specifically excluded before diffing.
Restricting the diff to EXECUTABLE, non-writable sections already
excludes the import tables themselves for typical PE layouts (linkers
place them in non-executable data sections), but a legitimate hotpatch
NOP-padding/trampoline at a function prologue can still produce a
genuine, non-malicious byte difference inside .text — see the
`stomping.verified_content_change` Finding's `limitations`.

The string-based IOC scan is retained as an unscored, low-confidence
lead — see hunt/_finding.py for why raw string matches never drive a
verdict on their own in phase two.
"""
import os
import ntpath
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_contexts, addr_to_module, prot_str,
    read_region, _extract_ioc_strings)
from dumpex.core.pe_utils import (parse_pe_header, expected_protection_name,
    section_protection_deviates, apply_base_relocations)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level)

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
# No "3": this hunter's max score is 2 (verified change, optionally
# corroborated by live RIP/EIP — there's no third independent signal).
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}

PE_VALIDATE_READ_MAX = 4096   # bytes read from each module base to parse its
                               # own header + section table (see injection.py)

REF_FILE_MAX_READ = 64 * 1024 * 1024   # cap on a --ref-dir reference file read;
                                        # legitimate DLLs/EXEs are far smaller,
                                        # this just bounds a pathological input

MAX_DIFF_RANGES = 20        # cap on how many differing byte ranges are KEPT
                             # for display/facts — a section with more than
                             # this many separate diffs is already
                             # unambiguously different, no need to enumerate
                             # every last one for a human to read.
MAX_DIFF_RANGES_SCAN = 200_000   # separate, much larger safety ceiling on how
                                  # many ranges are computed AT ALL (purely to
                                  # bound worst-case memory/CPU on a section
                                  # that is byte-for-byte unrelated to its
                                  # reference) — RIP-hit checking scans every
                                  # range up to THIS limit, not just the 20
                                  # kept for display, so a hit in e.g. the
                                  # 21st range is never silently missed.


def _module_basename(module) -> str:
    """
    Module paths recorded in a minidump are from the ORIGINAL Windows
    system (e.g. 'C:\\Windows\\System32\\foo.dll'). os.path.basename only
    splits on '/' when running on a POSIX analysis host, so it returns the
    whole backslash-separated string unchanged there — ntpath.basename
    always applies Windows path rules regardless of the host OS this
    tool itself runs on.
    """
    return ntpath.basename(module.name or "") if module.name else ""


def _regions_covering(start: int, end: int, regions: list) -> list:
    """MemoryInfo regions whose [BaseAddress, BaseAddress+RegionSize) overlaps [start, end)."""
    out = []
    for r in regions:
        rs, re_ = r.BaseAddress, r.BaseAddress + r.RegionSize
        if rs < end and re_ > start:
            out.append(r)
    return out


def _find_reference_file(module, ref_dir: str):
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


def _reference_identity_matches(mem_pe: dict, disk_pe: dict) -> "tuple[bool, str]":
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


def _diff_byte_ranges(a: bytes, b: bytes, max_ranges: int = MAX_DIFF_RANGES_SCAN) -> list:
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

    identity_ok, identity_reason = _reference_identity_matches(mem_pe, disk_pe)
    if not identity_ok:
        return {"identity_ok": False, "identity_reason": identity_reason,
                "diff_ranges": [], "ranges_truncated": False, "compared_len": 0,
                "disk_sha256": "", "mem_sha256": ""}

    # Relocation-normalize: the reference file's bytes reflect its
    # PREFERRED ImageBase; the in-memory module is loaded at module_base,
    # which can differ (ASLR). Applying that delta to the on-disk copy
    # before comparing means an unmodified-but-relocated section reads as
    # identical, not "changed".
    delta = module_base - disk_pe['image_base']
    disk_data = apply_base_relocations(disk_data, disk_pe, delta)

    start  = section["pointer_to_raw_data"]
    length = min(section["size_of_raw_data"], len(mem_bytes))
    if length <= 0 or start + length > len(disk_data):
        return {"identity_ok": True, "identity_reason": "", "diff_ranges": [],
                "ranges_truncated": False, "compared_len": 0, "disk_sha256": "", "mem_sha256": ""}

    disk_slice = disk_data[start:start + length]
    mem_slice  = mem_bytes[:length]
    all_ranges = _diff_byte_ranges(disk_slice, mem_slice)
    return {
        "identity_ok": True, "identity_reason": "",
        "diff_ranges":      all_ranges,
        "ranges_truncated": len(all_ranges) >= MAX_DIFF_RANGES_SCAN,
        "compared_len":     length,
        "disk_sha256":      hashlib.sha256(disk_slice).hexdigest(),
        "mem_sha256":       hashlib.sha256(mem_slice).hexdigest(),
    }


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False, ref_dir: str = None) -> dict:
    """
    Detect Module Stomping via a verified, relocation-normalized on-disk-
    vs-memory content diff (primary, scored — requires --ref-dir), a
    demoted protection-deviation lead, and a demoted string-IOC lead. See
    module docstring.
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    module_list_available = bool(mf.modules and mf.modules.modules)

    findings = {"protection_leads": [], "verified_changes": [], "score": 0, "max_score": 2}
    _r               = get_rules()
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]

    _print_hunt_header("Module Stomping")

    findings_list = []

    # ── Explicit coverage counters for the verified-content check ────────
    # Every one of these is a reason the ONE scored signal in this hunter
    # could not run to completion for at least one eligible section — see
    # content_complete below. Bare pass/fail booleans can't distinguish
    # "checked everything, all clean" from "silently skipped N sections",
    # which is exactly the gap this dict closes.
    coverage_counts = {
        "modules_total":          len(modules),
        "headers_parsed":         0,
        "sections_total":         0,   # eligible (exec, non-writable) sections found
        "sections_compared":      0,   # sections that got a real, identity-matched byte comparison
        "reference_missing":      0,   # --ref-dir given, no matching file found for the module
        "reference_mismatch":     0,   # matching-name file found, but its own header identity differs
        "reference_read_failed":  0,   # matching-name file found, but couldn't be read/parsed
        "memory_read_failed":     0,   # couldn't read the section's live memory bytes
        "short_reads":            0,   # read succeeded but nothing usable could be compared
    }

    protection_leads = []   # dicts: module, section, region, expected, actual
    verified_changes = []   # dicts: module, section, diff_ranges (display-capped),
                             #        ranges_truncated, compared_len, rip_in_changed_range,
                             #        disk_sha256, mem_sha256
    identity_skipped  = []  # (module, section, reason) — ref file found but version/identity mismatched
    parse_failed      = []  # (module, pe) — module's own header didn't structurally validate
    read_failed       = 0   # module HEADER reads that raised (distinct from section memory reads)

    if mem_info_available and module_list_available:
        for m in modules:
            try:
                header_bytes = read_region(mf, m.baseaddress, min(PE_VALIDATE_READ_MAX, m.size or PE_VALIDATE_READ_MAX))
            except Exception:
                read_failed += 1
                continue
            pe = parse_pe_header(header_bytes)
            if not pe["valid"]:
                # A loaded, known module whose own header fails structural
                # validation is itself unusual (the loader required a valid
                # header to map it) — a genuine coverage gap: this module
                # could not be checked for stomping at all.
                parse_failed.append((m, pe))
                continue
            coverage_counts["headers_parsed"] += 1

            ref_path = _find_reference_file(m, ref_dir) if ref_dir else None

            for section in pe["sections"]:
                if not section["is_executable"] or section["is_writable"]:
                    continue   # only declared-exec, declared-non-writable sections are meaningful here
                va_start = m.baseaddress + section["virtual_address"]
                va_end   = va_start + max(section["virtual_size"], section["size_of_raw_data"], 1)
                covering = _regions_covering(va_start, va_end, regions)
                coverage_counts["sections_total"] += 1

                # Protection-deviation LEAD — informational, never scored
                # (see module docstring for why WRITECOPY is excluded and
                # why deviation alone still isn't proof either way).
                for region in covering:
                    if prot_str(region.State) != "MEM_COMMIT":
                        continue
                    actual = prot_str(region.Protect)
                    if section_protection_deviates(actual, section):
                        protection_leads.append({
                            "module": m, "section": section, "region": region,
                            "expected": expected_protection_name(section["is_readable"],
                                                                   section["is_writable"], section["is_executable"]),
                            "actual": actual,
                        })

                # Verified content diff — the ONLY path to a nonzero score.
                if not ref_dir:
                    continue   # accounted for globally below (content_complete requires ref_dir)
                if ref_path is None:
                    coverage_counts["reference_missing"] += 1
                    continue
                try:
                    mem_bytes = read_region(mf, va_start,
                        min(section["size_of_raw_data"] or section["virtual_size"], va_end - va_start))
                except Exception:
                    coverage_counts["memory_read_failed"] += 1
                    continue
                if not mem_bytes:
                    coverage_counts["memory_read_failed"] += 1
                    continue
                diff = _diff_section_on_disk(ref_path, pe, m.baseaddress, section, mem_bytes)
                if diff is None:
                    coverage_counts["reference_read_failed"] += 1
                    continue
                if not diff["identity_ok"]:
                    coverage_counts["reference_mismatch"] += 1
                    identity_skipped.append((m, section, diff["identity_reason"]))
                    continue
                if diff["compared_len"] == 0:
                    coverage_counts["short_reads"] += 1
                    continue

                coverage_counts["sections_compared"] += 1
                all_ranges = diff["diff_ranges"]
                if all_ranges:
                    rip_in_changed = False
                    for off, length in all_ranges:   # scan EVERY range, not just the displayed subset
                        change_va = va_start + off
                        if any(change_va <= tc["ip"] < change_va + length for tc in thread_contexts):
                            rip_in_changed = True
                            break
                    verified_changes.append({
                        "module": m, "section": section, "va_start": va_start,
                        "diff_ranges": all_ranges[:MAX_DIFF_RANGES],
                        "ranges_truncated": diff["ranges_truncated"] or len(all_ranges) > MAX_DIFF_RANGES,
                        "total_ranges": len(all_ranges),
                        "compared_len": diff["compared_len"],
                        "rip_in_changed_range": rip_in_changed,
                        "disk_sha256": diff["disk_sha256"], "mem_sha256": diff["mem_sha256"],
                    })

    findings["protection_leads"] = protection_leads
    findings["verified_changes"] = verified_changes

    # ── Finding: protection-deviation lead (never scored) ────────────────
    if protection_leads:
        facts = []
        for hit in protection_leads[:20]:
            m, sec, r = hit["module"], hit["section"], hit["region"]
            name = _module_basename(m) or "(unnamed module)"
            facts.append(f"module={name} section={sec['name']!r} VA=0x{r.BaseAddress:x} "
                         f"declared={hit['expected']} actual={hit['actual']} page_type={prot_str(r.Type)}")
        if len(protection_leads) > 20:
            facts.append(f"... and {len(protection_leads)-20} more")
        findings_list.append(Finding(
            check="stomping.protection_deviation_lead",
            facts=facts,
            inference=f"{len(protection_leads)} module section(s) declared executable-but-"
                       f"not-writable show LIVE protection other than the normal, "
                       f"unmodified-mapping set (PAGE_EXECUTE_WRITECOPY excluded — that is "
                       f"routine loader behavior).",
            confidence=CONFIDENCE_MEDIUM,
            rationale="An unusual protection state is a structural fact, but proves nothing "
                       "about content by itself: an attacker can VirtualProtect a section "
                       "back to RX after stomping it and before a dump is captured, and a "
                       "debugger/EDR hook can transiently reprotect memory for entirely "
                       "benign reasons. This is reported as a LEAD and does NOT contribute "
                       "to the stomping score — only a verified content diff "
                       "(stomping.verified_content_change, requires --ref-dir) does.",
            limitations=["Protection state alone cannot confirm or rule out that section "
                         "content actually changed."],
            tag=TAG_LEAD,
        ))
    else:
        findings_list.append(Finding(
            check="stomping.protection_deviation_lead",
            facts=[f"{coverage_counts['headers_parsed']} module(s) checked"],
            inference="No module section declared executable-but-not-writable shows a "
                       "live protection state outside the normal set.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a protection anomaly is weak evidence of absence — "
                       "stomping via careful VirtualProtect bookkeeping (reprotect to RX "
                       "before the dump) would not show up here at all.",
            limitations=[],
            tag=TAG_OBSERVATION,
        ))

    # ── Finding: verified content change (the only scored signal) ────────
    if verified_changes:
        facts = []
        for vc in verified_changes[:15]:
            m, sec = vc["module"], vc["section"]
            name = _module_basename(m) or "(unnamed module)"
            ranges_str = ", ".join(f"+0x{off:x}(len 0x{length:x})" for off, length in vc["diff_ranges"][:5])
            if len(vc["diff_ranges"]) > 5:
                ranges_str += f", ... +{len(vc['diff_ranges'])-5} more shown"
            if vc["ranges_truncated"]:
                ranges_str += f" ({vc['total_ranges']} total differing range(s), truncated for display)"
            live = "  [LIVE RIP/EIP inside changed range]" if vc["rip_in_changed_range"] else ""
            facts.append(f"module={name} section={sec['name']!r} VA=0x{vc['va_start']:x} "
                         f"compared={vc['compared_len']} bytes changed_ranges=[{ranges_str}] "
                         f"disk_sha256={vc['disk_sha256'][:16]}… mem_sha256={vc['mem_sha256'][:16]}…{live}")
        if len(verified_changes) > 15:
            facts.append(f"... and {len(verified_changes)-15} more")
        any_rip = any(vc["rip_in_changed_range"] for vc in verified_changes)
        findings_list.append(Finding(
            check="stomping.verified_content_change",
            facts=facts,
            inference=f"{len(verified_changes)} module section(s) have relocation-normalized, "
                       f"byte-level content differences from an identity-matched "
                       f"(Machine/SizeOfImage/TimeDateStamp) reference file supplied via "
                       f"--ref-dir.",
            confidence=CONFIDENCE_HIGH if any_rip else CONFIDENCE_MEDIUM,
            rationale=("A thread's current RIP/EIP executes inside one of the actually-"
                       "changed byte ranges — the strongest evidence this hunter can "
                       "produce." if any_rip else
                       "Verified byte-level difference against an identity-matched, "
                       "relocation-normalized reference, but no observed thread is currently "
                       "executing inside the changed range(s)."),
            limitations=["IAT/delay-import ranges and hotpatch trampolines are NOT "
                         "specifically excluded before diffing — restricting the diff to "
                         "executable, non-writable sections already excludes the import "
                         "tables themselves for typical PE layouts, but a legitimate hotpatch "
                         "NOP-padding/trampoline at a function prologue can still produce a "
                         "genuine, non-malicious difference inside .text.",
                         "PDB GUID/Age (CodeView debug directory) is not checked as part of "
                         "reference-identity matching — Machine/SizeOfImage/TimeDateStamp "
                         "matching all three is a strong but not perfect guarantee the "
                         "reference is the exact same build.",
                         "Relocation normalization applies IMAGE_REL_BASED_HIGHLOW/DIR64 "
                         "fixups only — the types real x86/x64 linkers emit; an exotic or "
                         "corrupt relocation table would leave some fixups un-normalized."],
            tag=TAG_DETECTION,
        ))

    if identity_skipped:
        facts = [f"module={_module_basename(m) or '(unnamed)'} section={sec['name']!r} reason={reason}"
                 for m, sec, reason in identity_skipped[:15]]
        if len(identity_skipped) > 15:
            facts.append(f"... and {len(identity_skipped)-15} more")
        findings_list.append(Finding(
            check="stomping.reference_identity_mismatch",
            facts=facts,
            inference=f"{len(identity_skipped)} section(s) had a matching-basename reference "
                       f"file under --ref-dir, but its own header identity did not match the "
                       f"in-memory module — comparison was skipped rather than risk a false "
                       f"positive from diffing against a different build.",
            confidence=CONFIDENCE_LOW,
            rationale="A same-named file that is actually a different build/version/patch "
                       "level would show ordinary compiler-output differences that are not "
                       "stomping — skipping is the safe choice, but it also means this "
                       "section could not be verified at all.",
            limitations=["Coverage gap: supply a reference file matching the exact build "
                         "(Machine/SizeOfImage/TimeDateStamp) to verify these sections."],
            tag=TAG_OBSERVATION,
        ))

    if parse_failed:
        facts = [f"module={_module_basename(m) or '(unnamed)'} base=0x{m.baseaddress:x} reason={pe['reason']}"
                 for m, pe in parse_failed[:15]]
        if len(parse_failed) > 15:
            facts.append(f"... and {len(parse_failed)-15} more")
        findings_list.append(Finding(
            check="stomping.module_header_invalid",
            facts=facts,
            inference=f"{len(parse_failed)} known module(s) failed PE header structural "
                       f"validation at their own recorded base address.",
            confidence=CONFIDENCE_LOW,
            rationale="A loaded module's own header failing to parse is itself unusual "
                       "(the loader required a valid header to map it) — could be a "
                       "partially-paged-out header at dump time, or could itself be "
                       "evidence of tampering. Either way, these modules could NOT be "
                       "checked for stomping at all — this is a coverage gap, not a "
                       "negative result.",
            limitations=["These modules are excluded from both the protection-deviation "
                         "lead and the verified-content-change check."],
            tag=TAG_OBSERVATION,
        ))

    # ── Score ──────────────────────────────────────────────────────────
    score = 0
    if verified_changes:
        score = 2 if any(vc["rip_in_changed_range"] for vc in verified_changes) else 1
    findings["score"] = score

    # ── Check 2 (demoted lead, NOT scored): string IOC scan ─────────────
    print(f"  {DIM('[*] Scanning executable MEM_IMAGE regions for IOC strings (lead only)...')}\n")
    ioc_hits    = []
    skipped_wl  = []
    weak_only_skipped = []

    _WEAK_IOC_TERMS = {"virtualalloc", "writeprocessmemory",
                       "createremotethread", "wsasocket", "base64"}

    def _classify_ioc_hits(strings, patterns) -> list:
        hits = []
        for off, enc, s in strings:
            for pat in patterns:
                for m in pat.finditer(s):
                    token = m.group(0)
                    hits.append((off + m.start(), enc, token,
                                 token.casefold() in _WEAK_IOC_TERMS))
        return hits

    for r in regions:
        mtype = prot_str(r.Type)
        p     = prot_str(r.Protect)
        state = prot_str(r.State)
        if "MEM_IMAGE" not in mtype or state != "MEM_COMMIT":
            continue
        if "EXECUTE" not in p:
            continue
        if r.RegionSize > 0x500000:
            continue

        mod      = addr_to_module(r.BaseAddress, modules)
        mod_name = (_module_basename(mod).lower() if mod else "")
        is_wl    = mod_name in STOMPING_WHITELIST

        try:
            data    = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            continue

        strings = _extract_ioc_strings(data, r.BaseAddress)
        patterns = ([STOMPING_IOC] if is_wl else [STOMPING_IOC, STOMPING_NET_IOC])
        hits = _classify_ioc_hits(strings, patterns)

        if not hits:
            if is_wl:
                skipped_wl.append(mod_name)
            continue
        strong_hits = [h for h in hits if not h[3]]
        if not strong_hits:
            weak_only_skipped.append((r, mod, hits))
            continue
        ioc_hits.append((r, mod, hits, not is_wl))

    if skipped_wl:
        unique_wl = sorted(set(skipped_wl))
        print(f"  {DIM(f'[·] Whitelisted network DLLs skipped (network strings expected): {chr(44).join(unique_wl)}')}")
        print()

    if ioc_hits:
        n_strong = sum(sum(1 for h in hits if not h[3]) for _, _, hits, _ in ioc_hits)
        n_weak   = sum(sum(1 for h in hits if h[3]) for _, _, hits, _ in ioc_hits)
        facts = []
        for r, mod, hits, _ in ioc_hits[:15]:
            name = _module_basename(mod) if mod else "(unknown)"
            terms = sorted({tok for _, _, tok, _ in hits})[:8]
            facts.append(f"module={name} VA=0x{r.BaseAddress:x} terms={', '.join(terms)}")
        if len(ioc_hits) > 15:
            facts.append(f"... and {len(ioc_hits)-15} more")
        findings_list.append(Finding(
            check="stomping.ioc_string_lead",
            facts=facts,
            inference=f"{n_strong} strong + {n_weak} weak IOC-keyword token(s) found across "
                       f"{len(ioc_hits)} executable module region(s).",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that the bytes exist somewhere in the "
                       "region — it is trivial to plant, coincidentally match tool/API "
                       "names, or survive from unrelated benign code. This is reported as "
                       "an investigative lead only and does NOT contribute to the stomping "
                       "score; see stomping.verified_content_change for the only signal "
                       "that scores.",
            limitations=["Not corroborated by any structural (section/protection) evidence "
                         "on its own."],
            tag=TAG_LEAD,
        ))
        detail = f"{n_strong} strong + {n_weak} weak IOC token(s) across {len(ioc_hits)} module region(s) — LEAD ONLY, not scored"
        if verbose:
            for r, mod, hits, _ in ioc_hits:
                name = _module_basename(mod) if mod else "(unknown)"
                detail += f"\n          {name}  0x{r.BaseAddress:x}"
                for off, enc, tok, is_weak in hits[:10]:
                    tag = DIM(" (weak/common API)") if is_weak else ""
                    detail += f"\n            0x{r.BaseAddress+off:x}  [{enc}]  {tok}{tag}"
        _print_check("IOC strings in module code regions (lead)",
                     YELLOW("LEAD — not scored, see structural checks above"), detail)
    else:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    # ── Print detection/lead findings ─────────────────────────────────────
    for f in findings_list:
        f.print()

    # ── Coverage — independent of score/status, so "DETECTED but coverage
    # was partial" is representable rather than DETECTED silently implying
    # a complete scan. content_complete is specifically about the ONE
    # scored signal (verified content diff): it requires --ref-dir AND
    # every eligible section actually being compared, with zero failures
    # of any kind along the way. ─────────────────────────────────────────
    content_complete = (
        ref_dir is not None
        and coverage_counts["sections_compared"] == coverage_counts["sections_total"]
        and not any([
            coverage_counts["reference_missing"],
            coverage_counts["reference_mismatch"],
            coverage_counts["reference_read_failed"],
            coverage_counts["memory_read_failed"],
            coverage_counts["short_reads"],
        ])
    )

    coverage_reasons = []
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if not module_list_available:
        coverage_reasons.append("ModuleListStream missing from this dump")
    if read_failed:
        coverage_reasons.append(f"{read_failed} module header read(s) failed")
    if parse_failed:
        coverage_reasons.append(f"{len(parse_failed)} module header(s) failed PE structural validation")
    if ref_dir is None:
        coverage_reasons.append("--ref-dir not supplied — verified content comparison "
                                 "(the only scored signal) was not performed for any module")
    else:
        if coverage_counts["reference_missing"]:
            coverage_reasons.append(f"{coverage_counts['reference_missing']} section(s) had no "
                                     f"matching reference file under --ref-dir")
        if coverage_counts["reference_mismatch"]:
            coverage_reasons.append(f"{coverage_counts['reference_mismatch']} section(s) had a "
                                     f"reference file whose build identity didn't match")
        if coverage_counts["reference_read_failed"]:
            coverage_reasons.append(f"{coverage_counts['reference_read_failed']} reference "
                                     f"file(s) could not be read")
        if coverage_counts["memory_read_failed"]:
            coverage_reasons.append(f"{coverage_counts['memory_read_failed']} section(s) could "
                                     f"not be read from memory")
        if coverage_counts["short_reads"]:
            coverage_reasons.append(f"{coverage_counts['short_reads']} section(s) had nothing "
                                     f"comparable to read")

    if not (mem_info_available and module_list_available):
        coverage_status = "not_evaluated"
    elif read_failed or parse_failed or not content_complete:
        coverage_status = "partial"
    else:
        coverage_status = "complete"
    findings["coverage_status"]  = coverage_status
    findings["coverage_reasons"] = coverage_reasons
    findings["coverage_counts"]  = coverage_counts

    if coverage_status == "not_evaluated":
        status = NOT_EVALUATED
    elif score > 0:
        status = DETECTED
    elif coverage_status == "partial":
        status = INCONCLUSIVE
    else:
        status = NOT_DETECTED_IN_SCANNED_SCOPE
    findings["status"] = status
    findings["confidence"] = overall_confidence(findings_list, score)
    findings["verdict_level"] = verdict_level(score, _VERDICT_LEVEL_BY_SCORE)
    findings["findings"] = [f.to_dict() for f in findings_list]

    if status == NOT_EVALUATED:
        verdict = _status_text(NOT_EVALUATED, "; ".join(coverage_reasons) or "required streams missing")
    elif status == DETECTED:
        verdict = (RED("HIGH CONFIDENCE STOMPING — verified content change, RIP/EIP inside "
                       "the changed range") if score == 2 else
                   YELLOW("LIKELY STOMPING — verified content change against reference file"))
    elif status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE, "; ".join(coverage_reasons) or "partial coverage")
    else:
        verdict = GREEN("CLEAN — no verified stomping indicators")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2, requires --ref-dir; "
          f"protection-deviation and string-IOC leads above are informational and not counted)\n")

    if status == DETECTED and coverage_status == "partial":
        print(YELLOW(f"  [~] Coverage incomplete despite a detection: {'; '.join(coverage_reasons)} "
                      f"— additional stomped modules may exist beyond what could be checked.\n"))

    if not verbose and verified_changes:
        print(DIM("  Use --verbose to list every verified change in detail.\n"))
    if not ref_dir:
        print(DIM("  [·] --ref-dir not supplied — verified content-diff (the only scored "
                  "signal) was not attempted; reported as INCONCLUSIVE/partial coverage, "
                  "not a clean result.\n"))

    return findings
