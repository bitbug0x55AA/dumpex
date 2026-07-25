"""Module stomping hunter.

Phase-two detection model
──────────────────────────
The primary, scored signal is now a **disk-declared vs. live-memory
section diff**, not string matching:

  1. Parse each loaded module's OWN PE header out of process memory (the
     header describes how the module was laid out ON DISK — section
     names, sizes, and Characteristics flags — and survives a stomp that
     only overwrites a section's code, since stomping tooling has no
     reason to touch the header).
  2. For every section the header marks EXECUTABLE but NOT WRITABLE
     (dumpex.core.pe_utils.section_protection_exceeds_declared), find the
     MemoryInfo region(s) actually covering that section's VA range and
     compare their LIVE protection against what the header declares.
     A declared read+execute-only section that is live writable has been
     reprotected after mapping — the structural signature of stomping
     (write the payload, the loader/injector had to make it writable
     first) — independent of any string content.
  3. If a thread's CURRENT RIP/EIP (core.memory.get_thread_contexts) sits
     inside a mismatched section, that is corroborating live-execution
     evidence, same principle as hunt/injection.py.
  4. Optionally, when --ref-dir points at a directory containing a
     reference copy of the module (analyst-supplied — this tool has no
     access to the original system's disk), a genuine on-disk-vs-memory
     byte diff is computed per section via sha256, as a second,
     independent corroborating signal.

The original string-based IOC scan (Cobalt Strike / mimikatz / etc.
keywords found inside executable module memory) is retained because it is
still a useful lead for an analyst, but it is explicitly demoted: it
never contributes to `score` on its own and is reported at LOW confidence
as an observation/lead, per phase-two policy (strings are cheap to plant
or coincidentally match and must not drive a verdict by themselves).
"""
import os
import hashlib
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    get_thread_contexts, addr_to_module, prot_str,
    read_region, _extract_ioc_strings)
from dumpex.core.pe_utils import (parse_pe_header, expected_protection_name,
    section_protection_exceeds_declared)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION)

PE_VALIDATE_READ_MAX = 4096   # bytes read from each module base to parse its
                               # own header + section table (see injection.py)

REF_FILE_MAX_READ = 64 * 1024 * 1024   # cap on a --ref-dir reference file read;
                                        # legitimate DLLs/EXEs are far smaller,
                                        # this just bounds a pathological input


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
    base = os.path.basename(module.name or "")
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


def _diff_section_on_disk(ref_path: str, section: dict, mem_bytes: bytes) -> "dict|None":
    """
    Compare a section's on-disk raw bytes (from the analyst-supplied
    reference file) against the corresponding live memory bytes via
    sha256. Returns {"match": bool, "disk_sha256":, "mem_sha256":,
    "compared_len":} or None if the section's on-disk range couldn't be
    read at all (truncated/missing reference file).
    """
    try:
        size = os.path.getsize(ref_path)
        if size > REF_FILE_MAX_READ:
            return None
        with open(ref_path, "rb") as fh:
            disk_data = fh.read()
    except OSError:
        return None

    start = section["pointer_to_raw_data"]
    length = min(section["size_of_raw_data"], len(mem_bytes))
    if length <= 0 or start + length > len(disk_data):
        return None
    disk_slice = disk_data[start:start + length]
    mem_slice  = mem_bytes[:length]
    return {
        "match":        disk_slice == mem_slice,
        "disk_sha256":  hashlib.sha256(disk_slice).hexdigest(),
        "mem_sha256":   hashlib.sha256(mem_slice).hexdigest(),
        "compared_len": length,
    }


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False, ref_dir: str = None) -> dict:
    """
    Detect Module Stomping via disk-declared-vs-live-memory section
    comparison (primary, scored) plus an optional on-disk byte diff and a
    demoted string-IOC lead (both informational). See module docstring.
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    module_list_available = bool(mf.modules and mf.modules.modules)

    findings = {"section_mismatches": [], "ioc_image": [], "score": 0}
    _r               = get_rules()
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]
    SUSPICIOUS_PROTS    = _r["suspicious_protections"]

    _print_hunt_header("Module Stomping")

    findings_list = []

    # ── Check 1 (primary, scored): per-section disk-declared vs live-memory ──
    mismatches       = []   # dicts: module, section, region, expected, actual, rip_hit, disk_diff
    parse_failed     = []   # modules whose own header didn't structurally validate
    read_failed      = 0
    modules_scanned  = 0

    if mem_info_available and module_list_available:
        for m in modules:
            try:
                header_bytes = read_region(mf, m.baseaddress, min(PE_VALIDATE_READ_MAX, m.size or PE_VALIDATE_READ_MAX))
            except Exception:
                read_failed += 1
                continue
            modules_scanned += 1
            pe = parse_pe_header(header_bytes)
            if not pe["valid"]:
                # A loaded, known module whose own header fails structural
                # validation is itself unusual (the loader required a valid
                # header to map it) — worth a low-confidence note, but not
                # scored: could just be a header partially paged out at
                # dump time.
                parse_failed.append((m, pe))
                continue

            for section in pe["sections"]:
                if not section["is_executable"] or section["is_writable"]:
                    continue   # only declared-exec, declared-non-writable sections are meaningful here
                va_start = m.baseaddress + section["virtual_address"]
                va_end   = va_start + max(section["virtual_size"], section["size_of_raw_data"], 1)
                covering = _regions_covering(va_start, va_end, regions)
                for region in covering:
                    if prot_str(region.State) != "MEM_COMMIT":
                        continue
                    actual = prot_str(region.Protect)
                    if not section_protection_exceeds_declared(actual, section):
                        continue

                    rip_hit = next((tc for tc in thread_contexts
                                     if va_start <= tc["ip"] < va_end), None)

                    disk_diff = None
                    if ref_dir:
                        ref_path = _find_reference_file(m, ref_dir)
                        if ref_path:
                            try:
                                mem_bytes = read_region(mf, va_start,
                                    min(section["size_of_raw_data"] or section["virtual_size"], region.RegionSize))
                            except Exception:
                                mem_bytes = b""
                            if mem_bytes:
                                disk_diff = _diff_section_on_disk(ref_path, section, mem_bytes)

                    mismatches.append({
                        "module": m, "section": section, "region": region,
                        "expected": expected_protection_name(section["is_readable"],
                                                               section["is_writable"], section["is_executable"]),
                        "actual": actual, "rip_hit": rip_hit, "disk_diff": disk_diff,
                    })

    if mismatches:
        facts = []
        for hit in mismatches[:20]:
            m, sec, r = hit["module"], hit["section"], hit["region"]
            name = os.path.basename(m.name) if m.name else "(unnamed module)"
            f = (f"module={name} section={sec['name']!r} VA=0x{r.BaseAddress:x} "
                 f"declared={hit['expected']} actual={hit['actual']} page_type={prot_str(r.Type)}")
            if hit["rip_hit"]:
                f += f"  [LIVE: TID=0x{hit['rip_hit']['ThreadId']:x} {hit['rip_hit']['ip_reg']} inside section]"
            if hit["disk_diff"] is not None:
                f += f"  [on-disk diff: match={hit['disk_diff']['match']}]"
            facts.append(f)
        if len(mismatches) > 20:
            facts.append(f"... and {len(mismatches)-20} more")

        any_rip      = any(h["rip_hit"] for h in mismatches)
        any_disk_bad = any(h["disk_diff"] is not None and not h["disk_diff"]["match"] for h in mismatches)
        corroborated = any_rip or any_disk_bad
        conf = CONFIDENCE_HIGH if corroborated else CONFIDENCE_MEDIUM

        findings_list.append(Finding(
            check="stomping.section_protection_mismatch",
            facts=facts,
            inference=(f"{len(mismatches)} module section(s) that the module's OWN on-disk-"
                       f"declared PE header marks executable-but-not-writable are LIVE "
                       f"writable in memory — protection was changed after the loader "
                       f"mapped the module."),
            confidence=conf,
            rationale=("Corroborated: " + ", ".join(filter(None, [
                           "a thread's current RIP/EIP executes inside the mismatched section" if any_rip else "",
                           "on-disk reference bytes differ from live memory for the mismatched section" if any_disk_bad else "",
                       ])) if corroborated else
                       "Structural mismatch only — no live execution observed inside the "
                       "affected section and no on-disk reference was available (or it matched) "
                       "to confirm content actually changed. A loader/EDR hook or debugger "
                       "could in rare cases also alter section protection without stomping "
                       "content, so this alone is treated as MEDIUM, not HIGH."),
            limitations=(["No --ref-dir reference file supplied — on-disk byte-level "
                          "confirmation was not attempted."] if not ref_dir else []) +
                        (["Byte-level on-disk diff can reflect legitimate relocation/IAT "
                          "patching for some code layouts, not only stomping — treat as "
                          "corroboration, not standalone proof."] if any_disk_bad else []),
            tag=TAG_DETECTION if corroborated else TAG_LEAD,
        ))
        findings["section_mismatches"] = mismatches
        findings["score"] = 2 if corroborated else 1
    else:
        findings_list.append(Finding(
            check="stomping.section_protection_mismatch",
            facts=[f"{modules_scanned} module(s) checked, {read_failed} unreadable"],
            inference="No module section that is declared executable-but-not-writable in "
                       "its own on-disk PE header shows live writable protection.",
            confidence=CONFIDENCE_HIGH if (mem_info_available and module_list_available and read_failed == 0) else CONFIDENCE_LOW,
            rationale="Structural check ran to completion across all resolvable module "
                       "sections with no mismatch found." if read_failed == 0 else
                       f"{read_failed} module(s) could not be read — coverage is incomplete.",
            limitations=[] if read_failed == 0 else [f"{read_failed} module header read(s) failed."],
            tag=TAG_OBSERVATION,
        ))

    if parse_failed and verbose:
        print(DIM(f"  [·] {len(parse_failed)} known module(s) failed PE header structural "
                  f"validation at their own base address (possibly paged-out headers at "
                  f"dump time) — not scored, see stomping.module_header_invalid.\n"))
        for m, pe in parse_failed[:10]:
            name = os.path.basename(m.name) if m.name else "(unnamed)"
            print(DIM(f"      {name}  0x{m.baseaddress:x}  reason={pe['reason']}"))
        print()

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
        mod_name = os.path.basename(mod.name).lower() if mod else ""
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
            name = os.path.basename(mod.name) if mod else "(unknown)"
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
                       "score; see stomping.section_protection_mismatch for the structural, "
                       "scored signal.",
            limitations=["Not corroborated by any structural (section/protection) evidence "
                         "on its own."],
            tag=TAG_LEAD,
        ))
        detail = f"{n_strong} strong + {n_weak} weak IOC token(s) across {len(ioc_hits)} module region(s) — LEAD ONLY, not scored"
        if verbose:
            for r, mod, hits, _ in ioc_hits:
                name = os.path.basename(mod.name) if mod else "(unknown)"
                detail += f"\n          {name}  0x{r.BaseAddress:x}"
                for off, enc, tok, is_weak in hits[:10]:
                    tag = DIM(" (weak/common API)") if is_weak else ""
                    detail += f"\n            0x{r.BaseAddress+off:x}  [{enc}]  {tok}{tag}"
        _print_check("IOC strings in module code regions (lead)",
                     YELLOW("LEAD — not scored, see structural check above"), detail)
    else:
        _print_check("IOC strings in module code regions",
                     GREEN("CLEAN — no IOC patterns in executable module memory"))

    # ── Print primary structural finding(s) ──────────────────────────────
    for f in findings_list:
        f.print()

    # ── Verdict ───────────────────────────────────────────────────────────
    score = findings["score"]
    findings["status"] = None
    findings["findings"] = [f.to_dict() for f in findings_list]

    if not mem_info_available or not module_list_available:
        status = NOT_EVALUATED
    elif score == 0 and read_failed:
        status = INCONCLUSIVE
    else:
        status = DETECTED if score > 0 else NOT_DETECTED_IN_SCANNED_SCOPE
    findings["status"] = status

    if not mem_info_available or not module_list_available:
        missing = ", ".join(filter(None, [
            "MemoryInfoListStream" if not mem_info_available else "",
            "ModuleListStream" if not module_list_available else "",
        ]))
        verdict = _status_text(NOT_EVALUATED, f"{missing} missing from this dump")
    elif status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE, f"{read_failed} module(s) failed to read")
    elif score == 2:
        verdict = RED("HIGH CONFIDENCE STOMPING — section protection mismatch corroborated "
                       "by live execution and/or on-disk reference diff")
    elif score == 1:
        verdict = YELLOW("POSSIBLE STOMPING — section protection mismatch found, uncorroborated")
    else:
        verdict = GREEN("CLEAN — no stomping indicators")
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2, structural check only — "
          f"string IOC lead above is informational and not counted)\n")

    if not verbose and mismatches:
        print(DIM("  Use --verbose to list every mismatched section.\n"))
    if not ref_dir:
        print(DIM("  [·] --ref-dir not supplied — on-disk byte-level section diff was not "
                  "attempted (structural protection-mismatch check does not need it).\n"))

    return findings
