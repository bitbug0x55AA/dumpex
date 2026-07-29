"""Process hollowing / image-base mismatch hunter."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions,
    addr_to_module, va_to_file_offset, prot_str, read_region)
from dumpex.hunt._ui import (_print_hunt_header, _print_check, _status_text,
    DETECTED, NOT_DETECTED_IN_SCANNED_SCOPE, NOT_EVALUATED, INCONCLUSIVE)
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_LEAD, TAG_DETECTION, overall_confidence, verdict_level,
    lead_count, review_priority, leads_suffix)

# score -> verdict_level, owned by this hunter (see _finding.verdict_level).
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}


def _hunt_hollowing(mf: MinidumpFile, verbose: bool = False) -> dict:
    """
    Detect Process Hollowing by comparing PEB image path against the
    actual memory backing of the main module base address.

    Two STRUCTURAL ANCHORS, each meaningful alone but each with a
    plausible benign explanation in isolation:
      1. Main module memory type is MEM_PRIVATE instead of MEM_IMAGE —
         not mapped from a file backing at all.
      2. MZ header at image base is missing or zeroed — no valid PE
         header where one is expected.
    Two CORROBORATORS — weak on their own (RWX/JIT-style memory and
    name/case/redirection comparisons are routinely benign):
      3. Image base memory is RWX (needed to write replacement code).
      4. PEB ImagePath's name doesn't match the module list's own name
         for this base address (or the base isn't in the module list at
         all).

    DETECTED requires correlation, not a single flag: anchor 1
    (MEM_PRIVATE) firing together with EITHER anchor 2 (MZ wiped) or
    corroborator 3 (RWX) — mirrors dumpex/hunt/injection/'s own RWX+hidden-PE
    same-allocation correlation requirement. A single signal alone
    (including anchor 2 by itself, or either corroborator alone) is
    reported as a lead, not a detection — see
    dumpex.hunt._finding.review_priority for how it still surfaces for
    an analyst even at score==0.
    """
    peb     = mf.peb
    modules = get_modules(mf)
    # get_modules() returns [] both when ModuleList is entirely missing/empty
    # AND when it's present but genuinely has no entry for this address —
    # those are different coverage situations for check 4 below (the first
    # means the check never actually ran; the second is a real signal).
    modules_available = bool(mf.modules and mf.modules.modules)
    regions = get_memory_regions(mf)
    SUSPICIOUS_PROTS = get_rules()["suspicious_protections"]

    findings = {"score": 0, "max_score": 2}
    findings_list = []

    _print_hunt_header("Process Hollowing")

    if not peb:
        findings["status"] = NOT_EVALUATED
        findings["coverage_status"] = "not_evaluated"
        findings["coverage_reasons"] = ["PEB stream missing from this dump"]
        findings["confidence"] = overall_confidence([], 0)
        findings["verdict_level"] = verdict_level(0, _VERDICT_LEVEL_BY_SCORE, status=NOT_EVALUATED)
        findings["lead_count"] = 0
        findings["review_priority"] = review_priority([], 0, NOT_EVALUATED)
        findings["findings"] = []
        print(RED("  [!] PEB not available — cannot run hollowing check.\n"))
        print(f"  {BOLD('[ VERDICT ]')}  {_status_text(NOT_EVALUATED, 'PEB stream missing from this dump')}\n")
        return findings

    image_base = peb.image_base_address
    image_path = peb.image_path or "(unknown)"

    fo_base = va_to_file_offset(mf, image_base)
    fo_base_str = f"0x{fo_base:x}" if fo_base is not None else "(not captured)"
    print(f"  {DIM('PEB ImagePath     :')} {image_path}")
    print(f"  {DIM('ImageBase VA      :')} 0x{image_base:016x}  {DIM('(process virtual address)')}")
    print(f"  {DIM('ImageBase offset  :')} {fo_base_str}          {DIM('(byte offset in .dmp file)')}")
    print()

    base_region = None
    for r in regions:
        if r.BaseAddress <= image_base < r.BaseAddress + r.RegionSize:
            base_region = r
            break

    # ── Check 1 (anchor): memory type at image base ────────────────────
    mem_private = False
    if not base_region:
        _print_check("Memory type at image base",
                     YELLOW("NOTABLE — region not found in dump"),
                     "Image base page may not have been captured")
    else:
        mtype = prot_str(base_region.Type)
        p     = prot_str(base_region.Protect)
        fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
        fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
        if "MEM_IMAGE" in mtype:
            _print_check("Memory type at image base",
                         GREEN("CLEAN — MEM_IMAGE (mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
        else:
            mem_private = True
            _print_check("Memory type at image base",
                         RED("SUSPICIOUS — MEM_PRIVATE (not mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
            findings_list.append(Finding(
                check="hollowing.mem_private_at_image_base",
                facts=[f"VA=0x{base_region.BaseAddress:x} type={mtype} protect={p}"],
                inference="The main module's image base is backed by MEM_PRIVATE memory, "
                           "not a file-mapped MEM_IMAGE region.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="A genuine PE image loaded normally is always MEM_IMAGE at its "
                           "base — MEM_PRIVATE there means nothing was actually mapped from "
                           "the executable file this process is supposed to be running. "
                           "Structural on its own, but a manually-mapped, otherwise benign "
                           "loader (some DRM/anti-cheat/packer stubs) can also produce this "
                           "without hollowing — correlated with a second anomaly below before "
                           "it counts toward the score.",
                limitations=["A manual-mapping loader that isn't hollowing can also produce "
                             "this signal alone."],
                tag=TAG_LEAD,
            ))

    # ── Check 2 (anchor): MZ header at image base ───────────────────────
    mz_wiped = False
    mz_read_failed = False
    try:
        header = read_region(mf, image_base, min(64, 0x1000))
        if len(header) < 2:
            # Fewer than 2 bytes back is a short/failed read, not evidence
            # the MZ header is actually missing -- there isn't even enough
            # data to check the 'MZ' magic. Treating this as mz_wiped would
            # let a truncated read alone (paired with MEM_PRIVATE) reach
            # DETECTED without the MZ check having genuinely run.
            mz_read_failed = True
            _print_check("MZ header at image base",
                         YELLOW("NOTABLE — short read, could not check"),
                         f"Only {len(header)} byte(s) returned")
        elif header[:2] == b'MZ':
            _print_check("MZ header at image base",
                         GREEN("CLEAN — MZ present"),
                         f"Header bytes: {header[:8].hex()}")
        elif header == b'\x00' * len(header):
            mz_wiped = True
            _print_check("MZ header at image base",
                         RED("SUSPICIOUS — MZ zeroed out (header wiping)"),
                         f"First bytes: {header[:8].hex()}")
        else:
            mz_wiped = True
            _print_check("MZ header at image base",
                         YELLOW("NOTABLE — unexpected bytes where MZ should be"),
                         f"First bytes: {header[:8].hex()}")
        if mz_wiped:
            findings_list.append(Finding(
                check="hollowing.mz_header_missing",
                facts=[f"VA=0x{image_base:x} header_bytes={header[:8].hex()}"],
                inference="No valid MZ/DOS header is present where the PEB's own image base "
                           "says the main module should start.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="A loaded PE image always has an MZ header at its base — its "
                           "absence (zeroed or overwritten) is a structural fact, but reads "
                           "that raced a legitimate unmap/remap, or a short/partial capture "
                           "of that exact page, can also produce this without hollowing — "
                           "correlated with a second anomaly below before it counts toward "
                           "the score.",
                limitations=["Cannot distinguish deliberate header wiping from a capture-time "
                             "race or partial read of this specific page."],
                tag=TAG_LEAD,
            ))
    except Exception as e:
        mz_read_failed = True
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — could not read"),
                     str(e))

    # ── Check 3 (corroborator): RWX at image base ───────────────────────
    is_rwx = False
    if base_region:
        p = prot_str(base_region.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            is_rwx = True
            _print_check("Protection at image base",
                         RED("SUSPICIOUS — RWX (write needed to hollow)"),
                         f"{p}")
            findings_list.append(Finding(
                check="hollowing.rwx_at_image_base",
                facts=[f"VA=0x{base_region.BaseAddress:x} protect={p}"],
                inference="The main module's image base carries RWX-family protection.",
                confidence=CONFIDENCE_LOW,
                rationale="RWX at the image base is needed to write replacement code during "
                           "hollowing, but RWX alone is routinely used by JITs, debuggers, "
                           "and some legitimate packers — a lead, not proof, on its own.",
                limitations=["Does not by itself distinguish hollowing from JIT/legitimate "
                             "self-modifying-code use cases at this address."],
                tag=TAG_LEAD,
            ))
        else:
            _print_check("Protection at image base",
                         GREEN(f"CLEAN — {p}"))

    # ── Check 4 (corroborator): module list sanity ──────────────────────
    name_mismatch = False
    module_list_unavailable = not modules_available
    main_mod = addr_to_module(image_base, modules)
    if main_mod:
        mod_name = _basename_lower(main_mod.name)
        peb_name = _basename_lower(image_path)
        if mod_name == peb_name:
            _print_check("PEB image name vs module list",
                         GREEN(f"CLEAN — both report '{mod_name}'"))
        else:
            name_mismatch = True
            _print_check("PEB image name vs module list",
                         RED("SUSPICIOUS — name mismatch"),
                         f"PEB says '{peb_name}', module list says '{mod_name}'")
    elif module_list_unavailable:
        # ModuleList itself is missing/empty -- this check could not
        # actually run at all (main_mod is guaranteed None either way), so
        # it must not be reported as "not in any module" (a genuine signal
        # implying the list WAS checked) nor silently left out of coverage.
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — ModuleList unavailable, cannot verify"),
                     "ModuleListStream missing/empty from this dump")
    else:
        name_mismatch = True
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — image base not in any module"),
                     "Main executable may have been unmapped")
    if name_mismatch:
        findings_list.append(Finding(
            check="hollowing.peb_module_name_mismatch",
            facts=[f"PEB_image_path={image_path!r} module_list_match={bool(main_mod)}"],
            inference="The PEB's own ImagePath name doesn't match the module list's name "
                       "for this base address, or the base isn't in the module list at all.",
            confidence=CONFIDENCE_LOW,
            rationale="A name mismatch or missing module-list entry can also come from "
                       "DLL redirection, WoW64 path differences, or a capture-time race — "
                       "a lead, not proof, on its own.",
            limitations=["Does not by itself distinguish hollowing from benign path/"
                         "redirection differences."],
            tag=TAG_LEAD,
        ))

    # ── Correlation: DETECTED requires anchor 1 (MEM_PRIVATE) together ──
    # with at least one of anchor 2 (MZ wiped) or corroborator 3 (RWX) —
    # a single anomaly, including either anchor alone, stays lead-only.
    score = 0
    if mem_private and (mz_wiped or is_rwx):
        both_anchors_and_rwx = mz_wiped and is_rwx
        score = 2 if both_anchors_and_rwx else 1
        corroborators = ["MEM_PRIVATE at image base"]
        if mz_wiped:
            corroborators.append("MZ header missing/wiped")
        if is_rwx:
            corroborators.append("RWX protection")
        findings_list.append(Finding(
            check="hollowing.structural_correlation",
            facts=[f"VA=0x{image_base:x} " + " + ".join(corroborators)],
            inference=f"{len(corroborators)} independent structural signal(s) correlate at "
                       f"the same image base: {', '.join(corroborators)}.",
            confidence=CONFIDENCE_HIGH if both_anchors_and_rwx else CONFIDENCE_MEDIUM,
            rationale="Any one of these signals alone has a plausible benign explanation "
                       "(manual mapping, a capture-time read race, a JIT/packer using RWX). "
                       "MEM_PRIVATE at the image base correlated with a missing/wiped MZ "
                       "header AND/OR RWX protection at that same address is materially "
                       "harder to explain away — the combination the module's own checks "
                       "were designed to catch.",
            limitations=["Structural correlation is strong evidence but not a substitute "
                         "for live-execution corroboration (no thread-context signal is "
                         "available for this hunter)."],
            tag=TAG_DETECTION,
        ))

    findings["score"] = score

    evaluated = True   # PEB was present — the check actually ran
    # `complete` must reflect every check that failed to actually run, not
    # just a missing region: the MZ-header anchor reads a fixed 64-byte
    # window at image_base independently of base_region, and an OSError/
    # short-read failure there was previously only printed, never folded
    # into coverage -- as long as base_region existed, the result claimed
    # coverage_status: complete even though anchor 2 never actually ran.
    complete = base_region is not None and not mz_read_failed and not module_list_unavailable
    coverage_reasons = []
    if base_region is None:
        coverage_reasons.append("Image base page not captured in this dump — memory-type and "
                                 "RWX checks could not run")
    if mz_read_failed:
        coverage_reasons.append("Image base MZ header could not be read — MZ-header check "
                                 "could not run")
    if module_list_unavailable:
        coverage_reasons.append("ModuleListStream missing/empty from this dump — module-list "
                                 "sanity check could not run")
    coverage_status = derive_coverage_status(evaluated, complete)
    status = derive_status(evaluated, score > 0, complete)

    findings["coverage_status"]  = coverage_status
    findings["coverage_reasons"] = coverage_reasons
    findings["status"]           = status
    findings["confidence"]       = overall_confidence(findings_list, score)
    findings["verdict_level"]    = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    findings["findings"]         = [f.to_dict() for f in findings_list]
    findings["lead_count"]       = lead_count(findings_list)
    findings["review_priority"]  = review_priority(findings_list, score, status)

    if not complete:
        print(YELLOW(f"  [~] {'; '.join(coverage_reasons)}.\n"))

    if status == INCONCLUSIVE:
        verdict = _status_text(INCONCLUSIVE,
                                ("; ".join(coverage_reasons) or "partial coverage")
                                + leads_suffix(findings_list))
    elif status == NOT_DETECTED_IN_SCANNED_SCOPE:
        verdict = GREEN("CLEAN — no correlated hollowing indicators" + leads_suffix(findings_list))
    else:
        verdict = (RED("HIGH CONFIDENCE HOLLOWING — MEM_PRIVATE, MZ wiped, AND RWX all correlate")
                   if score >= 2 else
                   YELLOW("LIKELY HOLLOWING — MEM_PRIVATE at image base correlated with "
                          + ("MZ header wiped" if mz_wiped else "RWX protection")))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/2 — requires MEM_PRIVATE at image "
          f"base correlated with a second structural anomaly; single signals above are "
          f"leads only)\n")
    return findings


def _basename_lower(path: str) -> str:
    return os.path.basename(path or "").lower()
