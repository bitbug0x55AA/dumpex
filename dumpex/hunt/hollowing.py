"""Process hollowing / image-base mismatch hunter."""
import os
import re
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED, GREEN, YELLOW, DIM, BOLD, CYAN
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.core.memory import (get_modules, get_memory_regions,
    addr_to_module, va_to_file_offset, prot_str, read_region)
from dumpex.hunt._ui import _print_hunt_header, _print_check



def _hunt_hollowing(mf: MinidumpFile, verbose: bool = False) -> dict:
    """\n    Detect Process Hollowing by comparing PEB image path against\n    the actual memory backing of the main module base address.\n\n    Process Hollowing fingerprint:\n      1. Main module memory type is MEM_PRIVATE instead of MEM_IMAGE\n      2. MZ header at image base is missing or zeroed\n      3. Image base memory is RWX (needed to write replacement code)\n    """
    peb     = mf.peb
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    findings = {"checks": [], "score": 0}

    _print_hunt_header("Process Hollowing")

    if not peb:
        print(RED("  [!] PEB not available — cannot run hollowing check.\n"))
        return findings

    image_base = peb.image_base_address
    image_path = peb.image_path or "(unknown)"

    fo_base = va_to_file_offset(mf, image_base)
    fo_base_str = f"0x{fo_base:x}" if fo_base is not None else "(not captured)"
    print(f"  {DIM('PEB ImagePath     :')} {image_path}")
    print(f"  {DIM('ImageBase VA      :')} 0x{image_base:016x}  {DIM('(process virtual address)')}")
    print(f"  {DIM('ImageBase offset  :')} {fo_base_str}          {DIM('(byte offset in .dmp file)')}")
    print()

    # ── Check 1: Memory type at image base ────────────────────────────
    base_region = None
    for r in regions:
        if r.BaseAddress <= image_base < r.BaseAddress + r.RegionSize:
            base_region = r
            break

    if not base_region:
        _print_check("Memory type at image base",
                     YELLOW("NOTABLE — region not found in dump"),
                     "Image base page may not have been captured")
    else:
        mtype = prot_str(base_region.Type)
        p     = prot_str(base_region.Protect)
        if "MEM_IMAGE" in mtype:
            fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
            _print_check("Memory type at image base",
                         GREEN("CLEAN — MEM_IMAGE (mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
        else:
            fo_reg = va_to_file_offset(mf, base_region.BaseAddress)
            fo_reg_str = f"0x{fo_reg:x}" if fo_reg is not None else "(not captured)"
            _print_check("Memory type at image base",
                         RED("SUSPICIOUS — MEM_PRIVATE (not mapped from disk)"),
                         f"VA (process) 0x{base_region.BaseAddress:016x}  File offset {fo_reg_str}  {mtype}  {p}")
            findings["score"] += 1

    # ── Check 2: MZ header at image base ──────────────────────────────
    try:
        header = read_region(mf, image_base, min(64, 0x1000))
        if header[:2] == b'MZ':
            _print_check("MZ header at image base",
                         GREEN("CLEAN — MZ present"),
                         f"Header bytes: {header[:8].hex()}")
        elif header[:2] == b'':
            _print_check("MZ header at image base",
                         RED("SUSPICIOUS — MZ zeroed out (header wiping)"),
                         f"First bytes: {header[:8].hex()}")
            findings["score"] += 1
        else:
            _print_check("MZ header at image base",
                         YELLOW("NOTABLE — unexpected bytes where MZ should be"),
                         f"First bytes: {header[:8].hex()}")
            findings["score"] += 1
    except Exception as e:
        _print_check("MZ header at image base",
                     YELLOW("NOTABLE — could not read"),
                     str(e))

    # ── Check 3: RWX at image base ────────────────────────────────────
    if base_region:
        p = prot_str(base_region.Protect)
        if any(s in p for s in SUSPICIOUS_PROTS):
            _print_check("Protection at image base",
                         RED("SUSPICIOUS — RWX (write needed to hollow)"),
                         f"{p}")
            findings["score"] += 1
        else:
            _print_check("Protection at image base",
                         GREEN(f"CLEAN — {p}"))

    # ── Check 4: Module list sanity ───────────────────────────────────
    main_mod = addr_to_module(image_base, modules)
    if main_mod:
        mod_name = os.path.basename(main_mod.name).lower()
        peb_name = os.path.basename(image_path).lower()
        if mod_name == peb_name:
            _print_check("PEB image name vs module list",
                         GREEN(f"CLEAN — both report '{mod_name}'"))
        else:
            _print_check("PEB image name vs module list",
                         RED("SUSPICIOUS — name mismatch"),
                         f"PEB says '{peb_name}', module list says '{mod_name}'")
            findings["score"] += 1
    else:
        _print_check("PEB image name vs module list",
                     YELLOW("NOTABLE — image base not in any module"),
                     "Main executable may have been unmapped")
        findings["score"] += 1

    # Verdict
    score = findings["score"]
    verdict = (RED("HIGH CONFIDENCE HOLLOWING") if score >= 3 else
               YELLOW("LIKELY HOLLOWING") if score == 2 else
               YELLOW("POSSIBLE HOLLOWING") if score == 1 else
               GREEN("CLEAN — no hollowing indicators"))
    print(f"  {BOLD('[ VERDICT ]')}  {verdict}  ({score}/4 checks flagged)\n")
    return findings

