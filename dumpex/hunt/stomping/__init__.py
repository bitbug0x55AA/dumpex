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

This is a package, not a single file: memory_scan.py collects module/
section/protection facts and runs the unscored IOC-string region scan;
disk_reference.py owns reference-file lookup, build-identity matching,
and the relocation-normalized byte diff (it receives `read_region` as an
explicit parameter — see its own docstring for why); correlation.py
establishes RIP/EIP relationships (changed-range and anomalous-section
correlation); aggregate.py is the ONE place score/status/coverage_status/
verdict_level/confidence/lead_count/review_priority get computed;
presentation.py is the ONE place FINAL-RESULT console output (findings,
coverage-gap notes, the verdict line) gets rendered, once the scan is
done and a Report exists to render. This __init__.py is the thin entry
point: it also holds the per-module/per-section PROCESS ORCHESTRATION
loop (each section needs both a memory_scan protection check AND, when
--ref-dir is given, a disk_reference diff, so something has to call both
per section — that coordinating loop lives here rather than artificially
forcing it into either single-purpose module), and it is also where the
hunt header and in-progress scan announcements ("Scanning executable
MEM_IMAGE regions...") print — those need to appear BEFORE/DURING a scan
that can take a while, not only after a Report is built, so they live
here rather than in presentation.py (mirrors dumpex/hunt/cs_beacon/'s
same split between entry-point progress prints and presentation.py's
result rendering). memory_scan.py/disk_reference.py/correlation.py/
aggregate.py never print anything, under any circumstance.

The stable contract is `_hunt_stomping` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON shape as before this package split — this refactor only
changes internal structure. `read_region`/`get_thread_contexts` are
re-exported here and remain monkeypatchable (`stomping.read_region =
fake` before calling `_hunt_stomping()` still changes its behavior — see
dumpex/hunt/_runtime.py) because they are threaded explicitly/looked up
fresh at call time rather than each submodule importing its own separate
copy. Private per-step helper functions (`_module_basename`,
`_diff_section_on_disk`, etc.) are NOT re-exported here and make no
compatibility promise at all — import them from their actual module
(dumpex.hunt.stomping.memory_scan/.disk_reference/...) if you need them
directly.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import DIM
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import get_modules, get_memory_regions, get_thread_contexts, read_region
from dumpex.hunt._ui import _print_hunt_header
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.stomping.models import StompingScan, VerifiedChangeCandidate
from dumpex.hunt.stomping import memory_scan
from dumpex.hunt.stomping import disk_reference
from dumpex.hunt.stomping import aggregate
from dumpex.hunt.stomping import presentation


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False, ref_dir: str = None) -> dict:
    """
    Detect Module Stomping via a verified, relocation-normalized on-disk-
    vs-memory content diff (primary, scored — requires --ref-dir), a
    demoted protection-deviation lead, and a demoted string-IOC lead. See
    package docstring.
    """
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    module_list_available = bool(mf.modules and mf.modules.modules)

    _r               = get_rules()
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]

    _print_hunt_header("Module Stomping")

    # `read_region` is looked up HERE (this module's own re-exported,
    # still-monkeypatchable global) rather than imported separately inside
    # memory_scan.py/disk_reference.py — see dumpex/hunt/_runtime.py and
    # this package's own docstring above for why.
    runtime = HunterRuntime(read_region=read_region)

    # ── Explicit coverage counters for the verified-content check ────────
    # Every one of these is a reason the ONE scored signal in this hunter
    # could not run to completion for at least one eligible section — see
    # aggregate.py's content_complete. Bare pass/fail booleans can't
    # distinguish "checked everything, all clean" from "silently skipped
    # N sections", which is exactly the gap this dict closes.
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
        "relocation_failed":      0,   # delta != 0 but normalization couldn't be completed
    }

    protection_leads   = []   # dicts: module, section, region, expected, actual
    verified_candidates = []  # list[VerifiedChangeCandidate]
    identity_skipped    = []  # (module, section, reason) — ref file found but version/identity mismatched
    parse_failed        = []  # (module, pe) — module's own header didn't structurally validate
    read_failed         = 0   # module HEADER reads that raised (distinct from section memory reads)

    if mem_info_available and module_list_available:
        for m in modules:
            pe, hdr_read_failed = memory_scan.read_module_header(
                mf, runtime.read_region, m, PE_VALIDATE_READ_MAX)
            if hdr_read_failed:
                read_failed += 1
                continue
            if not pe["valid"]:
                # A loaded, known module whose own header fails structural
                # validation is itself unusual (the loader required a
                # valid header to map it) — a genuine coverage gap: this
                # module could not be checked for stomping at all.
                parse_failed.append((m, pe))
                continue
            coverage_counts["headers_parsed"] += 1

            ref_path = disk_reference.find_reference_file(m, ref_dir) if ref_dir else None

            for section in pe["sections"]:
                if not section["is_executable"] or section["is_writable"]:
                    continue   # only declared-exec, declared-non-writable sections are meaningful here
                va_start, va_end = memory_scan.section_va_range(m.baseaddress, section)
                coverage_counts["sections_total"] += 1

                # Protection-deviation LEAD — informational, never scored
                # (see package docstring for why WRITECOPY is excluded and
                # why deviation alone still isn't proof either way).
                protection_leads.extend(
                    memory_scan.check_section_protection(m, section, va_start, va_end, regions))

                # Verified content diff — the ONLY path to a nonzero score.
                if not ref_dir:
                    continue   # accounted for globally below (content_complete requires ref_dir)
                if ref_path is None:
                    coverage_counts["reference_missing"] += 1
                    continue
                diff = disk_reference.diff_section(
                    mf, runtime.read_region, ref_path, pe, m.baseaddress, section, va_start, va_end)
                if diff is None:
                    coverage_counts["reference_read_failed"] += 1
                    continue
                if diff.get("memory_read_failed"):
                    coverage_counts["memory_read_failed"] += 1
                    continue
                if not diff["identity_ok"]:
                    coverage_counts["reference_mismatch"] += 1
                    identity_skipped.append((m, section, diff["identity_reason"]))
                    continue
                if diff.get("relocation_failed"):
                    coverage_counts["relocation_failed"] += 1
                    continue
                if diff["compared_len"] == 0:
                    coverage_counts["short_reads"] += 1
                    continue

                coverage_counts["sections_compared"] += 1
                all_ranges = diff["diff_ranges"]
                if all_ranges:
                    verified_candidates.append(VerifiedChangeCandidate(
                        module=m, section=section, va_start=va_start,
                        all_ranges=all_ranges,
                        ranges_truncated_by_scan=diff["ranges_truncated"],
                        compared_len=diff["compared_len"],
                        disk_sha256=diff["disk_sha256"], mem_sha256=diff["mem_sha256"],
                    ))

    scan = StompingScan(protection_leads=protection_leads, verified_candidates=verified_candidates,
                         identity_skipped=identity_skipped, parse_failed=parse_failed,
                         read_failed=read_failed, coverage_counts=coverage_counts)

    # ── Check 2 (demoted lead, NOT scored): string IOC scan ─────────────
    print(f"  {DIM('[*] Scanning executable MEM_IMAGE regions for IOC strings (lead only)...')}\n")
    ioc_scan = memory_scan.scan_ioc_strings(mf, runtime.read_region, regions, modules,
                                             STOMPING_WHITELIST, STOMPING_IOC, STOMPING_NET_IOC)

    report = aggregate.build_report(scan, ioc_scan, thread_contexts, ref_dir,
                                     mem_info_available, module_list_available)

    return presentation.render(report, verbose)
