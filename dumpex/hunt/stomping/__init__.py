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

What an INCOMPLETE IOC sub-scan does and does not change
────────────────────────────────────────────────────────
That IOC scan skips any otherwise-eligible executable MEM_IMAGE region
larger than config.IOC_SCAN_MAX (5 MiB); a read of an eligible region can
also fail outright, or come back with fewer bytes than the region's own
declared size (a short read still gets its readable prefix scanned -- a
real hit in it is still reported -- but the region is not fully covered).
All three are RECORDED, never dropped: the oversized ones keep their full
region identity (VA, size, dump-file offset, allocation base, state/type/
protection, and the cap they exceeded) as dumpex.output.coverage.
ScanTargets on the scan's CoverageTracker, and surface as a
SCAN_REGION_OVERSIZED_SKIPPED / SCAN_REGION_READ_FAILED /
SCAN_REGION_SHORT_READ coverage limitation under the `ioc_string_scan`
source. The deliberate, explicitly-chosen consequences are:

  - the IOC CHECK is rendered INCOMPLETE, never "CLEAN — no IOC patterns
    in executable module memory": that sentence is a claim about all
    eligible executable module memory, and it may only be printed when
    all of it was actually read;
  - `coverage_status` becomes "partial", with the skipped regions named in
    `coverage_reasons` — memory that was never read is not covered memory,
    and the typed CoverageReport turns any limitation into "partial"
    regardless;
  - and therefore, at score 0, `status` is INCONCLUSIVE rather than
    NOT_DETECTED_IN_SCANNED_SCOPE. coverage_status and status are NOT
    independently choosable: the output contract pins the pair (see the
    schema's hunterRecord — NOT_DETECTED_IN_SCANNED_SCOPE requires
    coverage.status "complete"), so recording the gap settles the status
    too. This applies to the IOC scan's read failures as well, which
    previously left a run reporting a complete, clean scan;
  - `score`, `verdict_level` for a detection, and the findings themselves
    are UNCHANGED. A DETECTED run stays DETECTED with coverage_status
    "partial" (a real hit wins over incomplete coverage — see
    dumpex.hunt._coverage.derive_status), so an oversized region can
    neither invent nor hide a verified content change; it only stops a
    score-0 result from being presented as a clean bill of health over
    memory nobody read. See aggregate.build_report for the same decision
    stated at the point it is applied.
  - ONE exception to "coverage_status/status move together": if
    ModuleListStream is absent, `evaluated` is False regardless of the IOC
    scan (the scored content-diff check needs that stream and never runs
    at all — see `evaluated = mem_info_available and module_list_available`
    below), so the hunter is NOT_EVALUATED no matter what the IOC scan
    found. The IOC scan itself only needs MemoryInfoListStream, so it can
    still run in this case and still find a real gap — that gap is still
    surfaced as a coverage.limitations[] entry alongside the otherwise-
    unrelated NOT_EVALUATED result, rather than silently dropped just
    because build_coverage_report()'s own group-absent short-circuit fires
    for the UNRELATED "modules" source. See _stomping_coverage_report
    below for where this is appended after that call returns.

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
from dumpex.output.coverage import (
    build_coverage_report, observe_source, EvaluationRequirement, SourceRequirement,
    CoverageLimitation, LimitationCode, CoverageReport, CoverageStatus,
)

from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.stomping.models import StompingScan, VerifiedChangeCandidate
from dumpex.hunt.stomping import memory_scan
from dumpex.hunt.stomping import disk_reference
from dumpex.hunt.stomping import aggregate
from dumpex.hunt.stomping import presentation


def _stomping_coverage_report(scan, ioc_scan, ref_dir, mem_info_available, module_list_available):
    """Real dumpex.output.coverage.CoverageReport for a stomping run --
    built at each gap site aggregate.build_report() already derives
    coverage_status/coverage_reasons from (never parsed back out of that
    free text; see docs/hunt_migration_field_matrix.md's own migration
    rule). `memory_info`/`modules` are each their OWN independent
    evaluation_groups entry (not one combined group) because stomping's
    real `evaluated = mem_info_available and module_list_available` is
    AND-of-presence: EITHER one being absent alone is NOT_EVALUATED,
    unlike a combined group's OR-of-absence semantics (see comparison.py's
    own baseline.modules/target.modules precedent for the same pattern).
    `reference_files`/`module_headers`/`section_content_diff`/
    `ioc_string_scan` are synthetic sources (not real minidump streams),
    mirroring injection's own `hidden_pe_scan` pattern -- see
    dumpex.output.coverage's newly added STOMPING_*/MODULE_HEADER_* codes.

    The `ioc_string_scan` limitations come from the UNSCORED IOC-string
    region scan: an eligible executable MEM_IMAGE region over
    config.IOC_SCAN_MAX (identified by ScanTarget, not merely counted), one
    whose read failed, or one that returned fewer bytes than declared.
    They downgrade coverage.status to "partial" like any other limitation
    -- see this package's docstring for what that does and does not change
    about the hunter's verdict.

    These are appended to the report build_coverage_report() itself
    returns, AFTER that call, rather than folded into `completeness_checks`
    like every other gap here -- see the comment at the append site for
    why: this scan can run (and find real gaps) even when the `modules`
    evaluation-group source is ABSENT, a case build_coverage_report()
    itself short-circuits to NOT_EVALUATED while discarding every
    pre-built CoverageLimitation passed to it."""
    cc = scan.coverage_counts
    sources = {
        "memory_info": observe_source("memory_info", present=mem_info_available,
                                       items=["present"] if mem_info_available else []),
        "modules":     observe_source("modules", present=module_list_available,
                                       items=["present"] if module_list_available else []),
        "module_headers": observe_source("module_headers", present=True, items=["scanned"]),
        "reference_files": observe_source("reference_files", present=ref_dir is not None,
                                           items=["supplied"] if ref_dir is not None else []),
        "section_content_diff": observe_source("section_content_diff", present=True,
                                                items=["scanned"]),
        "ioc_string_scan": observe_source("ioc_string_scan", present=True, items=["scanned"]),
    }
    completeness_checks = []
    if scan.read_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.MODULE_HEADER_READ_FAILED, source="module_headers",
            affected_count=scan.read_failed))
    if scan.parse_failed:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.MODULE_HEADER_PARSE_FAILED, source="module_headers",
            affected_count=len(scan.parse_failed)))
    if ref_dir is None:
        completeness_checks.append(SourceRequirement(
            source="reference_files",
            absent_code=LimitationCode.STOMPING_REFERENCE_NOT_SUPPLIED))
    else:
        if cc["reference_missing"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_MISSING, source="reference_files",
                affected_count=cc["reference_missing"]))
        if cc["reference_mismatch"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_MISMATCH, source="reference_files",
                affected_count=cc["reference_mismatch"]))
        if cc["reference_read_failed"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_REFERENCE_READ_FAILED, source="reference_files",
                affected_count=cc["reference_read_failed"]))
        if cc["memory_read_failed"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_SECTION_MEMORY_READ_FAILED,
                source="section_content_diff", affected_count=cc["memory_read_failed"]))
        if cc["short_reads"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_SHORT_READ, source="section_content_diff",
                affected_count=cc["short_reads"]))
        if cc["relocation_failed"]:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.STOMPING_RELOCATION_FAILED, source="section_content_diff",
                affected_count=cc["relocation_failed"]))

    report = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("memory_info",)),
                           EvaluationRequirement(("modules",))],
        completeness_checks=completeness_checks)

    # The IOC-string scan's own gaps are appended to the ALREADY-BUILT
    # report, never folded into `completeness_checks` above like every
    # other gap in this function. Reason: scan_ioc_strings() only needs
    # MemoryInfoListStream (it does its own module lookup per-region via
    # addr_to_module(), tolerating an empty/absent module list) -- so it
    # can run, and find a REAL oversized/short/failed region, even when
    # `modules` is ABSENT and the "modules" evaluation_groups member above
    # fires build_coverage_report()'s own NOT_EVALUATED short-circuit.
    # That short-circuit unconditionally drops every pre-built
    # CoverageLimitation passed in `completeness_checks` (see its own
    # comment: "a pre-built business fact never applies when nothing was
    # evaluated") -- correct for every OTHER gap here, whose own scan
    # never ran without `modules`/`memory_info`, but wrong for this one.
    # Appending here instead means: hunter-level `status` is untouched
    # (still NOT_EVALUATED when the core module/section walk genuinely
    # couldn't run -- see aggregate.py's own `evaluated` derivation, which
    # this does not change), while the one gap this scan actually
    # observed is never silently dropped from --json purely because a
    # DIFFERENT part of the hunter had nothing to evaluate. `status` and
    # `coverage.status` staying literally NOT_EVALUATED here, alongside a
    # real limitation entry, mirrors the same shape build_coverage_report()
    # itself already uses for a FAILED (not ABSENT) completeness-check
    # source under this exact short-circuit -- an established precedent
    # for "not evaluated overall, but this one fact still gets surfaced",
    # not a new exception invented here.
    ioc_coverage = ioc_scan.coverage
    ioc_limitations = []
    if ioc_coverage.skipped_oversize:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_OVERSIZED_SKIPPED, source="ioc_string_scan",
            affected_count=ioc_coverage.skipped_oversize,
            targets=ioc_coverage.skipped_oversize_targets))
    if ioc_coverage.read_failed:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_READ_FAILED, source="ioc_string_scan",
            affected_count=ioc_coverage.read_failed))
    if ioc_coverage.short_reads:
        ioc_limitations.append(CoverageLimitation(
            code=LimitationCode.SCAN_REGION_SHORT_READ, source="ioc_string_scan",
            affected_count=ioc_coverage.short_reads))
    if not ioc_limitations:
        return report

    status = (CoverageStatus.PARTIAL if report.status == CoverageStatus.COMPLETE
              else report.status)
    return CoverageReport(status=status, sources=report.sources,
                           limitations=[*report.limitations, *ioc_limitations])


def _build_stomping_report(mf: MinidumpFile, ref_dir: str = None):
    """Run the scan/aggregate pipeline and return the aggregate.Report --
    the ONE place this pipeline is assembled, and runs EXACTLY ONCE per
    call. Prints nothing at all (see `_hunt_stomping()`/`collect_hunt()`
    for the two console/typed-record consumers of the same Report --
    PR4 of the `--hunt` v2.4 migration unified every hunter onto this
    build-once, multiple-consumers shape)."""
    modules = get_modules(mf)
    regions = get_memory_regions(mf)
    thread_contexts = get_thread_contexts(mf)
    mem_info_available    = bool(mf.memory_info and mf.memory_info.infos)
    module_list_available = bool(mf.modules and mf.modules.modules)

    _r               = get_rules(announce=False)
    STOMPING_WHITELIST  = _r["stomping_whitelist"]
    STOMPING_IOC        = _r["stomping_ioc_patterns"]
    STOMPING_NET_IOC    = _r["stomping_net_ioc_patterns"]

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
    ioc_scan = memory_scan.scan_ioc_strings(mf, runtime.read_region, regions, modules,
                                             STOMPING_WHITELIST, STOMPING_IOC, STOMPING_NET_IOC)

    report = aggregate.build_report(scan, ioc_scan, thread_contexts, ref_dir,
                                     mem_info_available, module_list_available)
    report.coverage_report = _stomping_coverage_report(
        scan, ioc_scan, ref_dir, mem_info_available, module_list_available)
    return report


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False, ref_dir: str = None) -> dict:
    """
    Detect Module Stomping via a verified, relocation-normalized on-disk-
    vs-memory content diff (primary, scored — requires --ref-dir), a
    demoted protection-deviation lead, and a demoted string-IOC lead. See
    package docstring.

    Both progress announcements below print BEFORE the (now fully
    silent) `_build_stomping_report()` call rather than interleaved with
    it -- console output is only ever observed as one fully-captured
    block (never mid-run) by anything that checks it, including
    tests/integration/test_hunt_cli_compat_freeze.py's own byte-exact
    fixtures, so this reordering changes nothing any consumer can see.
    `get_rules()` is called here too, BEFORE the header print, for the
    exact same reason dumpex.hunt.hollowing's own console wrapper does
    -- it prints a one-time "Rules loaded from ..." line the FIRST time
    it's ever called in a process, and the pre-split function called it
    before printing the header; the builder calls it again internally
    (a cheap cache hit after the first real load, see
    dumpex.rules_pkg.loader.get_rules), so this preserves that print
    order without the builder itself printing anything.
    """
    _print_stomping_pre_build_console()
    report = _build_stomping_report(mf, ref_dir=ref_dir)
    return presentation.render(report, verbose)


def _print_stomping_pre_build_console() -> None:
    """The header + IOC-scan progress line, extracted so
    `dumpex.hunt.collect_hunt()`'s console+JSON orchestrator (see that
    function's own docstring) can print the exact same lines
    `_hunt_stomping()` does, BEFORE calling `_build_stomping_report()`
    itself, without duplicating this print sequence (and its
    `get_rules()` print-ordering fix, see `_hunt_stomping()`'s own
    docstring) as a second copy."""
    get_rules()
    _print_hunt_header("Module Stomping")
    print(f"  {DIM('[*] Scanning executable MEM_IMAGE regions for IOC strings (lead only)...')}\n")
