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
excludes the import tables themselves for typical PE layouts, but a
legitimate hotpatch NOP-padding/trampoline at a function prologue can
still produce a genuine, non-malicious byte difference inside .text — see
the `stomping.verified_content_change` CheckResult's `limitations`.

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

  - the IOC gap is rendered in the console's unified COVERAGE section with
    an explicit impact line, never as "CLEAN — no IOC patterns in
    executable module memory": that sentence is a claim about all eligible
    executable module memory, and it may only be made when all of it was
    actually read;
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
  - `score`, `verdict_level` for a detection, and the checks themselves
    are UNCHANGED. A DETECTED run stays DETECTED with coverage_status
    "partial" (a real hit wins over incomplete coverage — see
    dumpex.hunt._coverage.derive_status), so an oversized region can
    neither invent nor hide a verified content change; it only stops a
    score-0 result from being presented as a clean bill of health over
    memory nobody read. See domain.CoverageSnapshot.complete for the same
    decision stated at the point it is applied.
  - ONE exception to "coverage_status/status move together": if
    ModuleListStream is absent, `evaluated` is False regardless of the IOC
    scan (the scored content-diff check needs that stream and never runs
    at all — see domain.CoverageSnapshot.evaluated), so the hunter is
    NOT_EVALUATED no matter what the IOC scan found. The IOC scan itself
    only needs MemoryInfoListStream, so it can still run in this case and
    still find a real gap — that gap is still surfaced as a
    coverage.limitations[] entry alongside the otherwise-unrelated
    NOT_EVALUATED result, rather than silently dropped just because
    build_coverage_report()'s own group-absent short-circuit fires for the
    UNRELATED "modules" source. See report_facts.project_coverage_report
    for where this is appended after that call returns.

This is a package, not a single file, and since the canonical-Report
migration (issue #8) it has the same shape as dumpex/hunt/injection/ and
dumpex/hunt/encoding/ (the two completed reference pilots):

  models.py         — the immutable Evidence value objects every layer
                       below produces; the ONE place a raw `Module`/
                       `MinidumpMemoryInfo`/PE-header dict is snapshotted.
  memory_scan.py    — module header reads, per-section protection-deviation
                       checks, and the unscored IOC-string region scan.
  disk_reference.py — reference-file lookup, build-identity matching, and
                       the relocation-normalized byte diff (it receives
                       `read_region` as an explicit parameter — see its own
                       docstring for why).
  correlation.py    — RIP/EIP relationships (changed-range and anomalous-
                       section correlation), and the last place a raw
                       thread-context dict is touched.
  domain.py         — `StompingReport`/`StompingEvidence`/`CoverageSnapshot`:
                       the canonical, recursively immutable result.
  aggregate.py      — the ONE place score/coverage/the six CheckResults get
                       computed. Takes typed evidence + scalars only.
  report_console.py — the ONE place console output is rendered, as a pure
                       post-hoc projection of an already-built Report.
  report_facts.py   — the fact strings + coverage projections the other
                       three projectors share.
  report_legacy.py  — `StompingReport` -> the v1.1 findings dict.
  report_record.py  — `StompingReport` -> the typed `HunterRecord`.

This __init__.py is the thin entry point: it holds the per-module/
per-section PROCESS ORCHESTRATION loop (each section needs both a
memory_scan protection check AND, when --ref-dir is given, a
disk_reference diff, so something has to call both per section — that
coordinating loop lives here rather than artificially forcing it into
either single-purpose module), then aggregates once and projects.

Nothing prints before the Report exists any more. The pre-migration
`_print_stomping_pre_build_console()` (a hunt header plus a
"Scanning executable MEM_IMAGE regions for IOC strings..." progress line,
preceded by an announcing `get_rules()` call purely to order its one-time
"Rules loaded from ..." line before that header) is gone entirely,
following dumpex.hunt.encoding's own resolution of the identical problem:
`report_console.render_console_lines` emits the header itself via
`dumpex.hunt._report_console.header_lines()`, the scan-progress line
became a VERBOSE-only scan-detail line, and the builder's own
`get_rules(announce=False)` call is now the only one this hunter makes --
so a `--hunt stomping` run no longer prints a "Rules loaded from ..."
line at all (nor does `--hunt all` any more: hollowing's own pre-build
console, the last remaining announcer, went the same way with issue #10).
Rule PROVENANCE is unaffected --
it is reported in --json `meta.rules` from
`dumpex.rules_pkg.loader.get_rules_source_info()`, which
`get_rules(announce=False)` populates exactly the same way.

The stable contract is `_hunt_stomping` itself (imported by
dumpex/hunt/__init__.py): same signature, same fields, same score/status/
coverage/JSON shape. `read_region`/`get_thread_contexts` are re-exported
here and remain monkeypatchable (`stomping.read_region = fake` before
calling `_hunt_stomping()` still changes its behavior — see
dumpex/hunt/_runtime.py) because they are threaded explicitly/looked up
fresh at call time rather than each submodule importing its own separate
copy. Private per-step helper functions (`_module_basename`,
`_diff_section_on_disk`, etc.) are NOT re-exported here and make no
compatibility promise at all — import them from their actual module
(dumpex.hunt.stomping.models/.memory_scan/.disk_reference/...) if you need
them directly.
"""
from minidump.minidumpfile import MinidumpFile
from dumpex.rules_pkg.loader import get_rules
from dumpex.core.memory import (get_modules, get_memory_regions, get_thread_contexts,
    read_region, va_to_file_offset)
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.stomping.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.stomping.models import ParseFailedEvidence, SectionDiffResult, module_ref, section_ref
from dumpex.hunt.stomping.models import IdentityMismatchEvidence
from dumpex.hunt.stomping import memory_scan
from dumpex.hunt.stomping import disk_reference
from dumpex.hunt.stomping import correlation
from dumpex.hunt.stomping.aggregate import build_report
from dumpex.hunt.stomping import report_console, report_legacy


def _build_stomping_report(mf: MinidumpFile, ref_dir: str = None):
    """Run the scan/aggregate pipeline and return the immutable
    `dumpex.hunt.stomping.domain.StompingReport` -- the ONE place this
    pipeline is assembled, and it runs EXACTLY ONCE per call. Prints
    nothing at all (see `_hunt_stomping()`/`collect_hunt()` for the
    console/typed-record consumers of the same Report).

    `ref_dir` stops here: everything below this function sees only
    `ref_dir_supplied`, a bool. Whether a reference directory was given is
    a coverage fact the verdict depends on; the path itself is a live
    filesystem handle the domain model must not retain.
    """
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
    # domain.CoverageSnapshot.content_complete. Bare pass/fail booleans
    # can't distinguish "checked everything, all clean" from "silently
    # skipped N sections", which is exactly the gap these close. Kept as a
    # plain local dict purely as an accumulator for this loop; it never
    # crosses into the Report (build_report takes named int scalars, and
    # CoverageSnapshot stores them as named fields -- a dict can never be
    # recursively immutable).
    counts = {
        "modules_total":          len(modules),
        "headers_parsed":         0,
        "sections_total":         0,
        "sections_compared":      0,
        "reference_missing":      0,
        "reference_mismatch":     0,
        "reference_read_failed":  0,
        "memory_read_failed":     0,
        "short_reads":            0,
        "relocation_failed":      0,
    }

    protection_leads    = []   # ProtectionLeadEvidence
    section_diffs       = []   # SectionDiffResult (pre-correlation transport)
    identity_mismatches = []   # IdentityMismatchEvidence
    parse_failures      = []   # ParseFailedEvidence
    header_read_failed  = 0    # module HEADER reads that raised (distinct from section reads)

    if mem_info_available and module_list_available:
        for m in modules:
            pe, hdr_read_failed = memory_scan.read_module_header(
                mf, runtime.read_region, m, PE_VALIDATE_READ_MAX)
            if hdr_read_failed:
                header_read_failed += 1
                continue
            if not pe["valid"]:
                # A loaded, known module whose own header fails structural
                # validation is itself unusual (the loader required a
                # valid header to map it) — a genuine coverage gap: this
                # module could not be checked for stomping at all.
                parse_failures.append(ParseFailedEvidence(module=module_ref(m),
                                                           reason=pe["reason"]))
                continue
            counts["headers_parsed"] += 1

            ref_path = disk_reference.find_reference_file(m, ref_dir) if ref_dir else None

            for section in pe["sections"]:
                if not section["is_executable"] or section["is_writable"]:
                    continue   # only declared-exec, declared-non-writable sections are meaningful here
                va_start, va_end = memory_scan.section_va_range(m.baseaddress, section)
                counts["sections_total"] += 1

                # Protection-deviation LEAD — informational, never scored
                # (see package docstring for why WRITECOPY is excluded and
                # why deviation alone still isn't proof either way).
                protection_leads.extend(memory_scan.check_section_protection(
                    mf, m, section, va_start, va_end, regions))

                # Verified content diff — the ONLY path to a nonzero score.
                if not ref_dir:
                    continue   # accounted for globally below (content_complete requires ref_dir)
                if ref_path is None:
                    counts["reference_missing"] += 1
                    continue
                diff = disk_reference.diff_section(
                    mf, runtime.read_region, ref_path, pe, m.baseaddress, section, va_start, va_end)
                if diff is None:
                    counts["reference_read_failed"] += 1
                    continue
                if diff.get("memory_read_failed"):
                    counts["memory_read_failed"] += 1
                    continue
                if not diff["identity_ok"]:
                    counts["reference_mismatch"] += 1
                    identity_mismatches.append(IdentityMismatchEvidence(
                        module=module_ref(m), section=section_ref(section),
                        reason=diff["identity_reason"]))
                    continue
                if diff.get("relocation_failed"):
                    counts["relocation_failed"] += 1
                    continue
                if diff["compared_len"] == 0:
                    counts["short_reads"] += 1
                    continue

                counts["sections_compared"] += 1
                if diff["diff_ranges"]:
                    section_diffs.append(SectionDiffResult(
                        module=module_ref(m), section=section_ref(section), va_start=va_start,
                        all_ranges=diff["diff_ranges"],
                        ranges_truncated_by_scan=diff["ranges_truncated"],
                        compared_len=diff["compared_len"],
                        disk_sha256=diff["disk_sha256"], mem_sha256=diff["mem_sha256"],
                        # Resolved here, once per verified change, and only
                        # on the path that actually produces one -- the
                        # section's own .dmp offset is --verbose-only
                        # detail (report_console.py), never a wire fact.
                        file_offset=va_to_file_offset(mf, va_start)))

    # ── Check 2 (demoted lead, NOT scored): string IOC scan ─────────────
    ioc_scan = memory_scan.scan_ioc_strings(mf, runtime.read_region, regions, modules,
                                             STOMPING_WHITELIST, STOMPING_IOC, STOMPING_NET_IOC)

    # RIP/EIP correlation is the last thing that needs the raw thread-
    # context dicts -- both calls return typed Evidence, so `build_report`
    # below never sees them.
    verified_changes = correlation.build_verified_changes(section_diffs, thread_contexts)
    rip_correlated_leads = correlation.correlate_protection_leads_with_rip(
        tuple(protection_leads), thread_contexts)

    ioc_coverage = ioc_scan.coverage
    return build_report(
        tuple(protection_leads), rip_correlated_leads, verified_changes,
        tuple(identity_mismatches), tuple(parse_failures), ioc_scan.hits,
        memory_info_stream=mem_info_available, module_list_stream=module_list_available,
        # bool(ref_dir), not `is not None`: an empty string is exactly as
        # unusable as None everywhere else in this function (`if ref_dir`
        # already gates both the reference lookup above and the
        # `sections_total`-accounting `continue` below on truthiness) --
        # `ref_dir_supplied` must agree, or ref_dir="" reports a scored
        # signal as "attempted" while every counter that would explain a
        # resulting partial-coverage gap stays at zero.
        ref_dir_supplied=bool(ref_dir),
        header_read_failed=header_read_failed, header_parse_failed=len(parse_failures),
        ioc_oversized=ioc_coverage.skipped_oversize_targets,
        ioc_read_failed=ioc_coverage.read_failed,
        ioc_read_failed_targets=ioc_coverage.read_failed_targets,
        ioc_short_reads=ioc_coverage.short_reads,
        ioc_short_read_targets=ioc_coverage.short_read_targets,
        ioc_whitelisted_modules=ioc_coverage.whitelisted_skipped,
        **counts)


def _hunt_stomping(mf: MinidumpFile, verbose: bool = False, ref_dir: str = None) -> dict:
    """
    Detect Module Stomping via a verified, relocation-normalized on-disk-
    vs-memory content diff (primary, scored — requires --ref-dir), a
    demoted protection-deviation lead, and a demoted string-IOC lead. See
    package docstring.

    Nothing prints before `_build_stomping_report()` returns:
    `report_console.render_console_lines` is a pure post-hoc projection of
    the already-built Report (see this package's own docstring on where the
    old header/scan-progress prints went), mirroring dumpex.hunt.injection's
    and dumpex.hunt.encoding's build-once, print-after shape.
    """
    report = _build_stomping_report(mf, ref_dir=ref_dir)
    return _render_stomping_console(report, verbose)


def _render_stomping_console(report, verbose: bool = False) -> dict:
    """Render the console report for an ALREADY-BUILT `StompingReport`,
    returning the same v1.1-shaped findings dict `_hunt_stomping()` always
    has -- extracted so `dumpex.hunt.cmd_hunt()`'s console+JSON
    orchestrator can feed ONE built Report to both this and
    `_record_from_stomping_report()` without scanning twice."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)
