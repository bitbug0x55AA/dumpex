"""Module-stomping hunter using verified memory-versus-reference changes.

Unusual live protection is a lead only. A scored result requires byte differences
against an identity-matched analyst reference. Reference bytes are
relocation-normalized so ordinary ASLR does not create a false positive; current
RIP/EIP inside an actual differing range provides the strongest correlation.

Missing references, identity mismatches, and incomplete reads make a score-zero
result partial and inconclusive. IOC strings remain unscored leads, and their
oversized, failed, or short reads are explicit coverage gaps. Hotpatch
trampolines are not specially excluded and may require analyst review.
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
        ioc_eligible_bytes=ioc_coverage.eligible_bytes,
        ioc_read_failed=ioc_coverage.read_failed,
        ioc_read_failed_targets=ioc_coverage.read_failed_targets,
        ioc_short_reads=ioc_coverage.short_reads,
        ioc_short_read_targets=ioc_coverage.short_read_targets,
        ioc_unaccounted=ioc_coverage.unaccounted,
        ioc_over_accounted=ioc_coverage.over_accounted,
        ioc_ledger_imbalance=ioc_coverage.ledger_imbalance,
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
