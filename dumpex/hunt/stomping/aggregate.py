"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the stomping hunter, and
where Finding objects and the public `findings` dict are built.

Nothing here prints; nothing here scans/diffs. This module only turns
already-collected facts (a StompingScan, an IocScan, thread contexts) into
the hunter's decision fields, calling into correlation.py for the RIP/EIP
relationships it needs along the way.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority)
from dumpex.hunt.stomping.memory_scan import _module_basename
from dumpex.hunt.stomping.config import MAX_DIFF_RANGES
from dumpex.hunt.stomping import correlation


def _ioc_verbose_facts(ioc_hits) -> list:
    """Finding.verbose_facts for stomping.ioc_string_lead -- console/--txt
    --verbose-only, uncapped, per-TOKEN detail (absolute VA, encoding,
    weak/common-API classification) `facts` above never carries: `facts`
    dedupes to one entry per REGION with a capped, deduped term list (built
    for --json). This is presentation formatting living in
    aggregate.py, not hunter logic in presentation.py -- see
    dumpex/hunt/stomping/presentation.py's own module docstring."""
    out = []
    for r, mod, hits, _ in ioc_hits:
        name = _module_basename(mod) if mod else "(unknown)"
        for off, enc, tok, is_weak in hits:
            weak = " (weak/common API)" if is_weak else ""
            out.append(f"module={name} region=0x{r.BaseAddress:x} VA=0x{r.BaseAddress+off:x} "
                       f"encoding={enc} token={tok}{weak}")
    return out

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.verdict_level).
# No "3": this hunter's max score is 2 (verified change, optionally
# corroborated by live RIP/EIP — there's no third independent signal).
_VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "high"}
# score==1 (verified content diff, no RIP corroboration) maps to "possible"
# rather than "likely" — see presentation.py's DETECTED verdict text for
# why: an uncorroborated diff is equally consistent with a benign
# hotpatch/EDR hook, so "likely [stomping]" would over-attribute intent
# from a table that's meant to be a plain display transform of the score,
# not a second place to encode that judgment call.


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail."""
    findings: dict
    findings_list: list
    ioc_scan: object = None
    verified_changes: list = field(default_factory=list)
    score: int = 0
    status: str = None
    coverage_status: str = None
    coverage_reasons: list = field(default_factory=list)
    coverage_report: object = None   # dumpex.output.coverage.CoverageReport (v2.4 migration only)
    ref_dir: "str|None" = None


def build_report(scan, ioc_scan, thread_contexts: list, ref_dir: "str|None",
                  mem_info_available: bool, module_list_available: bool) -> Report:
    findings = {"protection_leads": scan.protection_leads, "verified_changes": [],
                "score": 0, "max_score": 2}
    findings_list = []
    protection_leads = scan.protection_leads

    # Finalize verified_changes: RIP correlation (correlation.py) + display
    # truncation, from each raw VerifiedChangeCandidate.
    verified_changes = []
    for c in scan.verified_candidates:
        rip_in_changed = correlation.rip_in_ranges(thread_contexts, c.va_start, c.all_ranges)
        verified_changes.append({
            "module": c.module, "section": c.section, "va_start": c.va_start,
            "diff_ranges": c.all_ranges[:MAX_DIFF_RANGES],
            "ranges_truncated": c.ranges_truncated_by_scan or len(c.all_ranges) > MAX_DIFF_RANGES,
            "total_ranges": len(c.all_ranges),
            "compared_len": c.compared_len,
            "rip_in_changed_range": rip_in_changed,
            "disk_sha256": c.disk_sha256, "mem_sha256": c.mem_sha256,
        })
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
            facts=[f"{scan.coverage_counts['headers_parsed']} module(s) checked"],
            inference="No module section declared executable-but-not-writable shows a "
                       "live protection state outside the normal set.",
            confidence=CONFIDENCE_LOW,
            rationale="Absence of a protection anomaly is weak evidence of absence — "
                       "stomping via careful VirtualProtect bookkeeping (reprotect to RX "
                       "before the dump) would not show up here at all.",
            limitations=[],
            tag=TAG_OBSERVATION,
        ))

    # ── Finding: protection anomaly + a thread's LIVE RIP/EIP inside that ─
    # same section — a stronger, more specific signal than the bare
    # protection-deviation lead above, but still not the verified,
    # relocation-normalized byte diff that alone earns "confirmed
    # stomping" (stomping.verified_content_change below). Only checked
    # when the scored path couldn't already settle it (no --ref-dir, or
    # --ref-dir supplied but no verified diff came out of it) — once a
    # verified diff exists, its OWN rip_in_changed_range already covers
    # this correlation with actual evidence behind it, not just a
    # protection-state guess.
    if protection_leads and (not ref_dir or not verified_changes):
        rip_correlated = correlation.correlate_protection_leads_with_rip(protection_leads, thread_contexts)
        if rip_correlated:
            facts = []
            for hit, tc in rip_correlated[:20]:
                m, sec = hit["module"], hit["section"]
                name = _module_basename(m) or "(unnamed module)"
                facts.append(f"module={name} section={sec['name']!r} "
                             f"VA=0x{hit['va_start']:x}-0x{hit['va_end']:x} "
                             f"declared={hit['expected']} actual={hit['actual']} "
                             f"TID=0x{tc['ThreadId']:x} {tc['ip_reg']}=0x{tc['ip']:x}")
            if len(rip_correlated) > 20:
                facts.append(f"... and {len(rip_correlated)-20} more")
            findings_list.append(Finding(
                check="stomping.rip_in_anomalous_section_lead",
                facts=facts,
                inference=f"{len(rip_correlated)} module section(s) with anomalous live "
                           f"protection ALSO have a thread's current RIP/EIP executing "
                           f"inside that exact section.",
                confidence=CONFIDENCE_MEDIUM,
                rationale="A protection deviation alone proves nothing about content "
                           "(see stomping.protection_deviation_lead), but a thread "
                           "actively executing inside the SAME anomalously-protected "
                           "range is a materially stronger, more specific correlation "
                           "worth a closer manual look — without --ref-dir there is no "
                           "verified byte-level diff behind it, so this stays a lead, "
                           "not a confirmed stomping detection.",
                limitations=["Protection state + live RIP still cannot rule out a "
                             "debugger/EDR hook or other benign reprotect-then-execute "
                             "sequence — only a verified content diff "
                             "(stomping.verified_content_change, requires --ref-dir) can."],
                tag=TAG_LEAD,
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

    if scan.identity_skipped:
        facts = [f"module={_module_basename(m) or '(unnamed)'} section={sec['name']!r} reason={reason}"
                 for m, sec, reason in scan.identity_skipped[:15]]
        if len(scan.identity_skipped) > 15:
            facts.append(f"... and {len(scan.identity_skipped)-15} more")
        findings_list.append(Finding(
            check="stomping.reference_identity_mismatch",
            facts=facts,
            inference=f"{len(scan.identity_skipped)} section(s) had a matching-basename reference "
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

    if scan.parse_failed:
        facts = [f"module={_module_basename(m) or '(unnamed)'} base=0x{m.baseaddress:x} reason={pe['reason']}"
                 for m, pe in scan.parse_failed[:15]]
        if len(scan.parse_failed) > 15:
            facts.append(f"... and {len(scan.parse_failed)-15} more")
        findings_list.append(Finding(
            check="stomping.module_header_invalid",
            facts=facts,
            inference=f"{len(scan.parse_failed)} known module(s) failed PE header structural "
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

    # ── Finding: IOC string lead (unscored) ───────────────────────────────
    if ioc_scan.ioc_hits:
        n_strong = sum(sum(1 for h in hits if not h[3]) for _, _, hits, _ in ioc_scan.ioc_hits)
        n_weak   = sum(sum(1 for h in hits if h[3]) for _, _, hits, _ in ioc_scan.ioc_hits)
        facts = []
        for r, mod, hits, _ in ioc_scan.ioc_hits[:15]:
            name = _module_basename(mod) if mod else "(unknown)"
            terms = sorted({tok for _, _, tok, _ in hits})[:8]
            facts.append(f"module={name} VA=0x{r.BaseAddress:x} terms={', '.join(terms)}")
        if len(ioc_scan.ioc_hits) > 15:
            facts.append(f"... and {len(ioc_scan.ioc_hits)-15} more")
        findings_list.append(Finding(
            check="stomping.ioc_string_lead",
            facts=facts,
            verbose_facts=_ioc_verbose_facts(ioc_scan.ioc_hits),
            inference=f"{n_strong} strong + {n_weak} weak IOC-keyword token(s) found across "
                       f"{len(ioc_scan.ioc_hits)} executable module region(s).",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that the bytes exist somewhere in the "
                       "region — it is trivial to plant, coincidentally match tool/API "
                       "names, or survive from unrelated benign code. This is reported as "
                       "an investigative lead only and does NOT contribute to the stomping "
                       "score; see stomping.verified_content_change for the only signal "
                       "that scores.",
            limitations=["Not corroborated by any structural (section/protection) evidence "
                         "on its own."] + ([f"{ioc_scan.ioc_read_failed} otherwise-eligible region(s) "
                         f"could not be read and were not scanned for IOC strings."]
                         if ioc_scan.ioc_read_failed else []),
            tag=TAG_LEAD,
        ))

    # ── Coverage — independent of score/status, so "DETECTED but coverage
    # was partial" is representable rather than DETECTED silently implying
    # a complete scan. content_complete is specifically about the ONE
    # scored signal (verified content diff): it requires --ref-dir AND
    # every eligible section actually being compared, with zero failures
    # of any kind along the way. ─────────────────────────────────────────
    cc = scan.coverage_counts
    content_complete = (
        ref_dir is not None
        and cc["sections_compared"] == cc["sections_total"]
        and not any([
            cc["reference_missing"],
            cc["reference_mismatch"],
            cc["reference_read_failed"],
            cc["memory_read_failed"],
            cc["short_reads"],
            cc["relocation_failed"],
        ])
    )

    coverage_reasons = []
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if not module_list_available:
        coverage_reasons.append("ModuleListStream missing from this dump")
    if scan.read_failed:
        coverage_reasons.append(f"{scan.read_failed} module header read(s) failed")
    if scan.parse_failed:
        coverage_reasons.append(f"{len(scan.parse_failed)} module header(s) failed PE structural validation")
    if ref_dir is None:
        coverage_reasons.append("--ref-dir not supplied — verified content comparison "
                                 "(the only scored signal) was not performed for any module")
    else:
        if cc["reference_missing"]:
            coverage_reasons.append(f"{cc['reference_missing']} section(s) had no "
                                     f"matching reference file under --ref-dir")
        if cc["reference_mismatch"]:
            coverage_reasons.append(f"{cc['reference_mismatch']} section(s) had a "
                                     f"reference file whose build identity didn't match")
        if cc["reference_read_failed"]:
            coverage_reasons.append(f"{cc['reference_read_failed']} reference "
                                     f"file(s) could not be read")
        if cc["memory_read_failed"]:
            coverage_reasons.append(f"{cc['memory_read_failed']} section(s) could "
                                     f"not be read from memory")
        if cc["short_reads"]:
            coverage_reasons.append(f"{cc['short_reads']} section(s) had nothing "
                                     f"comparable to read")
        if cc["relocation_failed"]:
            coverage_reasons.append(f"{cc['relocation_failed']} section(s) needed "
                                     f"relocation normalization that could not be completed "
                                     f"(unsupported machine type or malformed relocation table)")

    evaluated = mem_info_available and module_list_available
    complete  = not (scan.read_failed or scan.parse_failed or not content_complete)
    coverage_status = derive_coverage_status(evaluated, complete)
    findings["coverage_status"]  = coverage_status
    findings["coverage_reasons"] = coverage_reasons
    findings["coverage_counts"]  = cc

    status = derive_status(evaluated, score > 0, complete)
    findings["status"] = status
    findings["confidence"] = overall_confidence(findings_list, score)
    findings["verdict_level"] = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    findings["findings"] = [f.to_dict() for f in findings_list]
    findings["lead_count"] = lead_count(findings_list)
    findings["review_priority"] = review_priority(findings_list, score, status)

    return Report(findings=findings, findings_list=findings_list, ioc_scan=ioc_scan,
                  verified_changes=verified_changes, score=score, status=status,
                  coverage_status=coverage_status, coverage_reasons=coverage_reasons,
                  ref_dir=ref_dir)
