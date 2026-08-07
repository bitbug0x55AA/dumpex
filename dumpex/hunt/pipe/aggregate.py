"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the pipe hunter, and where
Finding objects and the public `findings` dict are built.

Nothing here prints; nothing here scans/correlates. This module only
turns already-collected facts (a HandleScan, a PipeNameScan, a
CorrelationResult) into the hunter's decision fields.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import va_to_file_offset, prot_str
from dumpex.hunt._ui import INCONCLUSIVE
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority)
from dumpex.hunt.pipe.config import PIPE_CONTEXT_DISTANCE

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.verdict_level).
_VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "likely", 3: "high"}


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail."""
    findings: dict
    findings_list: list
    handle_scan: object = None
    pipe_name_scan: object = None
    correlation: object = None
    handle_stream_available: bool = False
    evaluated: bool = False
    score: int = 0
    status: str = None
    coverage_status: str = None
    coverage_reasons: list = field(default_factory=list)
    coverage_report: object = None   # dumpex.output.coverage.CoverageReport (v2.4 migration only)
    verdict_reason: str = ""


def build_report(mf, handle_scan, pipe_name_scan, correlation, mem_info_available: bool,
                  handle_stream_available: bool, rule_version: "str | None" = None) -> Report:
    findings = {
        "handle_pipes":    handle_scan.handle_classified,
        "private_pipes":   pipe_name_scan.private_pipes,
        "c2_context":      correlation.c2_hits,
        "framework_pipes": handle_scan.framework_handle_hits,
        "unbacked_in_rgn": correlation.unbacked_in_pipe_rgn,
        "score": 0,
    }
    findings_list = []

    handle_pipe_hits = handle_scan.handle_pipe_hits
    handle_classified = handle_scan.handle_classified
    framework_handle_hits = handle_scan.framework_handle_hits
    private_pipes = pipe_name_scan.private_pipes
    corroborated_handles = correlation.corroborated_handles
    start_addr_leads = correlation.start_addr_leads

    # ── Finding: open pipe handles (primary, scored path's raw material) ──
    if handle_stream_available and handle_pipe_hits:
        findings_list.append(Finding(
            check="pipe.open_handles",
            facts=[f"Handle=0x{hc['handle'].Handle:x} ObjectName={hc['handle'].ObjectName} "
                   f"GrantedAccess=0x{hc['handle'].GrantedAccess:x}"
                   + (f"  [framework={hc['framework_match'][0]}]" if hc["framework_match"] else "")
                   for hc in handle_classified[:20]] + (
                   [f"... and {len(handle_classified)-20} more"] if len(handle_classified) > 20 else []),
            # Full, uncapped -- facts above is capped at 20 for --json
            # (a sentinel entry, not a real "this is everything" claim);
            # every field it carries per handle is already complete, so the
            # only delta verbose_facts provides is completeness.
            verbose_facts=[f"Handle=0x{hc['handle'].Handle:x} ObjectName={hc['handle'].ObjectName} "
                           f"GrantedAccess=0x{hc['handle'].GrantedAccess:x}"
                           + (f"  [framework={hc['framework_match'][0]}]" if hc["framework_match"] else "")
                           for hc in handle_classified],
            inference=f"Process holds {len(handle_pipe_hits)} open handle(s) to named "
                       f"pipe object(s), per HandleDataStream.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="HandleDataStream is the OS's own record of what this process "
                       "actually has open — far stronger than a bare string match, but "
                       "having ANY pipe handle open is completely ordinary for most "
                       "Windows processes (IPC, RPC, print spooler, etc.); only a "
                       "handle whose name matches a known C2/lateral-movement framework "
                       "convention, or one corroborated by nearby C2 context / active "
                       "execution, is treated as a detection.",
            limitations=["Presence of a pipe handle is not inherently suspicious."],
            tag=TAG_OBSERVATION,
        ))

    # ── Finding: handle name matches a known framework convention ─────────
    if framework_handle_hits:
        facts = []
        mitre_ids = []
        for hc in framework_handle_hits:
            h = hc["handle"]
            fw, tech, mitre = hc["framework_match"]
            facts.append(f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} "
                         f"framework={fw} technique={tech} mitre={mitre}")
            if mitre and mitre not in mitre_ids:
                mitre_ids.append(mitre)
        findings_list.append(Finding(
            check="pipe.handle_framework_match",
            facts=facts,
            inference=f"{len(framework_handle_hits)} open pipe handle(s) match a known "
                       f"C2/lateral-movement framework naming convention.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="An OS-confirmed open handle (not just a string sitting in memory) "
                       "whose name matches a specific, narrow framework convention "
                       "(e.g. Cobalt Strike's msagent_/postex_ or PsExec's psexesvc) is "
                       "meaningfully unlikely to be coincidental — raised to HIGH only "
                       "when further corroborated (see pipe.corroboration below).",
            limitations=["Framework pipe-name conventions can be renamed/customized by an "
                         "operator; absence of a match does not mean absence of C2."],
            tag=TAG_DETECTION,
            # Real ATT&CK IDs from rules.yaml's own framework_pipes entries;
            # rule_version is the loaded ruleset's own CONTENT hash (not
            # rules.yaml's top-level "version:" FORMAT field -- see
            # __init__.py's own RULE_VERSION comment for why) -- neither is
            # invented here (see this hunter's own KNOWN_FRAMEWORK_PIPES in
            # dumpex/hunt/pipe/__init__.py and rules.yaml's own comments).
            technique_ids=mitre_ids,
            rule_version=rule_version,
        ))

    # ── Finding: string-scan lead (unscored) ──────────────────────────────
    if private_pipes:
        facts = []
        for hit in private_pipes[:15]:
            r = hit["region"]
            abs_va = r.BaseAddress + hit["offset"]
            fo = va_to_file_offset(mf, abs_va)
            fo_str = f"0x{fo:x}" if fo is not None else "(not captured)"
            facts.append(f"VA=0x{abs_va:x} file_offset={fo_str} name={hit['name'].strip()!r} "
                         f"region_type={prot_str(r.Type)}")
        if len(private_pipes) > 15:
            facts.append(f"... and {len(private_pipes)-15} more")
        findings_list.append(Finding(
            check="pipe.string_scan_lead",
            facts=facts,
            inference=f"{len(private_pipes)} occurrence(s) of a '\\pipe\\' name found in "
                       f"non-system-DLL memory via byte-pattern scan.",
            confidence=CONFIDENCE_LOW,
            rationale="A string match proves only that these bytes exist somewhere in "
                       "memory — not that any handle was ever opened by that name, nor "
                       "that the name isn't leftover/freed heap data or an unrelated "
                       "buffer. Reported as a lead for the analyst and to locate regions "
                       "for C2-context/execution correlation; does NOT contribute to the "
                       "pipe score on its own.",
            limitations=["Not corroborated by HandleDataStream."] if not handle_stream_available
                        else ["No corresponding open handle found for this exact name."],
            tag=TAG_LEAD,
        ))

    # ── Finding: handle corroborated by C2 context and/or live execution ──
    if corroborated_handles:
        facts = []
        for entry in corroborated_handles[:10]:
            h, sh, pipe_va = entry["hc"]["handle"], entry["string_hit"], entry["pipe_va"]
            f = f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} pipe_va=0x{pipe_va:x}"
            if entry["nearby_c2"]:
                rec = entry["nearby_c2"][0]
                distance = abs(rec["va"] - pipe_va)
                same_page = (rec["va"] // 0x1000) == (pipe_va // 0x1000)
                f += (f"  c2_va=0x{rec['va']:x} c2_match={rec['match']!r} "
                      f"distance=0x{distance:x} same_page={same_page}")
            if entry["rip_hit"]:
                tc = entry["rip_hit"]
                distance = abs(tc["ip"] - pipe_va)
                same_page = (tc["ip"] // 0x1000) == (pipe_va // 0x1000)
                f += (f"  live_rip=TID:0x{tc['ThreadId']:x}@{tc['ip_reg']}=0x{tc['ip']:x} "
                      f"distance=0x{distance:x} same_page={same_page}")
            facts.append(f)
        # HIGH only when at least one corroborated handle has BOTH nearby
        # C2 context AND a nearby RIP/EIP hit at once (the score=3 case
        # below) — a Finding's confidence must track what actually
        # justified it, not be uniformly HIGH regardless of whether one or
        # both signals fired.
        full_corroboration = any(e["nearby_c2"] and e["rip_hit"] for e in corroborated_handles)
        findings_list.append(Finding(
            check="pipe.corroboration",
            facts=facts,
            inference=f"{len(corroborated_handles)} open pipe handle(s) are corroborated "
                       f"by C2-style context and/or live RIP/EIP execution within "
                       f"±{PIPE_CONTEXT_DISTANCE} bytes of a matching pipe-name string's "
                       f"own address.",
            confidence=CONFIDENCE_HIGH if full_corroboration else CONFIDENCE_MEDIUM,
            rationale=("Combines an OS-confirmed open handle with BOTH independent memory "
                       "signals (C2 artifacts AND live execution), both within "
                       f"{PIPE_CONTEXT_DISTANCE} bytes of that pipe's name string — the "
                       "strongest correlation this hunter can produce." if full_corroboration else
                       "Combines an OS-confirmed open handle with ONE independent memory "
                       "signal (C2 artifacts or live execution, not both) within "
                       f"{PIPE_CONTEXT_DISTANCE} bytes of that pipe's name string."),
            limitations=["Name correlation between a handle's ObjectName and a string scan "
                         "hit uses exact match on the canonicalized pipe name (prefix "
                         "stripped, casefolded) — still not a cryptographic guarantee both "
                         "refer to the identical kernel object if the process has multiple "
                         "same-named pipe instances.",
                         f"Proximity window is ±{PIPE_CONTEXT_DISTANCE} bytes, not a proof of "
                         "logical association — an unrelated string or thread could "
                         "coincidentally fall within that window in a dense region."],
            tag=TAG_DETECTION,
        ))

    # ── Finding: StartAddress-only proximity (lead, never scored) ─────────
    if start_addr_leads:
        facts = []
        for entry in start_addr_leads[:15]:
            h, ti, pipe_va = entry["hc"]["handle"], entry["thread_info"], entry["pipe_va"]
            sa = ti.StartAddress or 0
            distance = abs(sa - pipe_va)
            same_page = (sa // 0x1000) == (pipe_va // 0x1000)
            facts.append(f"Handle=0x{h.Handle:x} ObjectName={h.ObjectName} pipe_va=0x{pipe_va:x} "
                         f"TID=0x{ti.ThreadId:x} StartAddr=0x{sa:x} distance=0x{distance:x} "
                         f"same_page={same_page}")
        if len(start_addr_leads) > 15:
            facts.append(f"... and {len(start_addr_leads)-15} more")
        findings_list.append(Finding(
            check="pipe.start_address_proximity_lead",
            facts=facts,
            inference=f"{len(start_addr_leads)} handle-confirmed pipe(s) have an unbacked "
                       f"thread whose StartAddress (not current RIP/EIP) falls within "
                       f"±{PIPE_CONTEXT_DISTANCE} bytes of the pipe name string.",
            confidence=CONFIDENCE_LOW,
            rationale="StartAddress records where a thread BEGAN, not where it is executing "
                       "now — unlike a live RIP/EIP hit, this is not evidence the thread is "
                       "currently doing anything related to the pipe. Reported as a lead "
                       "only and does NOT contribute to the pipe score.",
            limitations=["Superseded by pipe.corroboration whenever a live RIP/EIP hit is "
                         "also present for the same handle — this only appears when no RIP "
                         "hit was found."],
            tag=TAG_LEAD,
        ))

    # ── Score / Verdict ───────────────────────────────────────────────────
    # 0 — string leads / a generic open handle only.
    # 1 — a handle-confirmed pipe matches a known C2/lateral-movement
    #     framework naming convention (OS-confirmed usage + specific name),
    #     even with no further corroboration.
    # 2 — ANY handle-confirmed pipe (framework-matched or not) is
    #     corroborated by C2-style context OR live RIP/EIP execution
    #     within PIPE_CONTEXT_DISTANCE of the same-named string occurrence.
    # 3 — corroborated by BOTH at once, within that same distance window.
    #
    # Deliberately NOT gated on framework_match for tiers 2-3: a
    # same-named handle actively corroborated by nearby C2 context or live
    # execution is strong evidence on its own (an OS-confirmed handle PLUS
    # independent, PROXIMATE memory evidence), and requiring a
    # framework-name match on top of that would silently downgrade a
    # genuinely corroborated custom/non-framework pipe to a Finding the
    # score doesn't reflect — exactly the Finding/verdict mismatch this
    # scoring model exists to avoid. StartAddress proximity never
    # contributes here — see pipe.start_address_proximity_lead.
    score = 0
    if framework_handle_hits:
        score = 1
    for entry in corroborated_handles:
        if entry["nearby_c2"] and entry["rip_hit"]:
            score = max(score, 3)
        elif entry["nearby_c2"] or entry["rip_hit"]:
            score = max(score, 2)

    findings["score"] = score
    findings["max_score"] = 3

    coverage_counts = pipe_name_scan.coverage_counts
    c2_budget = pipe_name_scan.c2_budget
    pipe_name_budget = pipe_name_scan.pipe_name_budget
    c2_exhausted   = c2_budget.exhausted()
    name_exhausted = pipe_name_budget.exhausted()
    budget_exhausted = c2_exhausted or name_exhausted
    findings["budget_exhausted"] = budget_exhausted
    findings["scan_complete"] = coverage_counts.complete and not budget_exhausted
    findings["findings"] = [f.to_dict() for f in findings_list]

    # Coverage is tracked independently of status/score, so "DETECTED but
    # coverage was partial" stays representable rather than a nonzero
    # score silently implying every region/handle was checked.
    coverage_reasons = []
    if not mem_info_available:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if not handle_stream_available:
        coverage_reasons.append("HandleDataStream missing from this dump (needs "
                                 "MiniDumpWithHandleData) — the primary, scored "
                                 "pipe-handle check could not run")
    coverage_reasons.extend(coverage_counts.build_reasons(
        oversize_label="oversized region(s) skipped",
        read_failed_label="region(s) failed to read",
        short_read_label="region(s) returned fewer bytes than declared (short read) — "
                          "not fully scanned",
    ))
    if c2_exhausted:
        coverage_reasons.append(f"C2-context scan budget exhausted ({c2_budget.exhausted_reason})")
    if name_exhausted:
        coverage_reasons.append(f"pipe-name scan budget exhausted ({pipe_name_budget.exhausted_reason})")

    evaluated = mem_info_available or handle_stream_available
    # The PRIMARY (scored) check may not have run at all (no
    # HandleDataStream) or ran incompletely — a negative score here must
    # not be read the same as "checked and clean".
    complete  = handle_stream_available and coverage_counts.complete and not budget_exhausted
    coverage_status = derive_coverage_status(evaluated, complete)
    findings["coverage_status"]  = coverage_status
    findings["coverage_reasons"] = coverage_reasons

    status = derive_status(evaluated, score > 0, complete)
    findings["status"] = status
    findings["verdict_level"] = verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status)
    findings["confidence"] = overall_confidence(findings_list, score)
    findings["lead_count"] = lead_count(findings_list)
    findings["review_priority"] = review_priority(findings_list, score, status)

    # The ONLY place the verdict's explanatory text is assembled, from the
    # SAME coverage_reasons list findings["coverage_reasons"] holds — a
    # prior version had presentation.py re-derive a separate, narrower
    # reason string from raw coverage_counts/budget objects for two of
    # these three branches, which could silently drop a real gap (e.g.
    # HandleDataStream missing AND a short-read/budget-exhaustion gap
    # co-occurring: the console showed only the HandleDataStream note
    # while --json's coverage_reasons already had both). Computing it once
    # here means console and JSON can no longer drift apart.
    if not evaluated:
        verdict_reason = ("; ".join(coverage_reasons)
                           or "MemoryInfoListStream and HandleDataStream both missing from this dump")
    elif not handle_stream_available:
        verdict_reason = ("; ".join(coverage_reasons)
                           + " — only unscored string leads are available above")
    elif status == INCONCLUSIVE:
        verdict_reason = "; ".join(coverage_reasons) or "partial coverage"
    else:
        verdict_reason = ""

    return Report(findings=findings, findings_list=findings_list, handle_scan=handle_scan,
                   pipe_name_scan=pipe_name_scan, correlation=correlation,
                   handle_stream_available=handle_stream_available, evaluated=evaluated,
                   score=score, status=status,
                   coverage_status=coverage_status, coverage_reasons=coverage_reasons,
                   verdict_reason=verdict_reason)
