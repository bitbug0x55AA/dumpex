"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the injection hunter, and
where Finding objects and the public `findings` dict are built.

Nothing here prints; nothing here scans/correlates. This module only
turns already-collected facts (RWX regions, a HiddenPeScan, unbacked
threads, thread contexts, a Correlation) into the hunter's decision
fields. `findings["rwx"]`/`hidden_pe_validated`/`hidden_pe_unvalidated`/
`threads` keep holding raw Region/ThreadInfo objects exactly as the
single-file hunter did — this split changes structure only, not the
JSON shape (see dumpex/hunt/injection/__init__.py's docstring for the
explicit compatibility contract this preserves).
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority)
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.verdict_level).
_VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "likely", 3: "high"}


def _region_facts(r) -> str:
    return (f"VA=0x{r.BaseAddress:x} AllocationBase=0x{r.AllocationBase:x} "
            f"size=0x{r.RegionSize:x} type={prot_str(r.Type)} protect={prot_str(r.Protect)}")


def _pe_facts(pe: dict) -> str:
    if pe['valid']:
        return (f"PE header VALID: machine={pe['machine_name']} "
                f"pe32plus={pe['is_pe32_plus']} sections={pe['number_of_sections']} "
                f"entrypoint_rva=0x{pe['address_of_entry_point']:x} "
                f"declared_image_base=0x{pe['image_base']:x}")
    return f"PE header INVALID ({pe['reason']})"


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail."""
    findings: dict
    findings_list: list
    rwx: list = field(default_factory=list)
    validated_pe_hits: list = field(default_factory=list)
    mz_only_hits: list = field(default_factory=list)
    start_threads: list = field(default_factory=list)
    correlation: object = None
    coverage: dict = field(default_factory=dict)
    score: int = 0
    status: str = None


def build_report(rwx: list, hidden_pe_scan, validated_pe_hits: list, mz_only_hits: list,
                  start_threads: list, thread_contexts: list,
                  correlation, memory_info_stream: bool, thread_info_stream: bool,
                  module_list_stream: bool, thread_list_stream: bool,
                  threads_total: int, contexts_parsed: int) -> Report:
    """
    Turn already-collected scan/correlation facts into score/status/
    coverage/Finding objects, and the public `findings` dict.
    `validated_pe_hits`/`mz_only_hits` are memory_scan.split_hidden_pe_hits(
    hidden_pe_scan)'s output — computed once by the caller (also needed by
    correlation.py) rather than re-derived here.
    """
    coverage = {
        "memory_info_stream": memory_info_stream,
        "thread_info_stream": thread_info_stream,
        "module_list_stream": module_list_stream,
        "thread_list_stream": thread_list_stream,
    }
    coverage["thread_context"] = bool(thread_contexts)
    contexts_missing = max(0, threads_total - contexts_parsed)
    coverage["threads_total"]    = threads_total
    coverage["contexts_parsed"]  = contexts_parsed
    coverage["contexts_missing"] = contexts_missing

    evaluated = coverage["memory_info_stream"] or coverage["thread_info_stream"]
    # RIP/EIP correlation is the ONLY path to the HIGH (3/3) tier (see
    # scoring below) — a dump where thread contexts are missing or only
    # partially parsed cannot rule out a live-execution correlation that
    # simply wasn't observable, so that gap must count against
    # completeness the same way a missing/partial stream does, not be
    # treated as "nothing to check here".
    complete = (coverage["memory_info_stream"] and coverage["thread_info_stream"]
                and coverage["module_list_stream"] and hidden_pe_scan.read_failed == 0
                and hidden_pe_scan.short_reads == 0
                and coverage["thread_context"] and coverage["contexts_missing"] == 0)

    rwx_and_pe_alloc_bases = correlation.rwx_and_pe_alloc_bases
    rip_hits               = correlation.rip_hits
    rip_full_correlation   = correlation.rip_full_correlation
    start_hits              = correlation.start_hits
    rwx_by_alloc            = correlation.rwx_by_alloc
    pe_by_alloc             = correlation.pe_by_alloc

    # ── Score ────────────────────────────────────────────────────────────
    # 3 (HIGH)   — a thread's CURRENT RIP/EIP executes inside an allocation
    #               that structurally carries BOTH RWX protection AND a
    #               validated hidden PE header: page type + PE validation +
    #               live execution all converge on one AllocationBase.
    # 2 (MEDIUM) — same-allocation structural correlation (RWX + validated
    #               PE) without confirmed live execution, OR a thread's
    #               current RIP/EIP executing inside a suspicious
    #               allocation with only one signal, OR StartAddress-only
    #               correlation.
    # 1 (LOW)    — raw signals exist but never share an allocation and no
    #               thread (by RIP or StartAddress) executes inside one.
    # 0          — nothing.
    if not (rwx or validated_pe_hits or start_threads):
        score = 0
    elif rip_full_correlation:
        score = 3
    elif rwx_and_pe_alloc_bases or rip_hits or start_hits:
        score = 2
    else:
        score = 1

    status = derive_status(evaluated, score > 0, complete)

    # ── Findings (facts / inference / confidence / rationale / limitations) ──
    findings_list = []

    if rwx:
        allocs = sorted({f"0x{r.AllocationBase:x}" for r in rwx})
        findings_list.append(Finding(
            check="injection.rwx_regions",
            facts=[_region_facts(r) for r in rwx[:20]] + (
                [f"... and {len(rwx)-20} more"] if len(rwx) > 20 else []),
            inference=f"{len(rwx)} memory region(s) carry PAGE_EXECUTE_READWRITE/"
                       f"WRITECOPY protection, spanning {len(allocs)} distinct allocation(s).",
            confidence=CONFIDENCE_MEDIUM,
            rationale="RWX is a directly-observed page protection flag, not a heuristic "
                       "guess — but RWX alone is routinely used by JITs, debuggers, and "
                       "some legitimate packers, so it is a lead, not proof, until "
                       "corroborated by a validated PE header and/or live execution in "
                       "the same allocation.",
            limitations=["Does not by itself distinguish injection from JIT/legitimate "
                         "self-modifying-code use cases."],
            tag=TAG_LEAD,
        ))

    if validated_pe_hits:
        facts = []
        for h in validated_pe_hits[:20]:
            facts.append(_region_facts(h["region"]) + "  |  " + _pe_facts(h["pe"]))
        if len(validated_pe_hits) > 20:
            facts.append(f"... and {len(validated_pe_hits)-20} more")
        findings_list.append(Finding(
            check="injection.hidden_pe_validated",
            facts=facts,
            inference=f"{len(validated_pe_hits)} region(s) contain a structurally-valid "
                       f"PE header (DOS+COFF+optional header+full section table all "
                       f"parsed successfully) at an address absent from the module list.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="Passing full structural PE validation (not just an 'MZ' prefix) "
                       "rules out coincidental bytes and most decoys, but a valid header "
                       "outside the module list can also occur from a manually-mapped "
                       "but otherwise benign in-process library (e.g. some anti-cheat/DRM "
                       "loaders) — confidence rises to HIGH only when a thread's live "
                       "RIP/EIP actually executes inside the same allocation.",
            limitations=[f"Header validation read is capped at {PE_VALIDATE_READ_MAX} bytes; "
                         "a section table extending past that reports as invalid rather "
                         "than being partially trusted."],
            tag=TAG_LEAD,
        ))

    if mz_only_hits:
        facts = []
        for h in mz_only_hits[:10]:
            facts.append(_region_facts(h["region"]) + "  |  " + _pe_facts(h["pe"]))
        if len(mz_only_hits) > 10:
            facts.append(f"... and {len(mz_only_hits)-10} more")
        findings_list.append(Finding(
            check="injection.mz_prefix_unvalidated",
            facts=facts,
            inference=f"{len(mz_only_hits)} region(s) begin with the 2-byte 'MZ' prefix "
                       f"but fail structural PE header validation.",
            confidence=CONFIDENCE_LOW,
            rationale="Two matching bytes is extremely weak evidence on its own — this "
                       "is reported for analyst awareness (a truncated read, a genuine "
                       "decoy header, or a non-PE structure that happens to start with "
                       "'MZ' are all more likely explanations than a hidden module) and "
                       "is NOT counted toward the injection score.",
            limitations=["Not corroborated by section-table/entry-point validation; "
                         "treat as informational only."],
            tag=TAG_OBSERVATION,
        ))

    if start_threads:
        findings_list.append(Finding(
            check="injection.unbacked_thread_startaddress",
            facts=[f"TID=0x{ti.ThreadId:x} StartAddress=0x{(ti.StartAddress or 0):x}"
                   for ti in start_threads[:20]] + (
                   [f"... and {len(start_threads)-20} more"] if len(start_threads) > 20 else []),
            inference=f"{len(start_threads)} thread(s) began execution at an address not "
                       f"covered by any known module.",
            confidence=CONFIDENCE_LOW,
            rationale="StartAddress records where a thread BEGAN, not where it is "
                       "executing now — a thread can legitimately start inside "
                       "unbacked/JIT memory (e.g. a thread pool worker routine passed "
                       "as a raw function pointer into private memory) and still be "
                       "benign. Current RIP/EIP (below, when available) is the stronger "
                       "signal for what a thread is actually doing.",
            limitations=[],
            tag=TAG_LEAD,
        ))

    if not coverage["thread_context"]:
        findings_list.append(Finding(
            check="injection.rip_correlation_unavailable",
            facts=[f"thread_list_stream_present={coverage['thread_list_stream']}"],
            inference="No per-thread CONTEXT (RIP/EIP) could be read from this dump — "
                       "live-execution correlation could not run.",
            confidence=CONFIDENCE_LOW,
            rationale="Coverage gap, not a negative result: a suspicious allocation with "
                       "no RIP correlation available cannot be distinguished from one "
                       "that was checked and found not currently executing.",
            limitations=["Injection score cannot reach HIGH (3) in this run regardless "
                         "of other signals, since live-execution confirmation is the "
                         "only path to that tier."],
            tag=TAG_OBSERVATION,
        ))
    elif rip_hits:
        facts = []
        for tc, r in rip_hits[:20]:
            full = r.AllocationBase in rwx_and_pe_alloc_bases
            facts.append(f"TID=0x{tc['ThreadId']:x} {tc['ip_reg']}=0x{tc['ip']:x} "
                         f"-> {_region_facts(r)}  {'[FULL: RWX+validated-PE]' if full else ''}")
        if len(rip_hits) > 20:
            facts.append(f"... and {len(rip_hits)-20} more")
        conf = CONFIDENCE_HIGH if rip_full_correlation else CONFIDENCE_MEDIUM
        findings_list.append(Finding(
            check="injection.allocation_correlation",
            facts=facts,
            inference=(f"{len(rip_full_correlation)} thread(s) currently execute inside "
                        f"an allocation that is simultaneously RWX and hosts a validated "
                        f"hidden PE — page type, structural PE validation, and live "
                        f"RIP/EIP all converge on the same AllocationBase."
                        if rip_full_correlation else
                        f"{len(rip_hits)} thread(s) currently execute inside an "
                        f"allocation carrying at least one suspicious signal (RWX or a "
                        f"validated hidden PE), but not both at once."),
            confidence=conf,
            rationale=("This is the strongest evidence this hunter can produce: the "
                       "process is, at the moment of the dump, actively running code "
                       "from an allocation with no legitimate module backing and a "
                       "concealed PE image."
                       if rip_full_correlation else
                       "Live execution inside a flagged allocation is meaningful, but "
                       "only one structural signal (not both RWX and a validated PE) "
                       "was present in that allocation."),
            limitations=["RIP is a single-point-in-time snapshot; a thread that executed "
                         "there moments before or after the dump was captured would not "
                         "appear here."],
            tag=TAG_DETECTION if rip_full_correlation else TAG_LEAD,
        ))

    if rwx_and_pe_alloc_bases and not rip_full_correlation:
        findings_list.append(Finding(
            check="injection.structural_allocation_correlation",
            facts=[f"AllocationBase=0x{ab:x}  regions="
                   f"{', '.join(f'0x{r.BaseAddress:x}({prot_str(r.Type)}/{prot_str(r.Protect)})' for r in (rwx_by_alloc.get(ab, []) + pe_by_alloc.get(ab, [])))}"
                   for ab in sorted(rwx_and_pe_alloc_bases)],
            inference=f"{len(rwx_and_pe_alloc_bases)} allocation(s) carry BOTH an RWX "
                       f"sub-region AND a validated hidden PE header, without a "
                       f"currently-observed thread executing inside them.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="Same-allocation structural correlation is stronger than either "
                       "signal alone, but without a live RIP/EIP inside the allocation "
                       "this cannot be elevated to HIGH confidence — the code may not "
                       "(yet, or ever, at dump time) have been executed.",
            limitations=[] if coverage["thread_context"] else
                        ["RIP/EIP correlation could not run at all in this dump (see "
                         "injection.rip_correlation_unavailable) — this may understate "
                         "the true confidence."],
            tag=TAG_LEAD,
        ))

    # Coverage tracked independently of status/score — see dumpex.hunt.stomping /
    # pipe.py for why: a nonzero score must not silently imply every
    # region/thread was checked.
    coverage_reasons = []
    if not coverage["memory_info_stream"]:
        coverage_reasons.append("MemoryInfoListStream missing from this dump")
    if not coverage["thread_info_stream"]:
        coverage_reasons.append("ThreadInfoListStream missing from this dump")
    if not coverage["module_list_stream"]:
        coverage_reasons.append("ModuleListStream missing from this dump")
    if hidden_pe_scan.read_failed:
        coverage_reasons.append(f"{hidden_pe_scan.read_failed} region(s) failed to read while checking "
                                 f"for hidden PE headers")
    if hidden_pe_scan.short_reads:
        coverage_reasons.append(f"{hidden_pe_scan.short_reads} region(s) returned fewer bytes than "
                                 f"requested while checking for hidden PE headers "
                                 f"(short read) — not fully examined")
    if not coverage["thread_context"]:
        coverage_reasons.append("No per-thread CONTEXT (RIP/EIP) available — live-execution "
                                 "correlation could not run")
    elif coverage["contexts_missing"]:
        coverage_reasons.append(f"{coverage['contexts_missing']}/{coverage['threads_total']} "
                                 f"thread(s) had no parsed CONTEXT — live-execution correlation "
                                 f"ran, but not for every thread")
    coverage_status = derive_coverage_status(evaluated, complete)

    findings = {
        "rwx":                  rwx,
        "hidden_pe_validated":  validated_pe_hits,
        "hidden_pe_unvalidated": mz_only_hits,
        "threads":              start_threads,
        "thread_contexts":      thread_contexts,
        "rwx_and_pe_alloc_bases":  sorted(rwx_and_pe_alloc_bases),
        "rip_hits":             rip_hits,
        "rip_full_correlation": rip_full_correlation,
        "start_hits":           start_hits,
        "score":                score,
        "max_score":            3,
        "status":               status,
        "coverage":             coverage,
        "coverage_status":      coverage_status,
        "coverage_reasons":     coverage_reasons,
        "confidence":           overall_confidence(findings_list, score),
        "verdict_level":        verdict_level(score, _VERDICT_LEVEL_BY_SCORE, status=status),
        "pe_read_failed":       hidden_pe_scan.read_failed,
        "pe_short_reads":       hidden_pe_scan.short_reads,
        "findings":             [f.to_dict() for f in findings_list],
        "lead_count":           lead_count(findings_list),
        "review_priority":      review_priority(findings_list, score, status),
    }

    return Report(findings=findings, findings_list=findings_list, rwx=rwx,
                   validated_pe_hits=validated_pe_hits, mz_only_hits=mz_only_hits,
                   start_threads=start_threads, correlation=correlation,
                   coverage=coverage, score=score, status=status)
