"""The ONE place score/status/coverage_status/verdict_level/confidence/
lead_count/review_priority get computed for the injection hunter, and
where Finding objects and the public `findings` dict are built.

Nothing here prints; nothing here scans/correlates. This module only
turns already-collected Evidence (RWX/hidden-PE/unbacked-thread/RIP-hit/
StartAddress-hit -- see dumpex/hunt/injection/models.py) into the hunter's
decision fields. `findings["rwx"]`/`hidden_pe_validated`/
`hidden_pe_unvalidated`/`threads` now hold immutable Evidence dataclasses
instead of raw Region/ThreadInfo objects (the injection Evidence
migration) -- a real, intentional change to the v1.1 dict's own field
CONTENT (never byte-frozen for these fields to begin with, see
tests/integration/test_hunt_compat_freeze.py's own module docstring), not
to its key SHAPE. This module never touches `mf` or a raw minidump object
directly -- every address was already resolved by the scan/correlation
layer that built the Evidence it reads.
"""
from dataclasses import dataclass, field

from dumpex.hunt._coverage import derive_status, derive_coverage_status
from dumpex.hunt._finding import (Finding, CONFIDENCE_LOW, CONFIDENCE_MEDIUM,
    CONFIDENCE_HIGH, TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION, overall_confidence,
    verdict_level, lead_count, review_priority)
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.injection.memory_scan import pe_hit_is_context_scoreable
from dumpex.output.coverage import (
    observe_source, build_coverage_report, CoverageLimitation, LimitationCode, SourceRequirement,
)

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.verdict_level).
_VERDICT_LEVEL_BY_SCORE = {1: "possible", 2: "likely", 3: "high"}


def _region_facts(r) -> str:
    """`r` is a dumpex.hunt.injection.models.RegionRef -- type/protect are
    already prot_str()-formatted strings, resolved once at scan time."""
    return (f"VA=0x{r.base_address:x} AllocationBase=0x{r.allocation_base:x} "
            f"size=0x{r.size:x} type={r.type} protect={r.protect}")


def _pe_facts(pe) -> str:
    """`pe` is a dumpex.hunt.injection.models.PeHeaderInfo."""
    if pe.valid:
        return (f"PE header VALID: machine={pe.machine_name} "
                f"pe32plus={pe.is_pe32_plus} sections={pe.number_of_sections} "
                f"entrypoint_rva=0x{pe.address_of_entry_point:x} "
                f"declared_image_base=0x{pe.image_base:x}")
    return f"PE header INVALID ({pe.reason})"


# The three multi-line functions below build Finding.verbose_facts --
# console/--txt --verbose-only detail (see that field's own docstring) --
# for RWX/hidden-PE/unbacked-thread. Every field they carry beyond
# _region_facts()/_pe_facts() above is file offset alone (never given to
# --json, so it lives only here, not in `facts`); this is presentation
# formatting living in aggregate.py, not hunter logic in presentation.py --
# deliberate, so presentation.py never needs a Location or these Evidence
# objects at all (see dumpex/hunt/injection/presentation.py's own module
# docstring). Each takes the Evidence dataclass directly -- its `location`
# field was already resolved by memory_scan.py/thread_scan.py (the scan
# layer that still has `mf`); aggregate.py never needs `mf` or calls
# va_to_file_offset() at all, and never needs a separate address -> Location
# lookup table (the "raw object + parallel dict" pattern this replaces).
def _rwx_verbose_fact(ev) -> str:
    r, location = ev.region, ev.location
    fo_str = f"0x{location.file_offset:x}" if location.file_offset is not None else "(not captured)"
    return (f"VA (process)=0x{r.base_address:016x} size=0x{r.size:x} "
            f"AllocationBase=0x{r.allocation_base:016x} File_offset={fo_str} "
            f"{r.protect} {r.type}")


def _hidden_pe_verbose_fact(ev) -> str:
    r, pe, location = ev.region, ev.pe, ev.location
    fo_str = f"0x{location.file_offset:x}" if location.file_offset is not None else "(not captured)"
    return (f"VA (process)=0x{r.base_address:016x} AllocationBase=0x{r.allocation_base:016x} "
            f"File_offset={fo_str} Page_type={r.type} {r.protect} "
            f"PE_machine={pe.machine_name} PE_sections={pe.number_of_sections} "
            f"Entry_point_RVA=0x{pe.address_of_entry_point:x} "
            f"Declared_ImageBase=0x{pe.image_base:x}")


def _unbacked_thread_verbose_fact(ev) -> str:
    # ev.start_address may be None (see UnbackedThreadEvidence's own
    # docstring) -- 0-substituted here for DISPLAY only, matching this
    # hunter's console text before the Evidence migration; the true value
    # (including None) is what the v2.6 record adapter actually emits.
    fo_str = f"0x{ev.location.file_offset:x}" if ev.location.file_offset is not None else "(not captured)"
    return (f"TID=0x{ev.thread_id:x} StartAddress_VA=0x{(ev.start_address or 0):016x} "
            f"File_offset={fo_str}")


@dataclass
class Report:
    """Bundles the public `findings` dict with everything presentation.py
    needs to render console detail."""
    findings: dict
    findings_list: list
    rwx: list = field(default_factory=list)
    validated_pe_hits: list = field(default_factory=list)
    mz_only_hits: list = field(default_factory=list)
    suspicious_pe_hits: list = field(default_factory=list)
    informational_pe_hits: list = field(default_factory=list)
    start_threads: list = field(default_factory=list)
    correlation: object = None
    coverage: dict = field(default_factory=dict)
    # v2.4 migration (PR2): a structured dumpex.output.coverage.CoverageReport,
    # additive alongside `coverage`/`coverage_status`/`coverage_reasons`
    # above -- NOT yet read by presentation.py or dumpex/hunt/__init__.py,
    # only by dumpex.hunt.injection.collect.collect_injection_record(). See
    # that module and docs/hunt_migration_field_matrix.md's cross-cutting
    # finding #2 for why this must be the ONE place this hunter's coverage
    # status lives on the v2.4 HunterRecord, not a second fact duplicating
    # `coverage_status` below.
    coverage_report: object = None
    score: int = 0
    status: str = None


def _split_scoreable_pe_hits(validated_pe_hits: list, rwx_and_pe_alloc_bases: set,
                              rip_hits: list, start_hits: list) -> "tuple[list, list]":
    """
    Partition validated_pe_hits (memory_scan.split_hidden_pe_hits' output —
    the FULL set, never pre-filtered) into (suspicious, informational): the
    subset that actually drives score/lead vs. the subset kept for analyst
    visibility only. A hit is scoreable if its OWN memory context already
    qualifies (memory_scan.pe_hit_is_context_scoreable — MEM_PRIVATE, or
    non-module-backed with executable protection) OR correlation.py found
    its AllocationBase sharing an RWX region or live thread execution
    (RIP/EIP or StartAddress) with something else. Example: a read-only
    MEM_MAPPED PE header is context-only by itself, but if a thread's
    CURRENT RIP executes inside that same allocation, that live-execution
    signal promotes it regardless of page type.

    correlation.py always correlates against the COMPLETE validated_pe_hits
    set (not a pre-filtered one) precisely so this promotion path stays
    available — filtering before correlation would silently make a
    genuinely-corroborated context-only PE unreachable by any score tier.
    """
    correlated_bases = (set(rwx_and_pe_alloc_bases)
                         | {hit.region.allocation_base for hit in rip_hits}
                         | {hit.region.allocation_base for hit in start_hits})
    suspicious, informational = [], []
    for h in validated_pe_hits:
        if pe_hit_is_context_scoreable(h) or h.region.allocation_base in correlated_bases:
            suspicious.append(h)
        else:
            informational.append(h)
    return suspicious, informational


def build_report(rwx: tuple, hidden_pe_scan, validated_pe_hits: tuple, mz_only_hits: tuple,
                  start_threads: tuple, thread_contexts: list,
                  correlation, memory_info_stream: bool, thread_info_stream: bool,
                  module_list_stream: bool, thread_list_stream: bool,
                  threads_total: int, contexts_parsed: int,
                  *, all_regions: list = None, thread_info_entries: list = None,
                  module_list: list = None) -> Report:
    """
    Turn already-collected Evidence + Correlation into score/status/
    coverage/Finding objects, and the public `findings` dict.
    `validated_pe_hits`/`mz_only_hits` are memory_scan.split_hidden_pe_hits(
    hidden_pe_scan)'s output — computed once by the caller (also needed by
    correlation.py) rather than re-derived here. This function takes no
    `mf`, never calls va_to_file_offset(), and never needs a separate
    address -> Location lookup table: every Evidence object it reads
    (RwxRegionEvidence/HiddenPeEvidence/UnbackedThreadEvidence/
    RipHitEvidence/StartHitEvidence, see dumpex/hunt/injection/models.py)
    already carries its own resolved `location`, built once by the scan/
    correlation layer that still has `mf` -- see
    _rwx_verbose_fact()/_hidden_pe_verbose_fact()/
    _unbacked_thread_verbose_fact()'s own comment for why that formatting
    lives here now instead of in presentation.py.

    `all_regions`/`thread_info_entries`/`module_list` are the v2.4
    migration's (PR2) structured CoverageReport's own record-count inputs
    ONLY -- keyword-only and optional (default None -> record_count stays
    unset) so this stays additive: the v1.1 `coverage`/`coverage_status`/
    `coverage_reasons` fields below never read them, only the new
    `coverage_report` field does.
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

    # Split the FULL validated-PE set into what actually drives score/lead
    # vs. what is context-only/informational — see _split_scoreable_pe_hits.
    # Correlation above already ran against the complete validated_pe_hits
    # set, so a context-only hit that turns out to share an allocation with
    # RWX or live thread execution is promoted into suspicious_pe_hits here.
    suspicious_pe_hits, informational_pe_hits = _split_scoreable_pe_hits(
        validated_pe_hits, rwx_and_pe_alloc_bases, rip_hits, start_hits)

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
    # 0          — nothing, OR the only "hidden PE" evidence is context-
    #               only (read-only MEM_MAPPED, or an unbacked MEM_IMAGE
    #               view with no execute permission and no correlated
    #               RWX/live-execution signal) — see memory_scan.
    #               `suspicious_pe_hits` (not the raw validated_pe_hits)
    #               gates this so a purely-informational PE never drives a
    #               score on its own.
    if not (rwx or suspicious_pe_hits or start_threads):
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
        allocs = sorted({f"0x{ev.region.allocation_base:x}" for ev in rwx})
        findings_list.append(Finding(
            check="injection.rwx_regions",
            facts=[_region_facts(ev.region) for ev in rwx[:20]] + (
                [f"... and {len(rwx)-20} more"] if len(rwx) > 20 else []),
            verbose_facts=[_rwx_verbose_fact(ev) for ev in rwx],
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

    if suspicious_pe_hits:
        facts = []
        for h in suspicious_pe_hits[:20]:
            facts.append(_region_facts(h.region) + "  |  " + _pe_facts(h.pe))
        if len(suspicious_pe_hits) > 20:
            facts.append(f"... and {len(suspicious_pe_hits)-20} more")
        findings_list.append(Finding(
            check="injection.hidden_pe_validated",
            facts=facts,
            verbose_facts=[_hidden_pe_verbose_fact(h) for h in suspicious_pe_hits],
            inference=f"{len(suspicious_pe_hits)} region(s) contain a structurally-valid "
                       f"PE header (DOS+COFF+optional header+full section table all "
                       f"parsed successfully) at an address absent from the module list, "
                       f"in MEM_PRIVATE memory, an executable unbacked mapping, or "
                       f"otherwise correlated with an RWX allocation or live thread "
                       f"execution.",
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

    if informational_pe_hits:
        facts = []
        for h in informational_pe_hits[:20]:
            facts.append(_region_facts(h.region) + "  |  " + _pe_facts(h.pe))
        if len(informational_pe_hits) > 20:
            facts.append(f"... and {len(informational_pe_hits)-20} more")
        findings_list.append(Finding(
            check="injection.hidden_pe_validated_context_only",
            facts=facts,
            inference=f"{len(informational_pe_hits)} region(s) contain a structurally-valid "
                       f"PE header at an address absent from the module list, but are "
                       f"read-only/non-executable mappings (e.g. MEM_MAPPED, or a "
                       f"MEM_IMAGE view with no execute permission) with no correlated "
                       f"RWX allocation or live thread execution.",
            confidence=CONFIDENCE_LOW,
            rationale="A structurally-valid PE header alone, sitting in memory with no "
                       "execute permission and not backed by MEM_PRIVATE, occurs routinely "
                       "in benign file-mapping/DLL-preview scenarios (e.g. a mapped-but-"
                       "not-executed file view) — reported for analyst awareness but NOT "
                       "counted toward the injection score unless corroborated by RWX "
                       "correlation or live execution (see injection.hidden_pe_validated "
                       "above, when present).",
            limitations=["Memory-context classification only (page type + protection); "
                         "does not by itself rule out a hidden module that is simply not "
                         "currently executing."],
            tag=TAG_OBSERVATION,
        ))

    if mz_only_hits:
        facts = []
        for h in mz_only_hits[:10]:
            facts.append(_region_facts(h.region) + "  |  " + _pe_facts(h.pe))
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
            facts=[f"TID=0x{ti.thread_id:x} StartAddress=0x{(ti.start_address or 0):x}"
                   for ti in start_threads[:20]] + (
                   [f"... and {len(start_threads)-20} more"] if len(start_threads) > 20 else []),
            verbose_facts=[_unbacked_thread_verbose_fact(ti) for ti in start_threads],
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
        for hit in rip_hits[:20]:
            full = hit.region.allocation_base in rwx_and_pe_alloc_bases
            facts.append(f"TID=0x{hit.thread_id:x} {hit.ip_reg}=0x{hit.ip:x} "
                         f"-> {_region_facts(hit.region)}  {'[FULL: RWX+validated-PE]' if full else ''}")
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
                   f"{', '.join(f'0x{r.base_address:x}({r.type}/{r.protect})' for r in (rwx_by_alloc.get(ab, ()) + pe_by_alloc.get(ab, ())))}"
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
    # dumpex.hunt.pipe for why: a nonzero score must not silently imply every
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
        "suspicious_validated_pe_hits":    suspicious_pe_hits,
        "informational_validated_pe_hits": informational_pe_hits,
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

    # ── Structured CoverageReport (v2.4 migration, PR2) ───────────────────
    # Additive: built from the SAME facts as coverage_reasons above, but
    # through dumpex.output.coverage's structured model rather than a
    # hand-written string list -- never parsed back out of coverage_reasons
    # itself (see docs/hunt_migration_field_matrix.md's own migration rule).
    # "modules"/"thread_context" absence reuse the module_classification/
    # thread_context codes below via SourceRequirement, so a hunter never
    # hand-builds a SOURCE_ABSENT-shaped limitation itself; only the two
    # genuine business facts this reducer cannot infer from source state
    # alone (a partial hidden-PE scan, a partially-parsed thread-context
    # set) are hand-built CoverageLimitations.
    #
    # "memory_info"/"thread_info" are BOTH in evaluation_sources (so the
    # hunter is NOT_EVALUATED only when EVERY one of them is absent,
    # matching this hunter's own `evaluated = memory_info_stream or
    # thread_info_stream` above) AND in completeness_checks (so a SINGLE
    # one being absent -- the OTHER still present -- still produces a
    # PARTIAL-triggering limitation for it, matching `complete`'s own
    # `memory_info_stream and thread_info_stream and ...` AND-of-all-four
    # rule above). Omitting them from completeness_checks was a confirmed
    # regression: a memory_info-only-absent (or thread_info-only-absent)
    # dump would otherwise report coverage.status="complete" here while
    # `coverage_status` above (still correctly) says "partial" -- exactly
    # the two-sources-of-truth bug this migration exists to avoid.
    coverage_sources = {
        "memory_info":    observe_source("memory_info", present=coverage["memory_info_stream"],
                                          items=all_regions),
        "thread_info":    observe_source("thread_info", present=coverage["thread_info_stream"],
                                          items=thread_info_entries),
        "modules":        observe_source("modules", present=coverage["module_list_stream"],
                                          items=module_list),
        # Informational only, like `coverage["thread_list_stream"]` in the
        # v1.1 dict above -- neither this hunter's `complete`/`evaluated`
        # computation nor its coverage_reasons ever gates on
        # thread_list_stream by itself (see this function's own `complete`
        # expression), so no completeness_check is attached to it either;
        # it exists here purely so a v2.4 consumer can see this source's
        # real state, matching the informational fact the v1.1 dict
        # already carried under a different key.
        "thread_list":    observe_source("thread_list", present=thread_list_stream,
                                          items=list(range(threads_total))),
        "thread_context": observe_source("thread_context", present=coverage["thread_context"],
                                          items=thread_contexts),
        # Not an optional minidump stream -- the hidden-PE header scan
        # itself always ran by this point; this source only exists so
        # PE_HEADER_READ_FAILED/_SHORT_READ have a source key to validate
        # against (see build_coverage_report's own unknown-source check).
        "hidden_pe_scan": observe_source("hidden_pe_scan", present=True, items=["scanned"]),
    }
    # Order matches the v1.1 `coverage_reasons` list above exactly (memory_
    # info, thread_info, modules, PE read-failed, PE short-read, THEN
    # thread_context) -- confirmed regression in an earlier draft: thread_
    # context's SourceRequirement was listed BEFORE the PE checks, so a
    # dump hitting both a PE short-read AND a fully-absent thread_context
    # produced limitations in the opposite order from coverage_reasons
    # (thread_context first, PE second) for the exact same underlying
    # facts. A consumer reading `coverage.reasons` (rendered from
    # `limitations`, see CoverageReport.reasons) must see the same order
    # as `coverage_reasons` for identical input.
    coverage_completeness_checks = [
        "memory_info",
        "thread_info",
        SourceRequirement(source="modules",
                          absent_code=LimitationCode.MODULE_CLASSIFICATION_UNAVAILABLE),
    ]
    if hidden_pe_scan.read_failed:
        coverage_completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_READ_FAILED, source="hidden_pe_scan",
            affected_count=hidden_pe_scan.read_failed))
    if hidden_pe_scan.short_reads:
        coverage_completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PE_HEADER_SHORT_READ, source="hidden_pe_scan",
            affected_count=hidden_pe_scan.short_reads))
    coverage_completeness_checks.append(
        SourceRequirement(source="thread_context",
                          absent_code=LimitationCode.THREAD_CONTEXT_UNAVAILABLE))
    if coverage["thread_context"] and coverage["contexts_missing"]:
        coverage_completeness_checks.append(CoverageLimitation(
            code=LimitationCode.THREAD_CONTEXT_PARTIAL, source="thread_context",
            affected_count=coverage["contexts_missing"]))
    coverage_report = build_coverage_report(
        coverage_sources, evaluation_sources=("memory_info", "thread_info"),
        completeness_checks=coverage_completeness_checks)

    return Report(findings=findings, findings_list=findings_list, rwx=rwx,
                   validated_pe_hits=validated_pe_hits, mz_only_hits=mz_only_hits,
                   suspicious_pe_hits=suspicious_pe_hits, informational_pe_hits=informational_pe_hits,
                   start_threads=start_threads, correlation=correlation,
                   coverage=coverage, coverage_report=coverage_report, score=score, status=status)
