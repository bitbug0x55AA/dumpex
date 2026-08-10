"""The ONE place score/coverage/CheckResult/InjectionReport get computed
for the injection hunter.

Nothing here prints; nothing here scans/correlates. This module only turns
already-collected Evidence (RWX/hidden-PE/unbacked-thread/RIP-hit/
StartAddress-hit -- see dumpex/hunt/injection/models.py) and the
correlation result into `dumpex.hunt.injection.domain.InjectionReport`: a
`score`, a `CoverageSnapshot`, an `InjectionEvidence` bundle, and the
`CheckResult` tuple that explains them. Every projection (legacy v1.1
dict, current-schema HunterRecord, verdict-first console) is a pure
function of that ONE `InjectionReport` -- see `report_facts.py`/
`report_legacy.py`/`report_record.py`/`report_console.py`. This module
never builds a `dumpex.hunt._finding.Finding`, never formats a fact string
(that is `report_facts.py`'s job, applied identically for every
projection), and never touches `mf` or a raw minidump object directly --
every address was already resolved by the scan/correlation layer that
built the Evidence it reads.
"""
from dumpex.hunt._domain import CheckResult
from dumpex.hunt._finding import (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH,
    TAG_OBSERVATION, TAG_LEAD, TAG_DETECTION)
from dumpex.hunt.injection.config import PE_VALIDATE_READ_MAX
from dumpex.hunt.injection.correlation import correlated_allocations as _correlated_allocations
from dumpex.hunt.injection.domain import (
    CoverageSnapshot, InjectionEvidence, InjectionReport,
    VERDICT_LEVEL_BY_SCORE as _VERDICT_LEVEL_BY_SCORE,
)
from dumpex.hunt.injection.memory_scan import pe_hit_is_context_scoreable

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.
# verdict_level). Defined once on the canonical domain model
# (dumpex.hunt.injection.domain) and imported here rather than restated:
# the score this module computes and the verdict_level that model derives
# from a score must never be able to disagree about the same table.


def _split_scoreable_pe_hits(validated_pe_hits: tuple, rwx_and_pe_alloc_bases: set,
                              rip_hits: tuple, start_hits: tuple) -> "tuple[tuple, tuple]":
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
    return tuple(suspicious), tuple(informational)


def build_report(rwx: tuple, hidden_pe_scan, validated_pe_hits: tuple, mz_only_hits: tuple,
                  start_threads: tuple, thread_contexts: tuple,
                  correlation, memory_info_stream: bool, thread_info_stream: bool,
                  module_list_stream: bool, thread_list_stream: bool,
                  threads_total: int, contexts_parsed: int,
                  *, region_count: "int | None" = None, thread_info_count: "int | None" = None,
                  module_count: "int | None" = None) -> InjectionReport:
    """
    Turn already-collected Evidence + Correlation into the canonical
    `InjectionReport`. `validated_pe_hits`/`mz_only_hits` are
    memory_scan.split_hidden_pe_hits(hidden_pe_scan)'s output — computed
    once by the caller (also needed by correlation.py) rather than
    re-derived here. This function takes no `mf`, never calls
    va_to_file_offset(), and never needs a separate address -> Location
    lookup table: every Evidence object it reads (RwxRegionEvidence/
    HiddenPeEvidence/UnbackedThreadEvidence/RipHitEvidence/StartHitEvidence,
    see dumpex/hunt/injection/models.py) already carries its own resolved
    `location`, built once by the scan/correlation layer that still has
    `mf`. `thread_contexts` is a tuple of typed `ThreadContext` (see
    `thread_scan.resolve_thread_contexts`).

    `region_count`/`thread_info_count`/`module_count` feed the structured
    coverage projection's own record counts ONLY -- keyword-only, plain
    ints (or `None` when the caller genuinely never supplied the
    underlying list, distinct from a supplied-but-empty list/`0` -- see
    `CoverageSnapshot`'s own docstring). This function never receives the
    raw `mf.memory_info.infos`/`mf.thread_info.infos`/`mf.modules.modules`
    lists themselves -- computing `len(...)` is the scan layer's job (see
    `dumpex.hunt.injection._build_injection_report`), so aggregate.py
    never holds a reference to dump-derived data of any kind, only typed
    Evidence and scalars.
    """
    coverage = CoverageSnapshot(
        memory_info_stream=memory_info_stream, thread_info_stream=thread_info_stream,
        module_list_stream=module_list_stream, thread_list_stream=thread_list_stream,
        threads_total=threads_total, contexts_parsed=contexts_parsed,
        pe_read_failed=hidden_pe_scan.read_failed, pe_short_reads=hidden_pe_scan.short_reads,
        region_count=region_count, thread_info_count=thread_info_count,
        module_count=module_count,
    )

    rwx_and_pe_alloc_bases = correlation.rwx_and_pe_alloc_bases
    rip_hits               = correlation.rip_hits
    rip_full_correlation   = correlation.rip_full_correlation
    start_hits              = correlation.start_hits

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

    evidence = InjectionEvidence(
        rwx=rwx, validated_pe_hits=validated_pe_hits, mz_only_hits=mz_only_hits,
        suspicious_pe_hits=suspicious_pe_hits, informational_pe_hits=informational_pe_hits,
        start_threads=start_threads, thread_contexts=thread_contexts,
        correlated_allocations=_correlated_allocations(correlation), correlation=correlation,
    )

    # ── Checks (evidence / inference / confidence / rationale / limitations) ──
    results = []

    if evidence.rwx:
        allocs = sorted({f"0x{ev.region.allocation_base:x}" for ev in evidence.rwx})
        results.append(CheckResult(
            check="injection.rwx_regions",
            evidence=evidence.rwx, evidence_limit=20,
            inference=f"{len(evidence.rwx)} memory region(s) carry PAGE_EXECUTE_READWRITE/"
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

    if evidence.suspicious_pe_hits:
        results.append(CheckResult(
            check="injection.hidden_pe_validated",
            evidence=evidence.suspicious_pe_hits, evidence_limit=20,
            inference=f"{len(evidence.suspicious_pe_hits)} region(s) contain a structurally-valid "
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

    if evidence.informational_pe_hits:
        results.append(CheckResult(
            check="injection.hidden_pe_validated_context_only",
            evidence=evidence.informational_pe_hits, evidence_limit=20,
            inference=f"{len(evidence.informational_pe_hits)} region(s) contain a structurally-valid "
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

    if evidence.mz_only_hits:
        results.append(CheckResult(
            check="injection.mz_prefix_unvalidated",
            evidence=evidence.mz_only_hits, evidence_limit=10,
            inference=f"{len(evidence.mz_only_hits)} region(s) begin with the 2-byte 'MZ' prefix "
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

    if evidence.start_threads:
        results.append(CheckResult(
            check="injection.unbacked_thread_startaddress",
            evidence=evidence.start_threads, evidence_limit=20,
            inference=f"{len(evidence.start_threads)} thread(s) began execution at an address not "
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

    if not coverage.thread_context:
        results.append(CheckResult(
            check="injection.rip_correlation_unavailable",
            evidence=(),
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
    elif evidence.correlation.rip_hits:
        conf = CONFIDENCE_HIGH if rip_full_correlation else CONFIDENCE_MEDIUM
        results.append(CheckResult(
            check="injection.allocation_correlation",
            evidence=evidence.correlation.rip_hits, evidence_limit=20,
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
        results.append(CheckResult(
            check="injection.structural_allocation_correlation",
            evidence=evidence.correlated_allocations,
            inference=f"{len(rwx_and_pe_alloc_bases)} allocation(s) carry BOTH an RWX "
                       f"sub-region AND a validated hidden PE header, without a "
                       f"currently-observed thread executing inside them.",
            confidence=CONFIDENCE_MEDIUM,
            rationale="Same-allocation structural correlation is stronger than either "
                       "signal alone, but without a live RIP/EIP inside the allocation "
                       "this cannot be elevated to HIGH confidence — the code may not "
                       "(yet, or ever, at dump time) have been executed.",
            limitations=[] if coverage.thread_context else
                        ["RIP/EIP correlation could not run at all in this dump (see "
                         "injection.rip_correlation_unavailable) — this may understate "
                         "the true confidence."],
            tag=TAG_LEAD,
        ))

    return InjectionReport(score=score, coverage=coverage, results=tuple(results), evidence=evidence)
