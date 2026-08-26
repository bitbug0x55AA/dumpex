"""Run opt-in, budgeted content triage for skipped scan targets.

Targets are read from their own base addresses, not through MemoryInfo lookup:
captured segments may have no MemoryInfo entry, and a target may be only part of
a larger region. Input ordering, deduplication, and priority are preserved.

Per-target, whole-run, and target-count budgets are independent. Uncaptured
targets consume no read budget; remaining targets are deterministically deferred
after exhaustion. Deep triage does not change priority or coverage meaning.
"""
from dataclasses import replace

from dumpex.commands.report import _scan_content_range, _module_context_for
from dumpex.core.memory import get_modules, addr_to_module
from dumpex.output.records import Diagnostic, SEVERITY_WARNING, hex_address
from dumpex.hunt._investigation import (
    TriageInfo, TriageMode, TriageStatus, ContentReasonCode,
    ContentFinding, ContentFindingType, MAX_FINDINGS_PER_TARGET, MAX_FINDING_VALUE_LEN,
    RecommendedAction, InvestigationActionType, EvidenceAvailability,
)

__all__ = [
    "DEEP_TRIAGE_PER_TARGET_LIMIT", "DEEP_TRIAGE_RUN_BUDGET", "DEEP_TRIAGE_MAX_TARGETS",
    "run_deep_triage",
]

DEEP_TRIAGE_PER_TARGET_LIMIT = 4 * 1024 * 1024     # 4 MiB read cap per target
DEEP_TRIAGE_RUN_BUDGET       = 64 * 1024 * 1024    # 64 MiB whole-run cap
DEEP_TRIAGE_MAX_TARGETS      = 25                  # deterministic priority cutoff

_MIN_LEN = 6   # same default --report/--strings use (cli.py's --min-len default)

# Any status reached WITHOUT a real read -- see TriageInfo.__post_init__'s
# own _TRIAGE_ZERO_BYTE_STATUSES, duplicated here as the values (not the
# frozenset object) rather than imported, since that name is private to
# _investigation.py's own validation and this module only needs the two
# values it actually constructs from this branch.
_INCOMPLETE_DEEP_STATUSES = frozenset({
    TriageStatus.PARTIAL.value, TriageStatus.CLAMPED.value,
    TriageStatus.BUDGET_DEFERRED.value, TriageStatus.UNREADABLE.value,
})


def _zero_byte_triage(status: str) -> TriageInfo:
    return TriageInfo(mode=TriageMode.DEEP.value, status=status,
                       bytes_examined=0, region_fully_examined=False,
                       content_reason_codes=(), findings=(),
                       finding_count=0, findings_truncated=False)


def _content_signals(scan, *, base_address: int, module_context: str) -> "tuple[tuple, tuple, int, bool]":
    """Returns `(content_reason_codes, findings, finding_count,
    findings_truncated)`, derived ONLY from this deep read's own fresh
    evidence (`scan.ioc_strings`/`scan.mz_header_detected`/
    `scan.has_injected_pe`, from `_scan_content_range()`) -- never from
    the target's metadata facts already covered by
    `InvestigationReasonCode` (PRIVATE_EXECUTABLE_MEMORY/RWX_PROTECTION),
    which stay on `priority_reason_codes` and are not re-derived here.

    `content_reason_codes` is the quick summary; `findings` (issue #19
    Phase 2 review, item 4) is the bounded, structured evidence behind
    it -- capped at `MAX_FINDINGS_PER_TARGET` total entries.
    `ContentFinding.value` is truncated to `MAX_FINDING_VALUE_LEN`
    characters -- a bounded lead, not the full match; `--report
    --report-addr <base_address>` still gets the complete text, hexdump
    context, and an extractable artifact.

    Selection order (issue #19 Phase 2 review round 2, item 2) is
    REPRESENTATIVE-FIRST, not a bare offset-order fill: appending IOC
    findings offset-first until the cap, and only then trying to add an
    MZ finding, meant a target with >=20 plain IOC hits would silently
    crowd out BOTH the MZ finding and any network-pattern IOC finding --
    even though `content_reason_codes` would still list
    MZ_HEADER_DETECTED/NETWORK_PATTERN_STRING_MATCH, leaving those codes
    with no structured evidence behind them at all. Instead:

      1. The MZ header finding (if any) -- always included first, since
         an MZ header at the read's own start is the strongest single
         signal this scan can produce.
      2. The first network-pattern IOC finding (if any) -- a network hit
         is qualitatively distinct evidence from a plain IOC string hit,
         worth guaranteeing a representative for even when many plain
         hits exist.
      3. The first plain (non-network) IOC finding (if any), for the
         same reason.
      4. Every remaining IOC finding, in the same offset order
         `_scan_content_range()` already produced them, filling whatever
         slots remain up to the cap.

    `finding_count` is the TOTAL number of individual findings this read
    produced (MZ header counts as at most 1, plus every IOC string hit) --
    BEFORE this capped/reordered selection; `findings_truncated` is
    `finding_count > len(findings)`. Together they let a JSON consumer
    tell "there were exactly N findings, all shown" apart from "there
    were more than N, only a bounded representative sample is shown" --
    see `TriageInfo.finding_count`'s own docstring."""
    codes = []

    mz_finding = None
    if scan.mz_header_detected:
        codes.append(ContentReasonCode.MZ_HEADER_DETECTED.value)
        if scan.has_injected_pe:
            codes.append(ContentReasonCode.INJECTED_PE_HEADER.value)
        mz_finding = ContentFinding(
            type=ContentFindingType.MZ_HEADER.value, address=hex_address(base_address),
            module_context=module_context)

    ioc_findings = []
    if scan.ioc_strings:
        codes.append(ContentReasonCode.IOC_PATTERN_STRING_MATCH.value)
        if any(s.is_network_pattern for s in scan.ioc_strings):
            codes.append(ContentReasonCode.NETWORK_PATTERN_STRING_MATCH.value)
        for s in scan.ioc_strings:
            ioc_findings.append(ContentFinding(
                type=ContentFindingType.IOC_STRING.value, address=s.address, offset=s.offset,
                encoding=s.encoding, value=s.text[:MAX_FINDING_VALUE_LEN],
                is_network_pattern=s.is_network_pattern))

    finding_count = len(ioc_findings) + (1 if mz_finding is not None else 0)

    findings = []
    if mz_finding is not None:
        findings.append(mz_finding)

    remaining = list(ioc_findings)

    def _pop_first(predicate):
        for i, f in enumerate(remaining):
            if predicate(f):
                return remaining.pop(i)
        return None

    if len(findings) < MAX_FINDINGS_PER_TARGET:
        representative_net = _pop_first(lambda f: f.is_network_pattern)
        if representative_net is not None:
            findings.append(representative_net)
    if len(findings) < MAX_FINDINGS_PER_TARGET:
        representative_plain = _pop_first(lambda f: not f.is_network_pattern)
        if representative_plain is not None:
            findings.append(representative_plain)
    for f in remaining:
        if len(findings) >= MAX_FINDINGS_PER_TARGET:
            break
        findings.append(f)

    findings_truncated = finding_count > len(findings)
    return tuple(codes), tuple(findings), finding_count, findings_truncated


def _deep_read_triage(mf, target, *, read_cap: int, modules: list,
                       modules_available: bool) -> TriageInfo:
    """One budgeted `_scan_content_range()` call against `target`'s own
    `base_address` (see this module's own docstring for why never a
    resolved MemoryInfo region's address), reduced to a `TriageInfo`.

    Deliberately does NOT wrap this call in its own try/except:
    `_scan_content_range()` already catches the one thing that can
    legitimately fail here (the read itself, surfaced in
    `.string_scan_error`) internally. Adding a second, broader catch here
    would silently relabel an unrelated bug (a `TypeError` from a future
    signature change, a `ContentFinding`/`TriageInfo` construction error,
    ...) as ordinary evidence-unreadability, hiding a real dumpex defect
    behind a mundane-looking `status: "unreadable"` instead of surfacing
    it as the test/CLI failure it actually is."""
    module_context = _module_context_for(
        addr_to_module(target.base_address, modules), modules_available)
    scan = _scan_content_range(mf, base_address=target.base_address, requested_size=read_cap,
                                min_len=_MIN_LEN, module_context=module_context)

    if scan.string_scan_error is not None:
        return _zero_byte_triage(TriageStatus.UNREADABLE.value)

    bytes_examined = scan.string_scan["bytes_read"]
    if bytes_examined <= 0:
        return _zero_byte_triage(TriageStatus.UNREADABLE.value)

    if bytes_examined < read_cap:
        # The dump itself had fewer bytes than requested -- a real
        # evidence gap. Checked FIRST, ahead of the read_cap-vs-target.size
        # comparison below: a skipped target's own size is by definition
        # larger than whatever cap caused the skip, so read_cap < target.
        # size is true for nearly every real deep-triage read -- deciding
        # "clamped" before checking for a short read would silently mask
        # almost every genuine short read as a mere policy choice instead.
        status = TriageStatus.PARTIAL.value
        fully_examined = False
    elif read_cap < target.size:
        # We ourselves asked for less than the whole target (per-target/
        # run-budget pressure) AND the dump had at least that much --
        # a deliberate policy clamp, not evidence of a gap.
        status = TriageStatus.CLAMPED.value
        fully_examined = False
    else:
        # Asked for (read_cap >= target.size) and got (bytes_examined ==
        # read_cap >= target.size, so effectively the whole target) every
        # requested byte.
        status = TriageStatus.COMPLETED.value
        fully_examined = True

    content_reason_codes, findings, finding_count, findings_truncated = _content_signals(
        scan, base_address=target.base_address, module_context=module_context)
    return TriageInfo(mode=TriageMode.DEEP.value, status=status,
                       bytes_examined=bytes_examined, region_fully_examined=fully_examined,
                       content_reason_codes=content_reason_codes, findings=findings,
                       finding_count=finding_count, findings_truncated=findings_truncated)


def _with_chunked_analysis(recommended_actions: tuple) -> tuple:
    if any(a.type == InvestigationActionType.CHUNKED_ANALYSIS.value for a in recommended_actions):
        return recommended_actions
    return recommended_actions + (
        RecommendedAction(type=InvestigationActionType.CHUNKED_ANALYSIS.value),)


def _apply_triage(action, triage: TriageInfo):
    recommended_actions = action.recommended_actions
    if triage.status in _INCOMPLETE_DEEP_STATUSES:
        recommended_actions = _with_chunked_analysis(recommended_actions)
    return replace(action, triage=triage, recommended_actions=recommended_actions)


def run_deep_triage(mf, actions: list, *, per_target_limit: int = DEEP_TRIAGE_PER_TARGET_LIMIT,
                     run_budget: int = DEEP_TRIAGE_RUN_BUDGET,
                     max_targets: int = DEEP_TRIAGE_MAX_TARGETS) -> "tuple[list, list]":
    """Returns `(new_actions, diagnostics)`: `new_actions` is `actions`
    with every entry's `triage` replaced by a real `mode="deep"` result
    (and `recommended_actions` extended with `chunked_analysis` where the
    target wasn't fully examined) -- same length, same order, same
    identity of every OTHER field (priority/evidence_availability/
    coverage_effect unchanged, see this module's own docstring).
    `diagnostics` is a small, bounded `list[Diagnostic]` of whole-run
    notes (never per-target -- each action's own `triage.
    content_reason_codes` already carries the per-target content signal
    structurally, in `--json`, so no per-target diagnostic duplicates it).

    `actions` must already be `build_investigation_queue()`'s own
    priority-ordered output -- this function never re-sorts it, only
    walks it once, so the SAME deterministic prefix is read every time
    for the same queue and the same budgets."""
    if not actions:
        return [], []

    modules = get_modules(mf)
    modules_available = bool(mf.modules)

    remaining_budget = run_budget
    attempted = 0
    deferred = 0
    unreadable = 0
    total_bytes = 0
    new_actions = []

    for action in actions:
        target = action.target
        if action.evidence_availability != EvidenceAvailability.CAPTURED.value:
            new_actions.append(_apply_triage(action, _zero_byte_triage(
                TriageStatus.NOT_CAPTURED.value)))
            continue

        if attempted >= max_targets or remaining_budget <= 0:
            deferred += 1
            new_actions.append(_apply_triage(action, _zero_byte_triage(
                TriageStatus.BUDGET_DEFERRED.value)))
            continue

        read_cap = min(per_target_limit, remaining_budget, target.size)
        triage = _deep_read_triage(
            mf, target, read_cap=read_cap, modules=modules, modules_available=modules_available)
        attempted += 1
        remaining_budget -= triage.bytes_examined
        total_bytes += triage.bytes_examined
        if triage.status == TriageStatus.UNREADABLE.value:
            unreadable += 1
        new_actions.append(_apply_triage(action, triage))

    diagnostics = [Diagnostic(
        SEVERITY_WARNING,
        f"Deep triage (--triage-skipped) examined {attempted} of {len(actions)} skipped "
        f"target(s), {total_bytes} byte(s) total -- advisory only, does not resolve any "
        f"originating hunter's own coverage gap.",
        code="DEEP_TRIAGE_SUMMARY")]
    if deferred:
        diagnostics.append(Diagnostic(
            SEVERITY_WARNING,
            f"Deep triage budget exhausted: {deferred} skipped target(s) deferred "
            f"(run_budget={run_budget} bytes, max_targets={max_targets}) -- see "
            f"investigation_actions[].triage.status == 'budget_deferred'.",
            code="DEEP_TRIAGE_BUDGET_EXHAUSTED"))
    if unreadable:
        diagnostics.append(Diagnostic(
            SEVERITY_WARNING,
            f"Deep triage could not read {unreadable} captured target(s) -- see "
            f"investigation_actions[].triage.status == 'unreadable'.",
            code="DEEP_TRIAGE_READ_FAILED"))
    return new_actions, diagnostics
