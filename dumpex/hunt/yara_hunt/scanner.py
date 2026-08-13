"""Segment × rule-file YARA match loop: reads each memory segment, runs
every compiled rule file against it, normalizes matches, resolves each
hit's module/region context ONCE (rather than leaving `presentation.py` to
re-resolve `addr_to_module()` per hit at render time -- issue #11's
confirmed gap: "retains raw module objects in Report.modules"), and applies
the whole-scan budgets (deadline, total bytes, hit cap). Only collects
facts -- never scores, never prints.

Returns a frozen `ScanResult(matches, diagnostics)`: `matches` is every
individual (segment, rule_file) match, ONE `models.RuleMatchEvidence` each,
in scan order -- NOT deduplicated by `(rule, seg_va)`. Two different rule
FILES (or namespaces) that each define a same-named rule matching the same
region are two distinct pieces of evidence (different `file`/`namespace`,
different provenance) and must both survive into the Report; collapsing
them at this layer would silently drop a legitimate match from `matches`/
`YaraDetails` (the wire contract) and from `triggered_rules`' own
transparency, not just from console display. A console projector may still
GROUP entries that share a rule name for display purposes -- that is a
`report_console.py` concern, not a fact this module is allowed to discard.
`diagnostics` is a frozen `domain.ScanDiagnostics`.
"""
import dataclasses
import math
import os
import time
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import addr_to_module
from dumpex.hunt._coverage import segment_scan_target
from dumpex.hunt._domain import as_tuple, require_recursively_immutable
from dumpex.hunt.yara_hunt.config import YaraConfig, SCOPE_PRIVATE_OR_UNBACKED
from dumpex.hunt.yara_hunt.domain import ScanDiagnostics
from dumpex.hunt.yara_hunt.models import RuleMatchEvidence, StringEvidence
from dumpex.hunt.yara_hunt import context as context_mod


def select_segments(mf) -> list:
    """Prefer the 64-bit segment table, falling back to the 32-bit one."""
    if mf.memory_segments_64 and mf.memory_segments_64.memory_segments:
        return mf.memory_segments_64.memory_segments
    if mf.memory_segments and mf.memory_segments.memory_segments:
        return mf.memory_segments.memory_segments
    return []


@dataclasses.dataclass(frozen=True, slots=True)
class ScanResult:
    """Not part of the frozen domain graph itself (transient scan output,
    consumed once by `aggregate.build_report()` and discarded) but frozen
    all the same -- aggregate's input boundary admits typed evidence and
    scalars only, never a mutable scanner DTO, so this can't be a plain
    reassignable holder for `matches`/`diagnostics` even though nothing
    downstream keeps a reference to it. Holds what `scan_segments()`
    produced: `matches` -- a tuple of `models.RuleMatchEvidence`, one per
    individual match, in scan order -- and `diagnostics`, a frozen
    `domain.ScanDiagnostics`.

    `frozen=True` alone only blocks reassigning `result.matches`/
    `result.diagnostics` -- it does nothing to stop a caller mutating a
    mutable object (a `list`) it passed in AFTER construction, which would
    silently change what this "immutable" instance reports. `__post_init__`
    closes that: `matches` is copied into a fresh tuple (never the caller's
    own list), every item is checked to actually be a `RuleMatchEvidence`
    and recursively immutable, and `diagnostics` is checked to actually be
    a `ScanDiagnostics` -- constructor-input isolation, not just
    post-construction reassignment resistance."""
    matches: tuple
    diagnostics: ScanDiagnostics

    def __post_init__(self):
        matches = as_tuple(self.matches, "ScanResult.matches")
        for index, item in enumerate(matches):
            where = f"ScanResult.matches[{index}]"
            if type(item) is not RuleMatchEvidence:
                raise TypeError(
                    f"{where} must be a RuleMatchEvidence, got "
                    f"{type(item).__name__}: {item!r}")
            require_recursively_immutable(item, where)
        object.__setattr__(self, "matches", matches)
        if type(self.diagnostics) is not ScanDiagnostics:
            raise TypeError(
                f"ScanResult.diagnostics must be a ScanDiagnostics, got "
                f"{type(self.diagnostics).__name__}: {self.diagnostics!r}")


def scan_segments(mf: MinidumpFile, segs: list, rule_files: list, modules: list, regions: list,
                   modules_available: bool, mem_info_available: bool,
                   config: YaraConfig, monotonic=time.monotonic) -> ScanResult:
    """
    Walk every segment in `segs`, matching each against every compiled
    rule file in `rule_files`, applying every whole-scan resource budget
    (deadline, total bytes scanned, hit count) exactly as before this
    migration. `monotonic` is threaded explicitly (not imported directly
    from `time` in this module) so a caller/test can substitute a fake
    clock without needing the global `time.monotonic` to be patched — see
    dumpex/hunt/_runtime.py.
    """
    reader = mf.get_reader()

    all_hits     = []   # raw dicts, one per (segment, rule) match -- kept as
                          # dicts through the loop (frozen into
                          # models.RuleMatchEvidence only once the loop ends)
                          # so the hit-cap count (`len(all_hits)`) means
                          # exactly what it did before this migration
    skipped_targets = []   # ScanTarget per oversized segment
    read_failed  = 0
    read_failed_targets = []
    short_reads  = 0
    short_read_targets = []
    scanned      = 0
    timed_out    = 0
    timed_out_targets = []
    match_failed = 0
    match_failed_targets = []
    truncated    = False
    budget_exhausted   = False
    truncated_stop_index = None
    budget_exhausted_stop_index = None
    budget_exhausted_kind = None
    budget_exhausted_consumed = None

    def _mark_truncated():
        nonlocal truncated, truncated_stop_index
        truncated = True
        if truncated_stop_index is None:
            truncated_stop_index = seg_index

    def _mark_budget_exhausted(kind: str, consumed: int, current_segment_affected: bool = True):
        nonlocal budget_exhausted, budget_exhausted_stop_index, budget_exhausted_kind, \
            budget_exhausted_consumed
        budget_exhausted = True
        if budget_exhausted_stop_index is None:
            budget_exhausted_stop_index = seg_index if current_segment_affected else seg_index + 1
            budget_exhausted_kind = kind
            budget_exhausted_consumed = consumed

    total_bytes_scanned = 0
    scan_start = monotonic()
    scan_deadline = scan_start + config.scan_deadline_seconds

    def _elapsed_seconds(now: float) -> int:
        return max(0, math.ceil(now - scan_start))

    suppressed_module_pe = 0
    suppressed_scoped    = 0
    context_unverified   = 0

    for seg_index, seg in enumerate(segs):
        if truncated:
            break
        _now = monotonic()
        if _now > scan_deadline:
            _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now))
            break
        if total_bytes_scanned > config.max_total_bytes_scanned:
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
            break
        if seg.size > config.max_seg_scan:
            skipped_targets.append(segment_scan_target(seg, config.max_seg_scan))
            continue
        if total_bytes_scanned + seg.size > config.max_total_bytes_scanned:
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
            break
        try:
            data = reader.read(seg.start_virtual_address, seg.size)
        except Exception:
            read_failed += 1
            read_failed_targets.append(segment_scan_target(seg))
            continue
        total_bytes_scanned += len(data)
        if total_bytes_scanned > config.max_total_bytes_scanned:
            _mark_budget_exhausted("max_total_bytes_scanned", total_bytes_scanned)
        if len(data) < seg.size:
            short_reads += 1
            short_read_targets.append(segment_scan_target(seg))
            if not data:
                continue
        scanned += 1

        for rule_index, (fname, compiled) in enumerate(rule_files):
            remaining = scan_deadline - monotonic()
            if remaining <= 0:
                _mark_budget_exhausted("scan_deadline_seconds",
                                       _elapsed_seconds(scan_deadline - remaining))
                break
            try:
                call_timeout = max(1, min(config.match_timeout, int(remaining)))
                matches = compiled.match(data=data, timeout=call_timeout)
            except Exception as e:
                if "timeout" in type(e).__name__.lower():
                    timed_out += 1
                    timed_out_targets.append(segment_scan_target(seg))
                else:
                    match_failed += 1
                    match_failed_targets.append(segment_scan_target(seg))
                _now = monotonic()
                if _now > scan_deadline:
                    _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now),
                                           current_segment_affected=rule_index < len(rule_files) - 1)
                    break
                continue

            _now = monotonic()
            if _now > scan_deadline:
                _mark_budget_exhausted("scan_deadline_seconds", _elapsed_seconds(_now),
                                       current_segment_affected=rule_index < len(rule_files) - 1)

            for match in matches:
                if len(all_hits) >= config.max_total_hits:
                    _mark_truncated()
                    break

                hit_context_unverified = False
                hit_memory_context = None
                if match.rule == "PE_In_Private_Memory":
                    addr = seg.start_virtual_address
                    suppressed, unverified, ctx_value = context_mod.classify_pe_in_private_memory_hit(
                        addr, modules, regions, modules_available, mem_info_available)
                    hit_memory_context = ctx_value

                    if suppressed:
                        suppressed_module_pe += 1
                        continue

                    if unverified:
                        context_unverified += 1
                        hit_context_unverified = True
                elif match.meta.get("dumpex_scope") == SCOPE_PRIVATE_OR_UNBACKED:
                    addr = seg.start_virtual_address
                    suppressed, unverified, ctx_value = context_mod.classify_scoped_hit(
                        addr, modules, regions, modules_available, mem_info_available)
                    hit_memory_context = ctx_value

                    if suppressed:
                        suppressed_scoped += 1
                        continue

                    if unverified:
                        context_unverified += 1
                        hit_context_unverified = True

                # Module/region context resolved ONCE, here, at scan time --
                # not re-derived by the console at render time.
                mod = addr_to_module(seg.start_virtual_address, modules) if modules_available else None
                backing_module = os.path.basename(mod.name) if mod else None

                # `string_count` counts every string INSTANCE this match
                # actually had (not just the ones kept) so a cap at
                # config.max_strings_per_match is a visible, reportable
                # fact (`strings_truncated`) rather than a silent drop --
                # `annotated_strings` itself still stops growing once the
                # cap is reached, but counting continues past that point.
                annotated_strings = []
                string_count = 0
                for s in match.strings:
                    if hasattr(s, 'instances'):
                        for inst in s.instances:
                            string_count += 1
                            if len(annotated_strings) >= config.max_strings_per_match:
                                continue
                            off     = inst.offset
                            matched = inst.matched_data
                            annotated_strings.append(StringEvidence(
                                var=s.identifier, offset=off,
                                va=seg.start_virtual_address + off,
                                fo=seg.start_file_address + off, data=matched))
                    else:
                        off, varname, matched = s
                        string_count += 1
                        if len(annotated_strings) < config.max_strings_per_match:
                            annotated_strings.append(StringEvidence(
                                var=varname, offset=off, va=seg.start_virtual_address + off,
                                fo=seg.start_file_address + off, data=matched))

                all_hits.append({
                    "rule":     match.rule,
                    "file":     fname,
                    # yara-python's own Match.namespace -- "default" for
                    # every rule this codebase compiles today (rules.py
                    # compiles each FILE separately via `yara.compile(
                    # filepath=path)`, never a named `filepaths={...}`
                    # namespace), captured via getattr so a fake Match
                    # test double with no such attribute still works, and
                    # so a future namespace-aware compile path needs no
                    # scanner.py change to start reporting real values.
                    "namespace": getattr(match, "namespace", "default"),
                    "tags":     tuple(match.tags),
                    "meta":     dict(match.meta),
                    "seg_va":   seg.start_virtual_address,
                    "seg_fo":   seg.start_file_address,
                    "seg_size": seg.size,
                    "strings":  tuple(annotated_strings),
                    "string_count": string_count,
                    "backing_module": backing_module,
                    "context_unverified": hit_context_unverified,
                    "memory_context": hit_memory_context,
                })
            if truncated or budget_exhausted:
                break

    truncated_targets = ([segment_scan_target(s) for s in segs[truncated_stop_index:]]
                          if truncated_stop_index is not None else [])
    budget_exhausted_targets = (
        [segment_scan_target(s) for s in segs[budget_exhausted_stop_index:]]
        if budget_exhausted_stop_index is not None else [])
    truncated_budget_limit = config.max_total_hits if truncated else None
    _budget_limits_by_kind = {
        "scan_deadline_seconds": max(0, int(config.scan_deadline_seconds)),
        "max_total_bytes_scanned": config.max_total_bytes_scanned,
    }
    budget_exhausted_limit = (_budget_limits_by_kind[budget_exhausted_kind]
                                if budget_exhausted_kind is not None else None)

    # Every raw hit becomes its own `RuleMatchEvidence`, 1:1, in scan order
    # -- no dedup here (see this module's own docstring for why collapsing
    # by (rule, seg_va) would silently drop a legitimate distinct match
    # from a different rule file/namespace).
    matches = tuple(
        RuleMatchEvidence(
            rule=hit["rule"], file=hit["file"], namespace=hit["namespace"], tags=hit["tags"],
            meta=tuple(sorted(hit["meta"].items())),
            seg_va=hit["seg_va"], seg_fo=hit["seg_fo"], seg_size=hit["seg_size"],
            strings=hit["strings"], string_count=hit["string_count"],
            backing_module=hit["backing_module"], memory_context=hit["memory_context"],
            context_unverified=hit["context_unverified"])
        for hit in all_hits)

    diagnostics = ScanDiagnostics(
        segment_count=len(segs), scanned=scanned,
        skipped_oversize_targets=tuple(skipped_targets),
        read_failed_targets=tuple(read_failed_targets),
        short_read_targets=tuple(short_read_targets),
        timed_out_targets=tuple(timed_out_targets),
        match_failed_targets=tuple(match_failed_targets),
        truncated=truncated, truncated_targets=tuple(truncated_targets),
        truncated_budget_limit=truncated_budget_limit,
        budget_exhausted=budget_exhausted,
        budget_exhausted_targets=tuple(budget_exhausted_targets),
        budget_exhausted_kind=budget_exhausted_kind, budget_exhausted_limit=budget_exhausted_limit,
        budget_exhausted_consumed=budget_exhausted_consumed,
        total_bytes_scanned=total_bytes_scanned, suppressed_module_pe=suppressed_module_pe,
        suppressed_scoped=suppressed_scoped, context_unverified=context_unverified,
    )
    return ScanResult(matches=matches, diagnostics=diagnostics)
