"""Collect module, thread, and memory differences between two dumps.

Results are tagged by entity type and preserve before/after null semantics.
Thread module context distinguishes confirmed unregistered addresses from
unavailable module evidence. Collection produces structured records that console
rendering consumes without reopening either dump.

Differences are relations between two captured inventories, never observed
events. The comparison premise discloses which capture, process and image
identity facts the two dumps share, differ in, or do not establish; it
qualifies the records without gating them.
"""
import ntpath
import re

from minidump.constants import MINIDUMP_STREAM_TYPE

from dumpex.core.memory import (
    get_modules, get_thread_infos, get_memory_regions, addr_to_module,
    module_name_only, prot_str, recorded_start_address,
    truncated_thread_info_count, stream_failure, peb_failure, va_range_captured_bytes,
)
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.output.records import (
    ModuleDiffRecord, MODULE_DIFF_ADDED, MODULE_DIFF_REMOVED, MODULE_DIFF_REBASED,
    ThreadDiffRecord, THREAD_DIFF_ADDED, THREAD_DIFF_REMOVED,
    MemoryDiffRecord, MEMORY_DIFF_ADDED, MEMORY_DIFF_REMOVED, MEMORY_DIFF_PROTECTION_CHANGED,
    hex_address, MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
    COMPARISON_FACTS, ComparisonFactRecord, ComparisonCaptureDiagnostic, ComparisonPremiseRecord,
    COMPARISON_SIDE_BASELINE, COMPARISON_SIDE_TARGET, FACT_STATE_RECORDED, FACT_STATE_ABSENT,
    FACT_STATE_FAILED, FACT_STATE_UNSET, FACT_STATE_UNRECONSTRUCTED, FACT_STATE_BASE_UNKNOWN,
    FACT_STATE_UNMATCHED, FACT_STATE_UNCAPTURED, FACT_STATE_TRUNCATED, FACT_STATE_INVALID,
)
from dumpex.output.coverage import (
    observe_source, build_coverage_report, combine_coverage_reports,
    EvaluationRequirement, SourceRequirement, COVERAGE_NOT_EVALUATED,
    SourceObservation, SourceState, CoverageLimitation, LimitationCode,
)
from dumpex.output.command_result import CommandResult
from dumpex.core.process_info import (
    MAIN_IMAGE_PE_READ_MAX, build_process_identity_snapshot, classify_main_image_state,
    format_uint32_time_utc, main_image_machine, registered_main_module_facts,
)

_DIFF_MODES = ("modules", "threads", "memory", "all")


def _observe_or_failed(name: str, mf, stream_attr: str, getter) -> "tuple[SourceObservation, list]":
    """(observation, items) -- isolates one side's stream-presence-check +
    read into a single try/except. A genuinely raised exception (e.g. an
    mf.modules property that raises on access, as opposed to a stream
    that's merely absent or empty) is reported as SourceState.FAILED for
    THIS side specifically, via the same SourceObservation shape
    observe_source() already produces for the absent/present_empty/
    present cases -- never silently treated as "zero items," which would
    misreport every one of the OTHER side's real items as added/removed
    instead of correctly refusing to diff at all (see each
    collect_*_diff()'s own post-coverage FAILED gate, which this return
    value drives)."""
    try:
        present = bool(getattr(mf, stream_attr))
        items = getter(mf)
        return observe_source(name, present=present, items=items), items
    except Exception as e:
        # str(e) can legitimately be "" for an exception raised with no
        # message (e.g. bare `raise RuntimeError()`) -- SourceObservation.
        # detail requires None or a NON-EMPTY string, so fall back to
        # repr(e) (always non-empty: at minimum the exception's class
        # name) rather than let a message-less exception crash here too.
        return SourceObservation(name=name, state=SourceState.FAILED,
                                  detail=str(e) or repr(e)), []


def _module_match_key(m) -> str:
    """The cross-dump matching key for one module -- module_name_only()
    when the module has a real name, or an address-qualified key when it
    doesn't. module_name_only() returns "" for an anonymous module (no
    name at all, or an empty one), and "" alone would collide across
    EVERY anonymous module in the same dump -- {module_name_only(m.name):
    m for m in raw_...} would then silently keep only the last one,
    dropping every other anonymous module's diff entirely. Two anonymous
    modules can never share a base address within one dump, so this key
    is always unique there. Across dumps, an anonymous module's
    address-qualified key differs whenever its address differs, so it can
    never be matched as "rebased" -- the conservative, correct choice,
    since nothing else identifies it as "the same" module between two
    captures (unlike a named module, whose key is stable across dumps by
    construction)."""
    name_key = module_name_only(m.name)
    return name_key if name_key else f"<unnamed@0x{m.baseaddress:016x}>"


def _module_display_name(m) -> str:
    """The wire `name` field -- module_name_only() when available, else
    the same "(unnamed)" placeholder dumpex.commands.modules.py's
    ModuleRecord.name already uses for an anonymous module, so `name`
    always stays a non-empty string (required by the v2.1 schema) without
    leaking _module_match_key's internal address-qualified form onto the
    wire."""
    return module_name_only(m.name) or "(unnamed)"


def collect_module_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_modules. Matches
    modules by _module_match_key(m) (module_name_only(m.name), same as
    the console version, for a named module), exactly like the console
    version for named modules -- see _module_match_key's own docstring
    for anonymous ones. Returns ([], coverage) without attempting a diff
    at all when either side's ModuleListStream is entirely absent OR
    failed to read (see _observe_or_failed)."""
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.modules", mf_baseline, "modules", get_modules)
    target_obs, raw_target = _observe_or_failed(
        "target.modules", mf_target, "modules", get_modules)
    sources = {"baseline.modules": baseline_obs, "target.modules": target_obs}

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.modules",)),
                            EvaluationRequirement(("target.modules",))],
        # Bare names here so a FAILED side (which the evaluation_groups
        # gate above does NOT catch -- not_evaluated only fires on
        # ABSENT, never FAILED) still produces a SOURCE_FAILED limitation
        # via the reducer's existing FAILED branch, yielding PARTIAL
        # rather than a false COMPLETE with zero limitations.
        completeness_checks=["baseline.modules", "target.modules"],
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
        # Required in addition to the NOT_EVALUATED check above: a FAILED
        # side is not ABSENT, so it survives that gate, but raw_baseline/
        # raw_target is [] for it (the _observe_or_failed fallback) --
        # proceeding to diff against that [] would silently misreport
        # 100% of the OTHER side's real items as added/removed.
        return [], coverage

    mods_baseline = {_module_match_key(m): m for m in raw_baseline}
    mods_target = {_module_match_key(m): m for m in raw_target}
    added = set(mods_target) - set(mods_baseline)
    removed = set(mods_baseline) - set(mods_target)
    rebased = [n for n in (set(mods_baseline) & set(mods_target))
               if mods_baseline[n].baseaddress != mods_target[n].baseaddress]

    records = []
    for n in sorted(added):
        m = mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_ADDED, name=_module_display_name(m),
            full_path_before=None, full_path_after=m.name or None,
            base_address_before=None, base_address_after=hex_address(m.baseaddress)))
    for n in sorted(removed):
        m = mods_baseline[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REMOVED, name=_module_display_name(m),
            full_path_before=m.name or None, full_path_after=None,
            base_address_before=hex_address(m.baseaddress), base_address_after=None))
    for n in sorted(rebased):
        ma, mb = mods_baseline[n], mods_target[n]
        records.append(ModuleDiffRecord(
            change_type=MODULE_DIFF_REBASED, name=_module_display_name(mb),
            full_path_before=ma.name or None, full_path_after=mb.name or None,
            base_address_before=hex_address(ma.baseaddress),
            base_address_after=hex_address(mb.baseaddress)))
    return records, coverage


def collect_thread_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_threads.
    ThreadInfoListStream (mf.thread_info), not the base ThreadListStream --
    diff_threads itself only ever reads get_thread_infos(). A removed
    thread never gets a backing_module_before -- diff_threads never
    attempts baseline-side module resolution either.

    Unlike diff_threads' own console rendering (`sa = ti.StartAddress or
    0`, which folds "unknown" and "genuinely 0" into the same printed
    "0x0"), a start address is read through
    dumpex.core.memory.recorded_start_address here -- the single rule
    every command and hunter shares -- and is null whenever no address
    was established for that thread: no ThreadInfoListStream record, a
    record whose own DumpFlags disown every field but ThreadId, or one
    whose declared size stopped short of the StartAddress field. It is
    never coerced to 0: doing so would feed a fabricated address into
    addr_to_module() and could produce MODULE_CONTEXT_UNREGISTERED -- a
    real, confirmed "this thread is not backed by any known module" DFIR
    signal -- for a thread whose address was simply never known at all.
    start_address_*/backing_module_after/backing_module_context all stay
    null in that case, mirroring ThreadRecord's own module_context
    convention (see dumpex.output.records.base).

    target.modules is only read, and only registered as a coverage
    source, when at least one ADDED thread has a known StartAddress
    (removed threads never need it -- see above). Registering it
    unconditionally would silently mismatch "coverage says complete" with
    a backing_module_context that says "unavailable" whenever
    ModuleListStream happens to be missing from a dump with no added
    threads at all to explain it; registering it only when it's actually
    consulted keeps the two in sync -- an absent target.modules makes
    coverage partial (with its own reason) exactly when a
    backing_module_context could actually come back "unavailable"."""
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.thread_info", mf_baseline, "thread_info", get_thread_infos)
    target_obs, raw_target = _observe_or_failed(
        "target.thread_info", mf_target, "thread_info", get_thread_infos)
    sources = {"baseline.thread_info": baseline_obs, "target.thread_info": target_obs}
    completeness_checks = ["baseline.thread_info", "target.thread_info"]
    # A side whose ThreadInfoListStream declared records it never
    # delivered cannot settle which TIDs exist on that side, so the
    # added/removed sets it produces are not a closed answer: a TID
    # "removed" may simply be one whose record never arrived. The
    # records are still real and still reported -- what is corrected is
    # the claim that the comparison is complete.
    for name, obs, mf in (("baseline.thread_info", baseline_obs, mf_baseline),
                           ("target.thread_info", target_obs, mf_target)):
        # A side whose stream already FAILED to read is reported as
        # failed, not as truncated -- _observe_or_failed absorbed the
        # raise, and re-reading the attribute here would let it escape.
        undelivered = (0 if obs.state == SourceState.FAILED
                       else truncated_thread_info_count(getattr(mf, "thread_info", None)))
        if undelivered:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.THREAD_INFO_STREAM_TRUNCATED, source=name,
                affected_count=undelivered))

    ta = {ti.ThreadId: ti for ti in raw_baseline}
    tb = {ti.ThreadId: ti for ti in raw_target}
    added = set(tb) - set(ta)
    removed = set(ta) - set(tb)
    # If either REQUIRED side already failed to read, `added`/`ta`/`tb`
    # are meaningless (built from the [] fallback for whichever side
    # failed) -- the whole diff is about to be discarded below (the
    # thread_info_failed gate after build_coverage_report), so skip even
    # ATTEMPTING the target.modules read here: doing so anyway would
    # produce a spurious, misleading SOURCE_ABSENT/SOURCE_FAILED
    # limitation about modules when the actual, real problem is the
    # failed thread_info read.
    thread_info_failed = (baseline_obs.state == SourceState.FAILED
                           or target_obs.state == SourceState.FAILED)
    needs_target_modules = (not thread_info_failed
                             and any(recorded_start_address(tb[tid])[0] is not None
                                      for tid in added))

    modules_target_available = None
    modules_target = None
    if needs_target_modules:
        # mf_target.modules/get_modules(mf_target) are only ever touched
        # here, inside this branch -- when no added thread has a known
        # StartAddress, nothing below ever consults modules_target/
        # modules_target_available (see the "sa is None" branch further
        # down), so accessing the stream at all would be an unjustified
        # read of data this call never actually needed.
        modules_obs, modules_target = _observe_or_failed(
            "target.modules", mf_target, "modules", get_modules)
        sources["target.modules"] = modules_obs
        # A FAILED target.modules degrades the SAME way an absent one
        # does (module resolution just isn't attempted -- thread add/
        # remove detection itself never needed this stream) rather than
        # aborting the whole thread diff the way a FAILED thread_info
        # side does below -- this stream is a strictly optional
        # enrichment, not a source the diff computation itself depends on.
        # PRESENT_EMPTY still counts as "available" (the stream itself
        # exists; an address just won't resolve, correctly reported as
        # UNREGISTERED, not UNAVAILABLE) -- only ABSENT/FAILED are not.
        modules_target_available = modules_obs.state in (
            SourceState.PRESENT, SourceState.PRESENT_EMPTY)
        # A plain bare-name completeness check here would produce a
        # limitation byte-identical to collect_module_diff's own ("target
        # ModuleListStream not present in this dump" for ABSENT, or the
        # same SOURCE_FAILED text for FAILED) when both fire together
        # under collect_comparison(mode="all") -- scope="thread" +
        # unavailable_fields differentiates the two for EITHER state: this
        # one says WHICH thread-side fields are unavailable as a result,
        # not just that the stream is absent/unreadable.
        # _derive_required_source_limitation applies this customization to
        # both its ABSENT and FAILED branches identically, so the two
        # entities' limitations never collide (and combine_coverage_
        # reports' dedup, which only collapses byte-identical limitations,
        # correctly leaves both in place). affected_count is deliberately
        # not set -- SOURCE_ABSENT's own contract only allows it paired
        # with a counterpart_source whose record_count it must equal
        # exactly (see coverage.py's _validate_source_absent_against_
        # sources), and no such counterpart exists here (this fact is
        # about a SUBSET of target.thread_info's threads -- the added ones
        # with a known address -- not "every record in some counterpart
        # source").
        completeness_checks.append(SourceRequirement(
            "target.modules", scope="thread",
            unavailable_fields=("backing_module_after", "backing_module_context")))

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.thread_info",)),
                            EvaluationRequirement(("target.thread_info",))],
        completeness_checks=completeness_checks,
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
        # Only the two REQUIRED sources abort the whole thread diff --
        # target.modules failing is handled above (degrade, don't abort).
        return [], coverage

    records = []
    for tid in sorted(added):
        sa, _state = recorded_start_address(tb[tid])
        if sa is None:
            backing_module_after = None
            backing_module_context = None
        else:
            mod = addr_to_module(sa, modules_target)
            if mod is not None:
                # mod.name or "(unnamed)" BEFORE ntpath.basename -- same
                # order modules.py's own ModuleRecord.name uses, and for
                # the same reason: ntpath.basename(None) raises TypeError
                # outright (an anonymous module's name is None, not ""),
                # and basename-ing the empty string would otherwise
                # produce "" itself, which the wire's non-empty-string
                # contract for backing_module_after rejects.
                backing_module_after = ntpath.basename(mod.name or "(unnamed)")
                backing_module_context = MODULE_CONTEXT_RESOLVED
            elif modules_target_available:
                backing_module_after = None
                backing_module_context = MODULE_CONTEXT_UNREGISTERED
            else:
                backing_module_after = None
                backing_module_context = MODULE_CONTEXT_UNAVAILABLE
        records.append(ThreadDiffRecord(
            change_type=THREAD_DIFF_ADDED, tid=tid,
            start_address_before=None, start_address_after=hex_address(sa),
            backing_module_after=backing_module_after,
            backing_module_context=backing_module_context))
    for tid in sorted(removed):
        sa, _state = recorded_start_address(ta[tid])
        records.append(ThreadDiffRecord(
            change_type=THREAD_DIFF_REMOVED, tid=tid,
            start_address_before=hex_address(sa), start_address_after=None))
    return records, coverage


def collect_memory_diff(mf_baseline, mf_target) -> "tuple[list, object]":
    """(records, coverage) -- ported from diff.py's diff_memory.
    suspicious_before/_after reuse MemoryRegionRecord.suspicious's own
    SUSPICIOUS_PROTS check rather than diff_memory's own 4-tier console
    categorization (rwx/exec/notable/noise), which stays a future
    console-renderer concern."""
    baseline_obs, raw_baseline = _observe_or_failed(
        "baseline.memory_info", mf_baseline, "memory_info", get_memory_regions)
    target_obs, raw_target = _observe_or_failed(
        "target.memory_info", mf_target, "memory_info", get_memory_regions)
    sources = {"baseline.memory_info": baseline_obs, "target.memory_info": target_obs}

    coverage = build_coverage_report(
        sources,
        evaluation_groups=[EvaluationRequirement(("baseline.memory_info",)),
                            EvaluationRequirement(("target.memory_info",))],
        completeness_checks=["baseline.memory_info", "target.memory_info"],
    )
    if coverage.status == COVERAGE_NOT_EVALUATED:
        return [], coverage
    if baseline_obs.state == SourceState.FAILED or target_obs.state == SourceState.FAILED:
        return [], coverage

    ra = {r.BaseAddress: r for r in raw_baseline}
    rb = {r.BaseAddress: r for r in raw_target}
    added = set(rb) - set(ra)
    removed = set(ra) - set(rb)
    changed = {addr for addr in (set(ra) & set(rb))
               if prot_str(ra[addr].Protect) != prot_str(rb[addr].Protect)}

    records = []
    for addr in sorted(added):
        r = rb[addr]
        protect = prot_str(r.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_ADDED, base_address=hex_address(addr),
            size_before=None, size_after=r.RegionSize,
            protect_before=None, protect_after=protect,
            type_before=None, type_after=prot_str(r.Type),
            suspicious_before=None,
            suspicious_after=any(s in protect for s in SUSPICIOUS_PROTS)))
    for addr in sorted(removed):
        r = ra[addr]
        protect = prot_str(r.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_REMOVED, base_address=hex_address(addr),
            size_before=r.RegionSize, size_after=None,
            protect_before=protect, protect_after=None,
            type_before=prot_str(r.Type), type_after=None,
            suspicious_before=any(s in protect for s in SUSPICIOUS_PROTS),
            suspicious_after=None))
    for addr in sorted(changed):
        r_before, r_after = ra[addr], rb[addr]
        protect_before, protect_after = prot_str(r_before.Protect), prot_str(r_after.Protect)
        records.append(MemoryDiffRecord(
            change_type=MEMORY_DIFF_PROTECTION_CHANGED, base_address=hex_address(addr),
            size_before=r_before.RegionSize, size_after=r_after.RegionSize,
            protect_before=protect_before, protect_after=protect_after,
            type_before=prot_str(r_before.Type), type_after=prot_str(r_after.Type),
            suspicious_before=any(s in protect_before for s in SUSPICIOUS_PROTS),
            suspicious_after=any(s in protect_after for s in SUSPICIOUS_PROTS)))
    return records, coverage


# The identity sources the premise reads, each with the minidump stream a
# parse failure is recorded under (None for the header and the PEB, which
# are not directory streams).
_PREMISE_SOURCES = {
    "header":    None,
    "misc_info": MINIDUMP_STREAM_TYPE.MiscInfoStream,
    "sysinfo":   MINIDUMP_STREAM_TYPE.SystemInfoStream,
    "threads":   MINIDUMP_STREAM_TYPE.ThreadListStream,
    "peb":       None,
    "modules":   MINIDUMP_STREAM_TYPE.ModuleListStream,
}
_SOURCE_PRESENT = "present"
# The streams the loader reconstructs the PEB from.
_PEB_PREREQUISITES = ("sysinfo", "threads")
# The streams that can hold the bytes captured at the PEB image base.
_MEMORY_LIST_STREAMS = (MINIDUMP_STREAM_TYPE.Memory64ListStream,
                        MINIDUMP_STREAM_TYPE.MemoryListStream)

# Reported by the process-identity snapshot when it selects a path, which
# the premise never does: it reports the PEB path and the registered
# module's path as separate facts.
_PATH_SELECTION_DIAGNOSTICS = frozenset({"PROCESS_PATH_SOURCE_FALLBACK"})

# NT object roots a path can start with instead of a drive: \SystemRoot
# (the Windows directory) and \Device\<volume>. The dump records neither
# which directory \SystemRoot is nor which drive letter a volume has.
_NT_ROOT_RE = re.compile(r"^\\(systemroot|device\\[^\\]+)\\")
_DRIVE_RE = re.compile(r"^[a-z]:\\")
# Win32/NT prefixes that do not change which file a path names.
_UNC_PREFIXES = ("\\\\?\\unc\\", "\\??\\unc\\")
_LOCAL_PREFIXES = ("\\\\?\\", "\\??\\", "\\\\.\\")
# An 8.3 short-name component, which names a file under another spelling.
_SHORT_NAME_RE = re.compile(r"~\d")


class _CaptureView:
    """One capture as the premise reads it. Each identity source attribute
    of `mf` is read exactly once; an attribute whose read raises reads as
    None here and its source as failed, so the process-identity snapshot
    built over this view cannot raise on it, and one unreadable source
    costs only the facts read from it. Every other attribute is `mf`'s
    own, so the snapshot's bounded main-image header read reaches the
    real dump."""

    def __init__(self, mf):
        self._mf = mf
        self._raised = set()
        for attr in _PREMISE_SOURCES:
            try:
                value = getattr(mf, attr, None)
            except Exception:
                value = None
                self._raised.add(attr)
            self.__dict__[attr] = value

    def __getattr__(self, name):
        return getattr(self._mf, name)

    def source_state(self, attr: str) -> str:
        """FACT_STATE_FAILED when reading the source raised or its stream
        failed to parse, FACT_STATE_ABSENT when the dump does not hold it,
        else _SOURCE_PRESENT."""
        stream = _PREMISE_SOURCES[attr]
        if attr in self._raised or (stream is not None and stream_failure(self._mf, stream)):
            return FACT_STATE_FAILED
        if self.__dict__[attr] is None:
            return FACT_STATE_ABSENT
        return _SOURCE_PRESENT

    def peb_state(self) -> str:
        """_SOURCE_PRESENT, or why the dump yields no PEB: failed when
        reconstructing it raised, unreconstructed when a stream it is
        reconstructed from is absent or unreadable (so it was never
        attempted), else absent."""
        state = self.source_state("peb")
        if state != FACT_STATE_ABSENT:
            return state
        if peb_failure(self._mf):
            return FACT_STATE_FAILED
        if any(self.source_state(attr) != _SOURCE_PRESENT for attr in _PEB_PREREQUISITES):
            return FACT_STATE_UNRECONSTRUCTED
        return FACT_STATE_ABSENT


def _recorded(value) -> tuple:
    return (value, FACT_STATE_RECORDED) if value is not None else (None, FACT_STATE_UNSET)


def _fact(view: _CaptureView, attr: str, value) -> tuple:
    """(value, state) for a fact read from the single source `attr`."""
    state = view.source_state(attr)
    return _recorded(value) if state == _SOURCE_PRESENT else (None, state)


def _architecture(sysinfo) -> "str | None":
    name = getattr(getattr(sysinfo, "ProcessorArchitecture", None), "name", None)
    return name if isinstance(name, str) and name else None


def _os_version(sysinfo) -> "str | None":
    parts = [getattr(sysinfo, "MajorVersion", None), getattr(sysinfo, "MinorVersion", None),
             getattr(sysinfo, "BuildNumber", None)]
    if not all(isinstance(p, int) and not isinstance(p, bool) for p in parts):
        return None
    return ".".join(str(p) for p in parts)


def _image_machine(view: _CaptureView, snapshot, header_state: "str | None") -> tuple:
    """(value, state) for image_machine, from the shared main-image header
    classification `header_state` (classify_main_image_state)."""
    if header_state is None:
        return None, FACT_STATE_BASE_UNKNOWN
    if header_state == "pe_invalid":
        return None, FACT_STATE_INVALID
    if header_state in ("ok", "short_read"):
        machine = main_image_machine(snapshot.main_image_pe)
        return (machine, FACT_STATE_RECORDED) if machine is not None \
            else (None, FACT_STATE_TRUNCATED)
    # read_failed: bytes captured at the base that could not be read, or a
    # memory list stream that failed to parse, is a failed read; no bytes
    # captured there at all is uncaptured.
    captured = va_range_captured_bytes(view, snapshot.image_base_address,
                                       MAIN_IMAGE_PE_READ_MAX)
    if captured or any(stream_failure(view._mf, stream) for stream in _MEMORY_LIST_STREAMS):
        return None, FACT_STATE_FAILED
    return None, FACT_STATE_UNCAPTURED


def _module_facts(view: _CaptureView, snapshot, base_known: bool) -> "tuple[tuple, ...]":
    """(path, size, timestamp) facts of the ModuleListStream entry
    registered at the PEB image base."""
    if not base_known:
        blocked = FACT_STATE_BASE_UNKNOWN
    elif view.source_state("modules") != _SOURCE_PRESENT:
        blocked = view.source_state("modules")
    elif snapshot.module_claim.match_state != "resolved":
        blocked = FACT_STATE_UNMATCHED
    else:
        size, timestamp = registered_main_module_facts(view, snapshot)
        return tuple(_recorded(value) for value in (snapshot.module_claim.path, size, timestamp))
    return (None, blocked), (None, blocked), (None, blocked)


def _path_form(path: str) -> "tuple[str, str]":
    """(root, rest): `path` case-folded, with Win32/NT prefixes that do not
    change the file it names removed. `root` is "" for a drive or UNC path
    (`rest` is then the whole path), else the NT root it starts with --
    "systemroot" or "device\\<volume>" -- and `rest` the part after it."""
    form = path.replace("/", "\\").casefold()
    for prefix in _UNC_PREFIXES:
        if form.startswith(prefix):
            form = "\\\\" + form[len(prefix):]
            break
    else:
        for prefix in _LOCAL_PREFIXES:
            if form.startswith(prefix):
                form = form[len(prefix):]
                break
    root = _NT_ROOT_RE.match(form)
    return (root.group(1), form[root.end():]) if root else ("", form)


def _across_roots(first: "tuple[str, str]", second: "tuple[str, str]") -> "bool | None":
    """Whether two paths under different roots name the same file. The dump
    records neither where \\SystemRoot points nor which drive a \\Device
    volume is, so this is never True: None when the components the two
    can share agree, so the file may be the same; False when they cannot.
    Two different \\Device volumes are always different files."""
    (root_a, rest_a), (root_b, rest_b) = sorted((first, second))
    if root_a.startswith("device\\") and root_b.startswith("device\\"):
        return False
    # The path relative to its volume, where that is known: a \Device path
    # already is; a drive path is once its drive is removed.
    on_volume = rest_a
    if root_a == "":
        drive = _DRIVE_RE.match(rest_a)
        on_volume = rest_a[drive.end():] if drive else None
    if root_b != "systemroot":
        # A drive path against a \Device volume: the same path on the volume.
        return None if on_volume == rest_b else False
    # \SystemRoot against a drive path or a \Device volume: the Windows
    # directory is the volume's root (the same path on the volume) or any
    # directory below it (a path ending in the same components).
    if on_volume == rest_b or rest_a.endswith("\\" + rest_b):
        return None
    return False


def _paths_agree(first: str, second: str) -> "bool | None":
    """True when two paths name the same file, False when they cannot,
    None when their forms leave it undecidable: roots whose mapping the
    dump does not record (see _across_roots) or an 8.3 short name. A
    shared suffix alone never makes two paths agree."""
    form_a, form_b = _path_form(first), _path_form(second)
    if form_a[0] == form_b[0]:
        agree = form_a[1] == form_b[1]
    else:
        agree = _across_roots(form_a, form_b)
    if agree is False and (_SHORT_NAME_RE.search(form_a[1]) or _SHORT_NAME_RE.search(form_b[1])):
        return None
    return agree


def _capture_diagnostics(side: str, snapshot, header_state, peb_path, module_path) -> list:
    """The snapshot's identity diagnostics for one capture (the same ones
    --process reports); PROCESS_MAIN_IMAGE_PE_INVALID when the bytes at
    the PEB image base are not a valid PE header (--process's own code for
    it); and, unless the file names already disagree
    (PROCESS_MODULE_IDENTITY_MISMATCH), PEB_MODULE_PATH_MISMATCH when the
    PEB path and the registered module's path cannot name the same file
    or PEB_MODULE_PATH_UNRESOLVED when their forms leave that
    undecidable."""
    found = [ComparisonCaptureDiagnostic(side=side, code=d.code, severity=d.severity,
                                         message=d.message)
             for d in snapshot.diagnostics if d.code not in _PATH_SELECTION_DIAGNOSTICS]
    if header_state == "pe_invalid":
        found.append(ComparisonCaptureDiagnostic(
            side=side, code="PROCESS_MAIN_IMAGE_PE_INVALID", severity="warning",
            message=(f"the bytes captured at the PEB image base "
                     f"(0x{snapshot.image_base_address:016x}) are not a valid PE header: "
                     f"{snapshot.main_image_pe.reason or 'rejected'}")))
    if (peb_path is None or module_path is None
            or any(d.code == "PROCESS_MODULE_IDENTITY_MISMATCH" for d in found)):
        return found
    agree = _paths_agree(peb_path, module_path)
    if agree is False:
        found.append(ComparisonCaptureDiagnostic(
            side=side, code="PEB_MODULE_PATH_MISMATCH", severity="warning",
            message=(f"PEB image path ({peb_path}) cannot name the same file as the module "
                     f"registered at the PEB image base ({module_path})")))
    elif agree is None:
        found.append(ComparisonCaptureDiagnostic(
            side=side, code="PEB_MODULE_PATH_UNRESOLVED", severity="info",
            message=(f"PEB image path ({peb_path}) and the path of the module registered at "
                     f"the PEB image base ({module_path}) differ in a form that cannot be "
                     f"reconciled")))
    return found


def _capture_identity(mf, side: str) -> "tuple[tuple, list]":
    """(facts, diagnostics) for one capture: one (value, state) pair per
    COMPARISON_FACTS entry, in that order. Process and main-image facts
    come from build_process_identity_snapshot() -- the boundary --process
    uses -- whose only memory read is the bounded main-image header read
    (MAIN_IMAGE_PE_READ_MAX bytes at the PEB image base). The PEB image
    path states why the dump yields no PEB; the facts located at the PEB
    image base are base_unknown without one."""
    view = _CaptureView(mf)
    snapshot = build_process_identity_snapshot(view)
    peb_state = view.peb_state()
    base_known = peb_state == _SOURCE_PRESENT and snapshot.image_base_address is not None
    header_state = (classify_main_image_state(snapshot.image_base_address, snapshot.main_image_pe)
                    if base_known else None)
    peb_path = (_recorded(snapshot.peb_claim.image_path) if peb_state == _SOURCE_PRESENT
                else (None, peb_state))
    module_path, module_size, module_timestamp = _module_facts(view, snapshot, base_known)
    facts = (
        _fact(view, "header", format_uint32_time_utc(getattr(view.header, "TimeDateStamp", None))),
        _fact(view, "misc_info", snapshot.pid),
        _fact(view, "misc_info", snapshot.process_start_utc),
        _fact(view, "sysinfo", _architecture(view.sysinfo)),
        _fact(view, "sysinfo", _os_version(view.sysinfo)),
        _image_machine(view, snapshot, header_state),
        peb_path,
        module_path,
        module_size,
        module_timestamp,
    )
    return facts, _capture_diagnostics(side, snapshot, header_state, peb_path[0], module_path[0])


def collect_comparison_premise(mf_baseline, mf_target) -> ComparisonPremiseRecord:
    """The identity facts both captures record, side by side, with why
    each one is or is not recorded, and the identity disagreements inside
    each capture. Independent of the inventory comparison: it adds no
    coverage source and never refuses a comparison -- differing or
    missing identity qualifies the records, it does not withhold them."""
    baseline, baseline_diagnostics = _capture_identity(mf_baseline, COMPARISON_SIDE_BASELINE)
    target, target_diagnostics = _capture_identity(mf_target, COMPARISON_SIDE_TARGET)
    return ComparisonPremiseRecord(
        facts=tuple(
            ComparisonFactRecord(fact=fact, baseline=b_value, target=t_value,
                                 baseline_state=b_state, target_state=t_state)
            for fact, (b_value, b_state), (t_value, t_state)
            in zip(COMPARISON_FACTS, baseline, target)),
        capture_diagnostics=tuple(baseline_diagnostics + target_diagnostics))


def collect_comparison(mf_baseline, mf_target, mode: str = "all") -> CommandResult:
    """Mirrors diff.py's cmd_diff() gating (`if mode in (...)`) but
    returns a single CommandResult instead of printing -- one
    kind="comparison" result whose `records` is a tagged union of
    whichever entity types `mode` selected, and whose `coverage` is every
    selected entity's own CoverageReport combined via
    combine_coverage_reports() (unanimous not_evaluated required across
    entities; a single weak entity among otherwise-fine ones is partial,
    not not_evaluated). Takes already-open mf_baseline/mf_target -- same
    shape as cmd_diff's own mf_a (already open) -- opening dumps is the
    caller's job.

    `summary.premise` is collect_comparison_premise()'s record for every
    mode: what the two captures are known to share qualifies how each
    record is read, whichever entities were compared."""
    if mode not in _DIFF_MODES:
        raise ValueError(f"collect_comparison() mode must be one of {_DIFF_MODES}, got {mode!r}")

    all_records = []
    reports = []
    if mode in ("modules", "all"):
        records, coverage = collect_module_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)
    if mode in ("threads", "all"):
        records, coverage = collect_thread_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)
    if mode in ("memory", "all"):
        records, coverage = collect_memory_diff(mf_baseline, mf_target)
        all_records.extend(records)
        reports.append(coverage)

    combined = combine_coverage_reports(reports)
    premise = collect_comparison_premise(mf_baseline, mf_target)
    return CommandResult(kind="comparison", records=all_records, coverage=combined,
                          summary={"count": len(all_records), "premise": premise.to_dict()})
