"""--sysinfo and --pid commands."""
import os
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, DIM, GREEN, YELLOW, console_safe
from dumpex.output.records import SysInfoRecord, PidRecord
from dumpex.output.coverage import (
    observe_source, build_coverage_report, EvaluationRequirement, SourceRequirement,
    CoverageLimitation, LimitationCode, SourceState, SourceObservation, render_limitation,
)
from dumpex.output.command_result import CommandResult
from dumpex.core.process_info import (
    walk_environment_block, parse_environment_entries, normalize_windows_path,
    MAX_ENV_BYTES, MAX_ENV_ENTRIES,
)


def sysinfo_source_present(coverage, name: str) -> bool:
    """True when `name` (one of sysinfo/misc_info/peb/threads/modules)
    was present AND readable -- derived from the CoverageReport's own
    source state rather than a separately-returned flag, matching
    threads.py's/peb.py's is-present helpers. Deliberately PRESENT/
    PRESENT_EMPTY only, not `!= ABSENT`: a FAILED source did not
    successfully yield data, so treating it as "present" here would
    render whatever partial/None fields it left behind as a genuine
    answer instead of surfacing the SOURCE_FAILED reason."""
    return coverage.sources[name].state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY)


def _os_display_name(si) -> str:
    """
    Return a corrected OS name for `si`, fixing the upstream minidump
    library's guess_os(): its build-number table predates Windows 11, so it
    falls through to the generic "MajorVersion==10, MinorVersion==0,
    ProductType==WORKSTATION" branch and always reports "Windows 10" —
    even though Windows 11 keeps the same 10.0.x NT version and is only
    distinguishable by BuildNumber >= 22000.
    """
    os_name = si.OperatingSystem or "Windows (unknown version)"
    ptype   = si.ProductType.name if si.ProductType else None
    if (os_name == "Windows 10" and si.MajorVersion == 10 and si.MinorVersion == 0
            and ptype == "VER_NT_WORKSTATION"
            and isinstance(si.BuildNumber, int) and si.BuildNumber >= 22000):
        return "Windows 11"
    return os_name


# ── --sysinfo ────────────────────────────────────────────────────────────

# walk_environment_block()'s own §4.3.3 scope tokens, mapped to a human-
# readable sentence for coverage.sources["environment_block"].detail when
# state == "unparseable" (see _environment_evidence's own comment on that
# branch for why every token -- not just the None case -- goes through
# this, keeping the field's style consistent with pointer_unreadable's
# own full-sentence detail).
_UNPARSEABLE_DETAIL_TEXT = {
    "environment_bytes": "the first entry's own terminator was never found within the "
                          "captured byte budget",
    "captured_segment": "the first entry's own terminator was never found before the "
                         "captured memory ended",
    "undecodable_entry": "the first entry's own bytes could not be decoded as UTF-16",
}


def _environment_evidence(mf: MinidumpFile):
    """§4.3: independently walk the PEB's environment block via
    dumpex.core.process_info.walk_environment_block() (issue #38) rather
    than trusting mf.peb.environment_variables -- see that function's own
    docstring for why the library's own list cannot be told apart from a
    truncated/malformed one. Returns (SourceObservation, CoverageLimitation
    | None, entries) where `entries` is a tuple of
    process_info.EnvironmentEntry for "present"/"partial", `()` for
    "present_empty", `None` for every other (unavailable) state -- exactly
    §4.3.3's environment_variables null/[]/list rule, ahead of the caller
    projecting it into SysInfoRecord's plain-dict wire shape.

    Only "partial"/"pointer_unreadable"/"unparseable"/
    "architecture_unsupported" ever produce a CoverageLimitation here --
    "unsupported" is deliberately suppressed (its own preconditions,
    sysinfo+threads, are exactly what SYSINFO_PEB_UNAVAILABLE already
    covers whenever it fires -- §4.3.3's duplicate-absence-suppression
    rule), UNLESS `mf.peb` is unexpectedly present anyway, in which case
    ENVIRONMENT_PRECONDITION_INCONSISTENT fires instead (see below --
    this never happens for a real open_dump() output, only for an mf
    assembled directly with the two left out of sync).

    `max_bytes`/`max_entries` are passed to walk_environment_block()
    explicitly (rather than left to its own defaults) so the budget this
    function reports on a "partial" truncation is always the SAME value
    the walk itself was actually bounded by -- never a module-level
    constant assumed, from a distance, to match whatever the walk call
    used."""
    max_bytes, max_entries = MAX_ENV_BYTES, MAX_ENV_ENTRIES
    state, raw_entries, detail = walk_environment_block(mf, max_bytes=max_bytes, max_entries=max_entries)

    if state == "unsupported":
        # The suppression above is only sound because open_dump() builds
        # peb under the exact same "sysinfo and threads" precondition
        # (dumpex/core/memory.py's phase 3b, mirroring the library's own
        # __parse_peb()) -- so mf.peb is provably None whenever this
        # state fires for real. That invariant does not hold for an mf
        # assembled by hand: verified here rather than merely assumed, so
        # a genuine contradiction between "no TEB to walk from" and "a
        # PEB apparently exists anyway" still gets a limitation instead
        # of silently vanishing into environment_variables: null with
        # nothing in coverage.reasons to explain it. This branch is
        # unreachable through any real open_dump() output -- it exists
        # purely so the invariant is verified, not merely assumed.
        if getattr(mf, "peb", None) is not None:
            contradiction_detail = (
                "a PEB is present without the SystemInfoStream/ThreadListStream evidence "
                "the environment walk requires")
            return (SourceObservation(name="environment_block", state=SourceState.FAILED,
                                       detail=contradiction_detail),
                    CoverageLimitation(code=LimitationCode.ENVIRONMENT_PRECONDITION_INCONSISTENT,
                                        source="environment_block"),
                    None)
        return (SourceObservation(name="environment_block", state=SourceState.ABSENT),
                None, None)
    if state == "architecture_unsupported":
        # walk_environment_block() itself returns detail=None for this
        # state (§4.3.2's docstring: "None otherwise") -- the actual
        # architecture name is this contract's own text to compose, from
        # the same sysinfo attribute the walk already consulted.
        arch = getattr(getattr(mf, "sysinfo", None), "ProcessorArchitecture", None)
        arch_detail = getattr(arch, "name", None) or str(arch)
        # collect_sysinfo() suppresses peb.current_directory whenever
        # this code fires AND a peb object actually exists to read a
        # (potentially wrong-offset) value from -- named here via
        # unavailable_fields so that suppression is a visible coverage
        # fact, not a silent null. Conditional on peb being present:
        # when it's None, current_directory is null because there is no
        # PEB at all, a fact SYSINFO_PEB_UNAVAILABLE already owns -- this
        # limitation must not also claim credit for suppressing a value
        # that was never there to suppress (§4.3.3's duplicate-absence
        # rule: two limitations must never describe the same single fact).
        unavailable_fields = ("current_directory",) if getattr(mf, "peb", None) is not None else ()
        return (SourceObservation(name="environment_block", state=SourceState.ABSENT),
                CoverageLimitation(code=LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED,
                                    source="environment_block", detail=arch_detail,
                                    unavailable_fields=unavailable_fields),
                None)
    if state == "pointer_unreadable":
        return (SourceObservation(name="environment_block", state=SourceState.FAILED, detail=detail),
                CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNREADABLE,
                                    source="environment_block", detail=detail),
                None)
    if state == "unparseable":
        # walk_environment_block() itself returns one of four values for
        # `detail` here: None (its one genuinely ambiguous sub-case -- a
        # captured block ending right after a zero-length first "entry",
        # with no proof of whether more block was ever there to read --
        # see that function's own docstring), or one of the §4.3.3 scope
        # tokens ("environment_bytes"/"captured_segment"/
        # "undecodable_entry") when the very FIRST entry's own read
        # stopped before a terminator was found. §4.3.3 requires this
        # source's SourceObservation to always carry a non-null, human-
        # readable `detail` when `failed` -- never a bare machine token
        # (that shape belongs to ENVIRONMENT_BLOCK_TRUNCATED's own
        # `scope` field, not to free-text `detail`), so every one of the
        # four is mapped to its own sentence here rather than only
        # substituting for the None case.
        obs_detail = _UNPARSEABLE_DETAIL_TEXT.get(
            detail, "block capture ended before a terminator could be confirmed")
        return (SourceObservation(name="environment_block", state=SourceState.FAILED, detail=obs_detail),
                CoverageLimitation(code=LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE,
                                    source="environment_block"),
                None)
    if state == "present_empty":
        return (SourceObservation(name="environment_block", state=SourceState.PRESENT_EMPTY,
                                   record_count=0),
                None, ())

    # "present" / "partial" -- §4.4's `=`-prefix-aware name/value split.
    entries = parse_environment_entries(raw_entries)
    limitation = None
    if state == "partial":
        if detail in ("environment_bytes", "environment_entries"):
            budget_limit = max_bytes if detail == "environment_bytes" else max_entries
            # Not merely assumed: _classify_environment_capture() only
            # ever selects this stop reason once the running total
            # (captured bytes / entries kept) has reached max_bytes/
            # max_entries exactly -- neither counter can exceed its own
            # budget (each is checked and stopped at, never past, the
            # limit) -- so the real consumed amount and the configured
            # limit are structurally equal here, not coincidentally so.
            budget_consumed = budget_limit
        else:
            budget_limit = None
            budget_consumed = None
        limitation = CoverageLimitation(
            code=LimitationCode.ENVIRONMENT_BLOCK_TRUNCATED, source="environment_block",
            affected_count=len(entries), scope=detail,
            budget_limit=budget_limit, budget_consumed=budget_consumed)
    return (SourceObservation(name="environment_block", state=SourceState.PRESENT,
                               record_count=len(entries)),
            limitation, entries)


def _hostname_username_from_entries(entries) -> "tuple[str | None, str | None]":
    """COMPUTERNAME/USERNAME from the independently-walked environment
    block (§4.2), never mf.peb.environment_variables. A missing entry
    does not mean the whole block is unavailable -- both simply stay
    None. Last match wins when a name repeats (matches the codebase's
    pre-#41 iteration order), since a genuine environment block would
    not carry duplicate COMPUTERNAME/USERNAME entries in practice.
    `e.value or None` -- never the raw (possibly empty) string -- per
    §1.4: "The empty string is never emitted. A source string that is
    empty ... becomes null." A captured `COMPUTERNAME=`/`USERNAME=` with
    nothing after the `=` is real evidence (the block was walked), but
    the VALUE itself is still unavailable, exactly like every other
    empty-string-to-null field in this codebase."""
    hostname = None
    username = None
    for e in entries or ():
        if e.name.upper() == "COMPUTERNAME":
            hostname = e.value or None
        if e.name.upper() == "USERNAME":
            username = e.value or None
    return hostname, username


def collect_sysinfo(mf: MinidumpFile) -> CommandResult:
    """
    Pure data, no printing. Returns a CommandResult[SysInfoRecord] --
    records is a single-element list even for this one-record result.
    'partial' coverage when the sysinfo/misc-info/PEB/threads/modules/
    environment-block sources are individually missing; never
    'not_evaluated' (no evaluation_sources given) since --sysinfo always
    has at least dump_file (derived from the dump path itself, never
    dependent on any of these six sources) to report -- unlike --pid, a
    single-purpose command that reports nothing at all when all its
    sources are absent. Each of the five SourceRequirement completeness
    checks below uses its own dedicated code: none of these five reasons
    matches the generic SOURCE_ABSENT template's exact wording ("X not
    present in this dump"), and SYSINFO_PEB_UNAVAILABLE's text differs
    from --peb's own PEB_UNAVAILABLE, so it isn't reused across commands.
    `environment_block` is a sixth `coverage.sources` entry but is
    deliberately never declared as a SourceRequirement (§4.3.3/§4.7) --
    every gap it produces is instead a hand-built, caller-buildable
    CoverageLimitation from _environment_evidence(), inserted immediately
    before the `peb` completeness check so the specific environment
    failure reads before the general PEB consequence.
    """
    si  = mf.sysinfo
    mi  = mf.misc_info
    peb = mf.peb

    env_source, env_limitation, env_entries = _environment_evidence(mf)
    hostname, username = _hostname_username_from_entries(env_entries)
    # PEB.from_minidump() (the installed minidump library) computes
    # is_x64 = not (ProcessorArchitecture == INTEL), so it treats EVERY
    # non-INTEL architecture -- ARM64 included -- as x64 and reads
    # ProcessParameters's own scalar fields (current_directory among
    # them, by the identical offset table walk_environment_block()
    # itself refuses to trust here) at potentially wrong offsets. `peb`
    # is not None in that case (§4.3.2), so it would otherwise be treated
    # as ordinary evidence -- but a peb.current_directory read through
    # the same untrustworthy offsets ENVIRONMENT_ARCHITECTURE_UNSUPPORTED
    # already refuses to walk is no more trustworthy than the environment
    # block was, and must not be published as if it were.
    peb_offsets_untrustworthy = (
        env_limitation is not None
        and env_limitation.code == LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED)

    cpu_vendor = None
    if si and si.VendorId:
        try:
            cpu_vendor = bytes(si.VendorId).decode("ascii", errors="replace").rstrip("\x00")
        except Exception:
            cpu_vendor = None

    record = SysInfoRecord(
        dump_file=os.path.basename(mf.filename),
        hostname=hostname,
        username=username,
        os=(_os_display_name(si) if si else None),
        os_version=(f"{si.MajorVersion}.{si.MinorVersion}.{si.BuildNumber}"
                    if si and all(x is not None for x in
                    [si.MajorVersion, si.MinorVersion, si.BuildNumber]) else None),
        architecture=(si.ProcessorArchitecture.name if si and si.ProcessorArchitecture else None),
        product_type=(si.ProductType.name if si and si.ProductType else None),
        processors=(si.NumberOfProcessors if si else None),
        cpu_vendor=cpu_vendor,
        cpu_current_mhz=(mi.ProcessorCurrentMhz if mi and mi.ProcessorCurrentMhz else None),
        cpu_max_mhz=(mi.ProcessorMaxMhz if mi and mi.ProcessorMaxMhz else None),
        # None (not 0) when the stream itself is absent -- "no thread
        # list captured" and "thread list captured, zero threads" are not
        # the same claim, and 0 would silently read as the latter.
        thread_count=(len(mf.threads.threads) if mf.threads else None),
        module_count=(len(mf.modules.modules) if mf.modules else None),
        current_directory=(None if peb_offsets_untrustworthy or not peb
                            else normalize_windows_path(peb.current_directory)),
        environment_variables=(None if env_entries is None
                                else tuple({"name": e.name, "value": e.value} for e in env_entries)),
    )

    si_source      = observe_source("sysinfo", present=bool(si), items=[si] if si else [])
    mi_source      = observe_source("misc_info", present=bool(mi), items=[mi] if mi else [])
    peb_source     = observe_source("peb", present=bool(peb), items=[peb] if peb else [])
    threads_source = observe_source("threads", present=bool(mf.threads),
                                     items=(mf.threads.threads if mf.threads else []))
    modules_source = observe_source("modules", present=bool(mf.modules),
                                     items=(mf.modules.modules if mf.modules else []))
    sources = {
        "sysinfo": si_source, "misc_info": mi_source, "peb": peb_source,
        "threads": threads_source, "modules": modules_source,
        "environment_block": env_source,
    }

    # §4.7's frozen order: sysinfo, misc_info, <environment limitation, if
    # any>, peb, threads, modules.
    completeness_checks = [
        SourceRequirement("sysinfo", absent_code=LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE),
        SourceRequirement("misc_info", absent_code=LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE),
    ]
    if env_limitation is not None:
        completeness_checks.append(env_limitation)
    completeness_checks += [
        SourceRequirement("peb", absent_code=LimitationCode.SYSINFO_PEB_UNAVAILABLE),
        SourceRequirement("threads", absent_code=LimitationCode.SYSINFO_THREADS_UNAVAILABLE),
        SourceRequirement("modules", absent_code=LimitationCode.SYSINFO_MODULES_UNAVAILABLE),
    ]

    coverage = build_coverage_report(sources, completeness_checks=completeness_checks)
    return CommandResult(kind="sysinfo", records=[record], coverage=coverage, summary={"count": 1})


def _environment_console_text(coverage) -> str:
    """§4.6's four-way branch for the "Environment Variables" summary
    line, derived entirely from `coverage` (never a raw walk state the
    renderer would have to be handed separately) -- matches every other
    recon renderer's "only the collected record/coverage" rule."""
    env_obs = coverage.sources["environment_block"]
    if env_obs.state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY):
        return f"{env_obs.record_count} captured (--verbose or --json to view)"
    env_codes = {l.code for l in coverage.limitations if l.source == "environment_block"}
    if LimitationCode.ENVIRONMENT_ARCHITECTURE_UNSUPPORTED in env_codes:
        return "(not supported for this architecture)"
    if LimitationCode.ENVIRONMENT_BLOCK_UNPARSEABLE in env_codes:
        return "(unparseable -- see coverage below)"
    return "(unavailable)"


def render_sysinfo_console(record: SysInfoRecord, coverage, *, verbose: bool = False) -> None:
    """Takes the whole CoverageReport, not three separately-derived
    presence booleans -- each is recomputed here via
    sysinfo_source_present() rather than trusted from a stale call site,
    matching peb.py's render_peb_console(record, coverage) contract."""
    threads_present = sysinfo_source_present(coverage, "threads")
    modules_present = sysinfo_source_present(coverage, "modules")

    # §4.7's ordering guarantee is frozen text, not a suggestion: "this is
    # the order of coverage.limitations AND OF THE CONSOLE'S [~] LINES...
    # an analyst should see 'environment block pointers could not be
    # read: X' and only then 'PEB not available', not the other way
    # round." Every limitation must render EXACTLY ONCE, at the console
    # position matching its own place in that frozen order -- so
    # coverage.limitations is split into three segments around the (at
    # most one) environment_block-sourced entry: reasons before it print
    # in the top SYSTEM INFO block, the environment reason itself prints
    # only inside the ENVIRONMENT section below (§4.6's own sample
    # layout), and reasons after it print immediately following that
    # section -- never duplicated at the top AND locally, which would
    # both restate one line twice and, if the top block were left
    # unfiltered instead, print later-ordered reasons (e.g. modules)
    # before the environment section's own earlier-ordered one.
    before_env, env_only, after_env = [], [], []
    seen_env = False
    for limitation in coverage.limitations:
        if limitation.source == "environment_block":
            env_only.append(limitation)
            seen_env = True
        elif seen_env:
            after_env.append(limitation)
        else:
            before_env.append(limitation)

    print(f"\n{BOLD('═══ SYSTEM INFO ═══')}")
    for limitation in before_env:
        print(YELLOW(f"  [~] {render_limitation(limitation)}"))

    # ── OS ──────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Operating System')}")
    if record.os is not None:
        print(f"    {'OS':<22} {record.os}")
        print(f"    {'Version':<22} {record.os_version or '?'}")
        print(f"    {'Architecture':<22} {record.architecture or '?'}")
        print(f"    {'Product Type':<22} {record.product_type or '?'}")
    else:
        print(f"    {DIM('(sysinfo stream not available)')}")

    # ── Host ────────────────────────────────────────────────────────────
    print(f"\n  {BOLD('Host')}")
    # hostname/username are read from the captured environment block --
    # dump bytes, therefore attacker-controlled. Same rule as peb.py: the
    # console projection escapes, the record and --json keep the exact
    # decoded value.
    print(f"    {'Hostname':<22} {console_safe(record.hostname) or '(unknown)'}")
    print(f"    {'Username':<22} {console_safe(record.username) or '(unknown)'}")

    # ── Environment (§4.6) ─────────────────────────────────────────────
    # A sub-section indented alongside Operating System/Host/CPU/Dump
    # File, not a second top-level command banner -- the contract's own
    # console-layout sample shows "  ═══ ENVIRONMENT ═══" at the same
    # 2-space indent every other subsection header uses.
    print(f"\n  {BOLD('═══ ENVIRONMENT ═══')}")
    print(f"    {'Current Directory':<22} "
           f"{console_safe(record.current_directory) or '(unknown)'}")
    print(f"    {'Environment Variables':<22} {_environment_console_text(coverage)}")
    for limitation in env_only:
        print(YELLOW(f"    [~] {render_limitation(limitation)}"))
    if verbose and record.environment_variables:
        print()
        for entry in record.environment_variables:
            # Arbitrary bytes the process was started with -- §4.5 keeps
            # them unredacted as evidence, which makes escaping the console
            # projection the only thing between a crafted variable and a
            # forged dumpex line.
            print(f"      {console_safe(entry['name'])}={console_safe(entry['value'])}")
    for limitation in after_env:
        print(YELLOW(f"  [~] {render_limitation(limitation)}"))

    # ── CPU ─────────────────────────────────────────────────────────────
    if record.os is not None:
        print(f"\n  {BOLD('CPU')}")
        print(f"    {'Processors':<22} {record.processors}")
        if record.cpu_vendor:
            # bytes(si.VendorId).decode("ascii", errors="replace") -- raw
            # SystemInfoStream bytes, so control characters are reachable.
            print(f"    {'Vendor':<22} {console_safe(record.cpu_vendor)}")
        if record.cpu_current_mhz:
            print(f"    {'Current MHz':<22} {record.cpu_current_mhz}")
        if record.cpu_max_mhz:
            print(f"    {'Max MHz':<22} {record.cpu_max_mhz}")

    # ── Dump metadata ────────────────────────────────────────────────────
    print(f"\n  {BOLD('Dump File')}")
    print(f"    {'File':<22} {record.dump_file}")
    if threads_present:
        print(f"    {'Threads in dump':<22} {record.thread_count}")
    if modules_present:
        print(f"    {'Modules in dump':<22} {record.module_count}")
    print()


def cmd_sysinfo(mf: MinidumpFile, *, verbose: bool = False) -> CommandResult:
    result = collect_sysinfo(mf)
    render_sysinfo_console(result.records[0], result.coverage, verbose=verbose)
    return result


# ── --pid ────────────────────────────────────────────────────────────────

def collect_pid(mf: MinidumpFile) -> CommandResult:
    """
    Report the Process ID recorded in the minidump.

    Tries multiple streams in priority order so the result is as reliable
    as possible even when a dump was produced by a non-standard tool:

      1. MINIDUMP_MISC_INFO  – most authoritative; written by MiniDumpWriteDump
      2. Thread list         – all threads share the same owning PID on Windows;
                               reported as a cross-check when MiscInfo is absent
      3. Exception stream    – contains ThreadId; used purely as a last resort
         (gives TID, not PID, so it is labelled accordingly)

    Pure data, no printing. Returns a CommandResult[PidRecord] --
    'complete' only when MiscInfo directly supplied the PID; 'partial'
    when a weaker fallback path was used (reuses the same human-readable
    explanations the console has always shown, now rendered from
    dumpex.output.coverage's PID_THREAD_LIST_FALLBACK/
    PID_EXCEPTION_TID_FALLBACK/PID_NO_USABLE_FALLBACK codes instead of
    hand-composed here); 'not_evaluated' when none of the three sources
    are present in the dump at all -- there is nothing to fall back to,
    not merely an unreliable answer (PID_SOURCES_ABSENT, via
    EvaluationRequirement, since the wording doesn't fit the generic
    3-source SOURCE_GROUP_ABSENT template).

    The two fallback limitations (thread-list cross-check, exception TID)
    are hand-built CoverageLimitations, not derived by the reducer --
    "MiscInfo didn't yield a usable PID" isn't a plain source-absence fact
    the reducer can infer from SourceObservation state alone (MiscInfo
    can be present yet lack a ProcessId), so this is business logic only
    the command itself can determine, same as threads.py's TID-mismatch
    limitations.
    """
    pid    = None
    source = None

    # ── 1. MiscInfo (most reliable) ──────────────────────────────────────
    mi = mf.misc_info
    if mi and getattr(mi, "ProcessId", None):
        pid    = mi.ProcessId
        source = "MINIDUMP_MISC_INFO (ProcessId field)"

    threads = mf.threads.threads if mf.threads else []
    exc = getattr(mf, "exception", None)
    exc_tid = None

    completeness_checks = []

    # ── 2. Thread list cross-check / fallback ────────────────────────────
    if threads and pid is None:
        tids = [t.ThreadId for t in threads]
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.PID_THREAD_LIST_FALLBACK, source="misc_info",
            counterpart_source="threads", related_tids=tuple(tids)))

    # ── 3. Exception stream – last resort (gives TID, not PID) ───────────
    if exc and pid is None:
        try:
            exc_tid = exc.ThreadId
        except AttributeError:
            pass
        if exc_tid:
            completeness_checks.append(CoverageLimitation(
                code=LimitationCode.PID_EXCEPTION_TID_FALLBACK, source="exception", thread_id=exc_tid))

    record = PidRecord(
        pid=pid,
        source=source,
        # None (not 0) when ThreadListStream itself is absent -- "no
        # thread list captured" and "thread list captured, zero threads"
        # are not the same claim (same rule as SysInfoRecord.thread_count).
        thread_count=(len(threads) if mf.threads else None),
        exc_tid=exc_tid,
    )

    misc_info_source = observe_source("misc_info", present=bool(mi), items=[mi] if mi else [])
    threads_source    = observe_source("threads", present=bool(mf.threads), items=threads)
    exception_source  = observe_source("exception", present=bool(exc), items=[exc] if exc else [])
    sources = {"misc_info": misc_info_source, "threads": threads_source, "exception": exception_source}

    if pid is None and not completeness_checks:
        # A source object can be present yet contribute nothing usable
        # (e.g. mf.threads exists but its own .threads list is empty, or
        # the exception stream exists but carries no ThreadId) -- neither
        # fallback above appended a limitation in that case, which would
        # otherwise leave a non-complete status with empty reasons. Added
        # unconditionally (not gated on an independently-recomputed
        # "are all three sources absent" check) -- if they really are all
        # absent, build_coverage_report's own not_evaluated branch (see
        # evaluation_sources below) reads `sources` directly and returns
        # before ever looking at completeness_checks, so this entry is
        # simply never used in that case rather than needing to be kept
        # in sync with a second, separately-computed condition.
        completeness_checks.append(
            CoverageLimitation(code=LimitationCode.PID_NO_USABLE_FALLBACK, source="misc_info"))

    coverage = build_coverage_report(
        sources,
        evaluation_sources=EvaluationRequirement(
            sources=("misc_info", "threads", "exception"),
            all_absent_code=LimitationCode.PID_SOURCES_ABSENT),
        completeness_checks=completeness_checks,
    )
    return CommandResult(kind="pid", records=[record], coverage=coverage, summary={"count": 1})


def render_pid_console(record: PidRecord, coverage) -> None:
    """Takes the whole CoverageReport, not a bare reasons list -- matches
    peb.py's render_peb_console(record, coverage) contract, so a stale
    call site can't pass a mismatched/incomplete reasons list."""
    print(f"\n{BOLD('═══ PROCESS ID ═══')}")

    if record.pid is not None:
        print(f"  {'PID (decimal)':<26} {GREEN(str(record.pid))}")
        print(f"  {'PID (hex)':<26} {GREEN(f'0x{record.pid:x}')}")
        print(f"  {'Source':<26} {DIM(record.source)}")
        if record.thread_count:
            print(f"  {'Threads in dump':<26} {record.thread_count}")
    else:
        print(f"  {YELLOW('[!] ProcessId not found in MiscInfo stream.')}")

    for w in coverage.reasons:
        print(f"\n  {YELLOW('[~]')} {w}")

    print()


def cmd_pid(mf: MinidumpFile) -> CommandResult:
    result = collect_pid(mf)
    render_pid_console(result.records[0], result.coverage)
    return result
