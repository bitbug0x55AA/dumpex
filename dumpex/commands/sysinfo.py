"""--sysinfo and --pid commands."""
import os
import re
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD, CYAN, DIM, GREEN, YELLOW, console_safe
from dumpex.ui.console_layout import resolve_width
from dumpex.output.records import SysInfoRecord, PidRecord
from dumpex.output.coverage import (
    observe_source, build_coverage_report, EvaluationRequirement, SourceRequirement,
    CoverageLimitation, LimitationCode, SourceState, SourceObservation, render_limitation,
)
from dumpex.output.command_result import CommandResult
from dumpex.core.process_info import (
    walk_environment_block, parse_environment_entries, normalize_windows_path,
    format_uint32_time_utc, MAX_ENV_BYTES, MAX_ENV_ENTRIES,
)
from dumpex.core.evidence import cached_sha256_file


def sysinfo_source_present(coverage, name: str) -> bool:
    """True when `name` (one of dump_file/sysinfo/misc_info/peb/threads/
    modules) was present AND readable -- derived from the CoverageReport's own
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


def _dump_file_identity(path) -> "tuple[int | None, str | None, str | None]":
    """(size_bytes, sha256, failure_detail) for the dump file itself.

    The only --sysinfo evidence that is not already in memory: every other
    field is read off an already-parsed `mf`, while size/SHA-256 require
    going back to disk. Both are reported together or not at all -- they
    are one claim ("this is the evidence file dumpex looked at"), and a
    size without a digest identifies nothing.

    Hashing goes through evidence.cached_sha256_file() rather than
    sha256_file(), so a `--sysinfo --json` run reads a multi-gigabyte dump
    once for both this record and meta.evidence's own sha256, and the two
    can never report different digests for the same file.

    `size_bytes` is the number of bytes actually hashed rather than a
    separate os.path.getsize() call: it then describes exactly the bytes
    that produced `sha256`, instead of being a second, independently-timed
    observation that a file changing under us could put out of step with
    the digest. Returns the OS error's text as the third element (with
    both values None) rather than raising -- collect_sysinfo() turns it
    into SYSINFO_DUMP_FILE_UNREADABLE, since one unreadable evidence file
    must not cost the analyst every other field the dump already yielded.
    """
    if not isinstance(path, str) or not path:
        return None, None, "no dump path recorded on the parsed dump"
    try:
        sha256 = cached_sha256_file(path)
        size = os.path.getsize(path)
    except (OSError, ValueError) as e:
        # ValueError as well as OSError: os.stat()/open() reject a
        # structurally invalid path (an embedded NUL, most notably) with
        # ValueError, not OSError, and letting that one escape would cost
        # the analyst every other field the already-parsed dump still
        # holds -- the exact opposite of what this guard is for.
        return None, None, f"{type(e).__name__}: {e}"
    return size, sha256, None


def _dump_time_utc(mf: MinidumpFile) -> "str | None":
    """MinidumpHeader.TimeDateStamp as the contract's UTC string, or None.

    Read off the header rather than any directory stream: open_dump()'s
    phase 1 parses the header before any per-stream parser runs and exits
    1 if it cannot, so by the time this runs the header is present for
    every dump that got this far -- which is why no coverage source or
    limitation is declared for it. A `0` (the producer never filled the
    field in) or an out-of-UINT32-range value normalizes to None, the same
    field-level "present but not certifiable" rule cpu_vendor already
    follows here.

    getattr-guarded because test fakes and hand-assembled MinidumpFile
    objects do not always carry a header, and a missing one is exactly the
    same answer as an unset TimeDateStamp: no dump timestamp available.

    `header.TimeDateStamp` is only the real timestamp because open_dump()'s
    phase 1 corrects it: the installed minidump library reads
    MINIDUMP_HEADER's Reserved/TimeDateStamp union as two separate fields
    and lands Flags's low 32 bits in TimeDateStamp instead (see
    dumpex.core.memory._correct_header_union). An `mf` built by hand,
    without going through open_dump(), carries the library's uncorrected
    value -- which is why the fix lives at the single loader, not here.
    """
    header = getattr(mf, "header", None)
    return format_uint32_time_utc(getattr(header, "TimeDateStamp", None))


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
    environment-block/dump-file sources are individually missing; never
    'not_evaluated' (no evaluation_sources given) since --sysinfo always
    has at least `dump_file`'s basename (derived from the dump path
    itself, never dependent on any of these seven sources) to report --
    unlike --pid, a single-purpose command that reports nothing at all
    when all its sources are absent. Each of the five SourceRequirement
    completeness checks below uses its own dedicated code: none of these
    five reasons matches the generic SOURCE_ABSENT template's exact
    wording ("X not present in this dump"), and SYSINFO_PEB_UNAVAILABLE's
    text differs from --peb's own PEB_UNAVAILABLE, so it isn't reused
    across commands.

    Two of the seven `coverage.sources` entries -- `environment_block`
    (§4.3.3) and `dump_file` (§4.2) -- are deliberately never declared as
    SourceRequirements: every gap they produce is instead a hand-built,
    caller-buildable CoverageLimitation, so the reason an analyst reads
    names the actual failure rather than the generic absent/failed
    template. `dump_file` is also the one source whose evidence is not
    already in memory: establishing it re-reads the file from disk.
    """
    si  = mf.sysinfo
    mi  = mf.misc_info
    peb = mf.peb

    env_source, env_limitation, env_entries = _environment_evidence(mf)
    hostname, username = _hostname_username_from_entries(env_entries)
    dump_size, dump_sha256, dump_read_failure = _dump_file_identity(
        getattr(mf, "filename", None))
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
        dump_file_size_bytes=dump_size,
        dump_sha256=dump_sha256,
        dump_time_utc=_dump_time_utc(mf),
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
    # The dump file itself, observed exactly like environment_block (§4.3.3):
    # a real `coverage.sources` key with NO SourceRequirement of its own, so
    # the gap it can produce is the hand-built SYSINFO_DUMP_FILE_UNREADABLE
    # below rather than an auto-derived SOURCE_FAILED. The generic
    # SOURCE_FAILED template ("... present but could not be read") would be
    # the wrong claim here: the commonest failure is a file that is no longer
    # present at all, which that wording asserts it is.
    #
    # record_count=1 for the PRESENT case because SourceObservation
    # requires a positive count there and this source yields exactly one
    # thing: the file's identity (size + digest), established or not.
    dump_file_source = SourceObservation(
        name="dump_file",
        state=(SourceState.PRESENT if dump_read_failure is None else SourceState.FAILED),
        record_count=(1 if dump_read_failure is None else None),
        detail=dump_read_failure)
    sources = {
        "dump_file": dump_file_source,
        "sysinfo": si_source, "misc_info": mi_source, "peb": peb_source,
        "threads": threads_source, "modules": modules_source,
        "environment_block": env_source,
    }

    # §4.7's frozen order, which is SECTION order (§4.6): the console's
    # three top-level banners are DUMP, SYSTEM INFO, ENVIRONMENT, and each
    # limitation renders under the section that owns the field it explains
    # -- so declaring them in that same order keeps coverage.limitations
    # and the console's [~] lines a single sequence, exactly as before,
    # rather than making the renderer reorder one against the other.
    #
    #   DUMP         <dump-file limitation, if any>, threads, modules
    #   SYSTEM INFO  sysinfo, misc_info
    #   ENVIRONMENT  <environment limitation, if any>, peb
    #
    # The environment-before-peb rule §4.7 froze survives verbatim: the
    # two stay adjacent and in that order, so an analyst still reads
    # "environment block pointers could not be read: X" before the general
    # "PEB not available" consequence, never the other way round.
    completeness_checks = []
    if dump_read_failure is not None:
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.SYSINFO_DUMP_FILE_UNREADABLE, source="dump_file",
            detail=dump_read_failure))
    completeness_checks += [
        SourceRequirement("threads", absent_code=LimitationCode.SYSINFO_THREADS_UNAVAILABLE),
        SourceRequirement("modules", absent_code=LimitationCode.SYSINFO_MODULES_UNAVAILABLE),
        SourceRequirement("sysinfo", absent_code=LimitationCode.SYSINFO_SYSTEM_INFO_UNAVAILABLE),
        SourceRequirement("misc_info", absent_code=LimitationCode.SYSINFO_MISC_INFO_UNAVAILABLE),
    ]
    if env_limitation is not None:
        completeness_checks.append(env_limitation)
    completeness_checks.append(
        SourceRequirement("peb", absent_code=LimitationCode.SYSINFO_PEB_UNAVAILABLE))

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


# ── --verbose environment listing (§4.6.1) ───────────────────────────────

_ENV_INDENT = 6                 # matches the listing's existing indent
_ENV_NAME_MIN_WIDTH = 14        # a narrow dump still gets a scannable column
_ENV_NAME_MAX_WIDTH = 30        # ... and one pathological name can't widen it
_ENV_GUTTER = 2                 # spaces between the name and value columns

# Break a wrapped value only at these separators, and only AFTER them, so
# a reader can see the piece is continued. `;` first because that is what
# every Windows list-valued variable (Path, PATHEXT, PSModulePath) uses.
_ENV_VALUE_BREAK_AFTER = ";,"

# console_safe() renders a control character as the literal text `\xNN` or
# `\uNNNN`. Those must never be split across a wrap, or the evidence reads
# as a different byte than it was -- so a value is tokenized into escape
# sequences and single characters, and a break can only fall BETWEEN
# tokens.
_ENV_ESCAPE_TOKEN_RE = re.compile(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|.", re.DOTALL)


def _wrap_env_value(value: str, width: int) -> list:
    """Split an already-console_safe()d value into display lines of at
    most `width` columns.

    Lossless by construction: `"".join(result) == value`. Nothing is
    inserted (no ellipsis, no continuation marker inside the text) and
    nothing is dropped, so an analyst reading a wrapped `Path` across four
    lines is reading the exact captured value -- this is soft wrapping,
    not truncation, and §4.5 keeps environment values unredacted as
    evidence.

    Break preference, in order:
      1. just after a `;`/`,` -- the natural boundary of the list-valued
         variables that make this listing unreadable in the first place;
      2. just after whitespace, for prose-like values;
      3. anywhere a token boundary allows, for one long unbroken token
         (a URL, a base64 blob) -- overflowing the terminal instead would
         re-create the wall of text this exists to fix.
    A `\\xNN`/`\\uNNNN` escape produced by console_safe() is one token and
    is never broken into.
    """
    if not value:
        return []
    tokens = _ENV_ESCAPE_TOKEN_RE.findall(value)
    lines, start = [], 0
    while start < len(tokens):
        if len(tokens) - start <= width:
            lines.append("".join(tokens[start:]))
            break
        window = tokens[start:start + width]
        # Rightmost separator inside the window: the fullest line that
        # still ends on a boundary. `+ 1` keeps the separator itself on
        # the line it terminates.
        cut = max((i + 1 for i, t in enumerate(window) if t in _ENV_VALUE_BREAK_AFTER),
                   default=0)
        if not cut:
            cut = max((i + 1 for i, t in enumerate(window) if t.isspace()), default=0)
        if not cut:
            cut = len(window)   # no boundary at all -- break on the token grid
        lines.append("".join(tokens[start:start + cut]))
        start += cut
    return lines


def _render_environment_entries(entries, *, width: "int | None" = None) -> None:
    """Print the --verbose `name`/`value` listing as an aligned two-column
    block (§4.6.1).

    The listing used to be one flat `name=value` per line. With a real
    dump's ~40 variables that is unreadable for two compounding reasons:
    names vary from 2 to 30-odd characters, so there is no column for the
    eye to follow, and the handful of `;`-joined list values (`Path` above
    all) run far past the terminal and hard-wrap at column 0, destroying
    what block structure the rest of the listing had.

    So: names are padded to a shared column, values wrap under their own
    column with a hanging indent, and `Path` breaks after its semicolons.
    The `=` separator is dropped rather than padded around, because
    padding it would stop the line being the literal `name=value` anyway
    while keeping it harder to scan -- and this listing is the human
    projection; `--json`/`--csv` remain the machine-readable forms and are
    untouched.

    Every name and value goes through console_safe() FIRST, and all
    measuring, padding, and wrapping happens on the escaped text. Doing it
    the other way round would both mis-align the columns (an escape
    expands) and, worse, let a crafted variable wrap in a way that forges
    a line -- §4.5 keeps these values unredacted precisely because they
    are evidence, which is what makes them attacker-controlled.
    """
    safe = [(console_safe(e["name"]), console_safe(e["value"])) for e in entries]
    total = resolve_width(width)

    longest = max((len(name) for name, _ in safe), default=0)
    name_width = max(_ENV_NAME_MIN_WIDTH, min(_ENV_NAME_MAX_WIDTH, longest))
    value_column = _ENV_INDENT + name_width + _ENV_GUTTER
    value_width = max(20, total - value_column)
    pad = " " * value_column

    for name, value in safe:
        lines = _wrap_env_value(value, value_width)
        if len(name) > name_width:
            # An over-long name gets its own line rather than shoving the
            # value column right for all 40 entries. Deliberately not
            # truncated: the name is evidence too.
            print(f"{' ' * _ENV_INDENT}{CYAN(name)}")
            for line in lines or [DIM("(empty)")]:
                print(f"{pad}{line}")
            continue
        # Padded BEFORE colouring: colouring first would make the ANSI
        # escape count toward the field width and break the column
        # whenever colour is enabled.
        label = CYAN(f"{name:<{name_width}}")
        first = lines[0] if lines else DIM("(empty)")
        print(f"{' ' * _ENV_INDENT}{label}{' ' * _ENV_GUTTER}{first}")
        for line in lines[1:]:
            print(f"{pad}{line}")


_SIZE_UNITS = ("KiB", "MiB", "GiB", "TiB")


def _format_size(size_bytes: int) -> str:
    """Console projection of a byte count: the exact number always, with a
    binary-unit approximation in front of it once the file is big enough
    for the digits alone to be unreadable ("2.1 GiB (2254857216 bytes)").

    The exact count is never replaced, only prefixed -- a size is evidence
    an analyst may need to match against a hash manifest or a file listing,
    and "2.1 GiB" matches nothing. Binary units (not decimal MB/GB), since
    that is what every Windows tool an analyst would cross-check against
    reports."""
    scaled, unit = float(size_bytes), None
    for candidate in _SIZE_UNITS:
        if scaled < 1024:
            break
        scaled /= 1024
        unit = candidate
    if unit is None:
        return f"{size_bytes} bytes"
    return f"{scaled:.1f} {unit} ({size_bytes} bytes)"


# §4.6's section ownership: which top-level console section prints the
# [~] line for a limitation carrying a given `source`. A limitation
# renders under the section that owns the FIELD it explains -- "ThreadList
# Stream not present (thread_count unavailable)" belongs next to the
# Threads-in-dump line, not above the OS table -- which is also why
# collect_sysinfo() declares its completeness_checks in this same order
# (§4.7), so coverage.limitations and the console's [~] lines stay one
# sequence instead of two that a reader has to reconcile.
_SECTION_SOURCES = {
    "DUMP":        ("dump_file", "threads", "modules"),
    "SYSTEM INFO": ("sysinfo", "misc_info"),
    "ENVIRONMENT": ("environment_block", "peb"),
}
# Inverted once at import, and asserted to be a partition: a source listed
# under two sections would print its limitation twice, and one listed
# under none would drop it silently. Both are exactly the "renders exactly
# once" bugs §4.6 says this contract has already caught in past
# implementations, so the structure enforces it rather than the renderer
# re-deriving it per call.
_SECTION_BY_SOURCE = {}
for _section, _sources in _SECTION_SOURCES.items():
    for _source in _sources:
        assert _source not in _SECTION_BY_SOURCE, f"{_source} owned by two sections"
        _SECTION_BY_SOURCE[_source] = _section


def _limitations_by_section(coverage) -> dict:
    """coverage.limitations split into one list per console section,
    each keeping coverage.limitations' own relative order.

    An unrecognized source (none exists today; a future one added to
    collect_sysinfo without a _SECTION_SOURCES entry would) falls back to
    the DUMP section rather than vanishing: printing a reason under a
    slightly odd heading is a cosmetic defect, silently dropping one is an
    evidence defect."""
    by_section = {name: [] for name in _SECTION_SOURCES}
    for limitation in coverage.limitations:
        by_section[_SECTION_BY_SOURCE.get(limitation.source, "DUMP")].append(limitation)
    return by_section


def _render_section_limitations(limitations) -> None:
    for limitation in limitations:
        print(YELLOW(f"  [~] {render_limitation(limitation)}"))


def render_sysinfo_console(record: SysInfoRecord, coverage, *, verbose: bool = False) -> None:
    """Takes the whole CoverageReport, not three separately-derived
    presence booleans -- each is recomputed here via
    sysinfo_source_present() rather than trusted from a stale call site,
    matching peb.py's render_peb_console(record, coverage) contract.

    §4.6's layout is three PEER top-level sections, in this order:

        ═══ DUMP ═══           what file this is, and how much is in it
        ═══ SYSTEM INFO ═══    the machine the process ran on
        ═══ ENVIRONMENT ═══    the process's own environment block

    All three carry the same `═══ X ═══` banner at column 0 and put their
    fields at the same 4-space indent, so the value column lines up across
    the whole command and no section reads as nested inside another. That
    last part is the actual defect this layout fixes: ENVIRONMENT used to
    be a `  ═══ ENVIRONMENT ═══` banner in the MIDDLE of SYSTEM INFO's own
    subsections, and a banner is how a terminal reader segments output --
    indentation is not. CPU and Dump File printed after it were therefore
    read as belonging to ENVIRONMENT even though they never did
    structurally, which is precisely what an analyst reported.
    """
    threads_present = sysinfo_source_present(coverage, "threads")
    modules_present = sysinfo_source_present(coverage, "modules")
    section_limitations = _limitations_by_section(coverage)

    # ── DUMP ────────────────────────────────────────────────────────────
    # First, because it answers "which artifact am I even looking at?" --
    # the question every other section's answer is qualified by.
    print(f"\n{BOLD('═══ DUMP ═══')}")
    _render_section_limitations(section_limitations["DUMP"])
    print(f"    {'File':<22} {record.dump_file}")
    if record.dump_file_size_bytes is not None:
        print(f"    {'Size':<22} {_format_size(record.dump_file_size_bytes)}")
    if record.dump_sha256 is not None:
        print(f"    {'SHA-256':<22} {record.dump_sha256}")
    if record.dump_time_utc is not None:
        print(f"    {'Dump Time':<22} {record.dump_time_utc}")
    if threads_present:
        print(f"    {'Threads in dump':<22} {record.thread_count}")
    if modules_present:
        print(f"    {'Modules in dump':<22} {record.module_count}")

    # ── SYSTEM INFO ─────────────────────────────────────────────────────
    print(f"\n{BOLD('═══ SYSTEM INFO ═══')}")
    _render_section_limitations(section_limitations["SYSTEM INFO"])

    print(f"\n  {BOLD('Operating System')}")
    if record.os is not None:
        print(f"    {'OS':<22} {record.os}")
        print(f"    {'Version':<22} {record.os_version or '?'}")
        print(f"    {'Architecture':<22} {record.architecture or '?'}")
        print(f"    {'Product Type':<22} {record.product_type or '?'}")
    else:
        print(f"    {DIM('(sysinfo stream not available)')}")

    print(f"\n  {BOLD('Host')}")
    # hostname/username are read from the captured environment block --
    # dump bytes, therefore attacker-controlled. Same rule as peb.py: the
    # console projection escapes, the record and --json keep the exact
    # decoded value.
    print(f"    {'Hostname':<22} {console_safe(record.hostname) or '(unknown)'}")
    print(f"    {'Username':<22} {console_safe(record.username) or '(unknown)'}")

    # CPU stays a SYSTEM INFO subsection alongside Operating System/Host:
    # processor count/vendor/clocks describe the machine, not the
    # process's environment.
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

    # ── ENVIRONMENT (§4.6) ──────────────────────────────────────────────
    # Last, and a peer of the two above rather than a subsection of
    # SYSTEM INFO: with --verbose it can run to hundreds of lines, so
    # anything printed after it is effectively invisible.
    print(f"\n{BOLD('═══ ENVIRONMENT ═══')}")
    # Above the fields AND above the --verbose list, so a reader learns
    # the capture was truncated/unreadable before reading what it yielded
    # -- §4.6's "the truncation [~] line is printed above the list".
    _render_section_limitations(section_limitations["ENVIRONMENT"])
    print(f"    {'Current Directory':<22} "
           f"{console_safe(record.current_directory) or '(unknown)'}")
    print(f"    {'Environment Variables':<22} {_environment_console_text(coverage)}")
    if verbose and record.environment_variables:
        # Arbitrary bytes the process was started with -- §4.5 keeps them
        # unredacted as evidence, which makes escaping the console
        # projection the only thing between a crafted variable and a
        # forged dumpex line. _render_environment_entries() owns that.
        print()
        _render_environment_entries(record.environment_variables)
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
