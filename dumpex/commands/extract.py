"""--extract and --strings commands."""
import re
import sys
from pathlib import Path
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN, console_safe
from dumpex.core.memory import (
    read_region, _extract_strings_from_data, RegionReadError, addr_to_module, get_modules,
    get_memory_regions, _get_region_at, prot_str,
)
from dumpex.core.pe_utils import has_executable_protection, is_private_memory_type, parse_pe_header
from dumpex.core.safe_io import write_output_bytes, compute_bytes_summary
from dumpex.output.records import (
    ExtractRecord, StringRecord, Artifact, Diagnostic, SEVERITY_WARNING, hex_address,
    MODULE_CONTEXT_RESOLVED, MODULE_CONTEXT_UNREGISTERED, MODULE_CONTEXT_UNAVAILABLE,
)
from dumpex.output.coverage import (
    SourceObservation, SourceState, CoverageLimitation, LimitationCode, SourceRequirement,
    build_coverage_report, observe_source,
)
from dumpex.output.command_result import CommandResult


class OutputWriteError(RuntimeError):
    """Raised by collect_extract() when writing the --output file itself
    fails (PermissionError, disk full, ...) -- distinguished from
    RegionReadError so cmd_extract's own try/except reports "Write
    failed", not "Read failed", for a problem that has nothing to do with
    reading the dump."""


def _module_context_for(mod, modules_available: bool) -> str:
    """Same rule dumpex.commands.report._module_context_for applies --
    duplicated here (a 3-line, private helper) rather than imported, since
    report.py itself imports from this module (build_extract_artifact) and
    the reverse import would be circular."""
    if mod:
        return MODULE_CONTEXT_RESOLVED
    return MODULE_CONTEXT_UNREGISTERED if modules_available else MODULE_CONTEXT_UNAVAILABLE


def _read_region_or_raise(mf, addr: int, size: int) -> bytes:
    """Shared by collect_extract/collect_strings: the ONLY call in either
    function wrapped into a narrow, purpose-specific exception --
    everything else in their own try blocks (write failures, a bad
    --grep regex, a record/schema construction bug) must propagate as
    itself, not get relabeled as a read failure just because it happened
    to occur inside the same function. See cmd_extract/cmd_strings's own
    narrowed except clauses."""
    try:
        return read_region(mf, addr, size)
    except Exception as exc:
        raise RegionReadError(str(exc)) from exc


def build_extract_artifact(artifact_id: str, kind: str, path: str, data: bytes,
                            description: "str | None" = None) -> Artifact:
    """Shared by collect_extract() here and (a later Phase E migration)
    dumpex.commands.report.py's own optional extract-to-file step --
    both write raw bytes to a file and need the identical size_bytes/
    sha256 shape an Artifact requires, computed once via
    compute_bytes_summary() rather than parsed back out of
    write_output_bytes()'s own display-string return value."""
    size_bytes, sha256 = compute_bytes_summary(data)
    return Artifact(id=artifact_id, kind=kind, path=path,
                     size_bytes=size_bytes, sha256=sha256, description=description)


def collect_extract(mf, addr: int, size: int, output: "str | None",
                     auto_size: bool = False, force: bool = False) -> CommandResult:
    """Read-then-write, then package the read-side facts as an
    ExtractRecord and the write-side facts as an Artifact -- see
    ExtractRecord's own docstring for why the two aren't merged. The
    read is wrapped into RegionReadError (a bad --extract address/size is
    a usage error with nothing else in scope to report, not an evidence-
    completeness gap -- see cmd_extract's own try/except for the exit-1
    path); the write is wrapped into OutputWriteError so the two failure
    modes are never confused with each other or with an unrelated
    Artifact/ExtractRecord construction bug (which must propagate as
    itself, not get mislabeled as either)."""
    data = _read_region_or_raise(mf, addr, size)
    mz_detected = data[:2] == b'MZ'
    out = output or f"region_0x{addr:x}.bin"

    artifact = build_extract_artifact("extract_output", "extracted_region", out, data,
                                       description=f"Bytes extracted from 0x{addr:x}")
    try:
        write_output_bytes(out, data, mf.filename, force, "--extract output")
    except Exception as exc:
        # write_output_bytes' own expected refusals (dump-path collision,
        # already-exists without --force) are sys.exit(1) calls, i.e.
        # SystemExit -- a BaseException, not an Exception subclass, so
        # they are never caught here and propagate untouched, already
        # having printed their own specific message.
        raise OutputWriteError(str(exc)) from exc

    # A bare 'MZ' prefix is not, by itself, evidence of an injected PE --
    # the same domain correction dumpex.commands.report applies to
    # has_injected_pe. Only claim "injected PE" here when module ownership
    # is CONFIRMED absent, the header structurally validates in full (not
    # just its first two bytes), and the containing region is MEM_PRIVATE
    # or carries executable protection -- the same MEM_PRIVATE-or-
    # executable-protection test
    # dumpex.hunt.injection.memory_scan.pe_hit_is_context_scoreable and
    # dumpex.commands.report._scan_content_range both use. Anything weaker
    # stays the honest, bare "MZ header detected" claim under the SAME
    # code this command has always used, never the stronger one -- but
    # WHICH weaker reason applies is tracked and named individually,
    # rather than one sentence listing every possible cause at once, and
    # the two streams this classification depends on (modules,
    # memory_info) are declared as coverage sources so their absence
    # lowers coverage.status instead of silently degrading the claim.
    modules_available = bool(mf.modules)
    mem_info_available = bool(mf.memory_info)
    pe_sources = {}
    pe_completeness_checks = []
    module_context = None
    region_type = region_protect = None
    pe_header_state = None
    confirmed_injected = False
    if mz_detected:
        modules = get_modules(mf) if modules_available else []
        pe_sources["modules"] = observe_source("modules", present=modules_available, items=modules)
        pe_completeness_checks.append(SourceRequirement(
            "modules", absent_code=LimitationCode.EXTRACT_MODULE_CONTEXT_UNAVAILABLE))
        module_context = _module_context_for(addr_to_module(addr, modules), modules_available)

        # MemoryInfoListStream is only consulted -- and only required for
        # completeness -- when module ownership does NOT already settle the
        # question. A known module owning this address confirms it is not
        # an unregistered injected PE regardless of the containing region's
        # memory type, so a dump missing MemoryInfoListStream entirely is
        # not a completeness gap for THIS extraction: nothing memory-type-
        # dependent was left unanswered.
        region = None
        if module_context != MODULE_CONTEXT_RESOLVED:
            regions = get_memory_regions(mf) if mem_info_available else []
            pe_sources["memory_info"] = observe_source(
                "memory_info", present=mem_info_available, items=regions)
            pe_completeness_checks.append(SourceRequirement(
                "memory_info", absent_code=LimitationCode.EXTRACT_MEMORY_INFO_UNAVAILABLE))
            region = _get_region_at(addr, regions) if mem_info_available else None
        region_type = prot_str(region.Type) if region is not None else None
        region_protect = prot_str(region.Protect) if region is not None else None

        # A present MemoryInfoListStream with no descriptor covering this
        # address is deliberately NOT a coverage limitation -- it stays a
        # diagnostic-only fact (see the reasons list below), matching
        # dumpex.commands.report's own long-standing REPORT_REGION_NOT_FOUND
        # precedent for the identical condition ("no committed region
        # found" is loud on the console/diagnostics but never itself moves
        # coverage.status there either). The two commands must not answer
        # "is this a coverage gap" differently for the same dump condition.

        if module_context == MODULE_CONTEXT_UNREGISTERED and region is not None:
            pe = parse_pe_header(data)
            if pe['valid']:
                pe_header_state = "ok"
                confirmed_injected = (is_private_memory_type(region_type)
                                       or has_executable_protection(region_protect))
            else:
                pe_header_state = "short_read" if pe['insufficient_data'] else "pe_invalid"

    record = ExtractRecord(requested_address=hex_address(addr), requested_size=size,
                            auto_sized=auto_size, bytes_read=len(data),
                            mz_header_detected=mz_detected, pe_header_state=pe_header_state)
    diagnostics = []
    if mz_detected:
        if confirmed_injected:
            diagnostics.append(Diagnostic(
                severity=SEVERITY_WARNING,
                message=(f"Valid PE header detected at 0x{addr:x}, outside any loaded "
                         f"module, in {region_type} memory (protect={region_protect}) — "
                         f"possible injected PE"),
                code="EXTRACT_INJECTED_PE_DETECTED"))
        else:
            # Each applicable deficit is named independently, on its own
            # axis -- module ownership and memory type/protection are two
            # separate questions, and a run missing BOTH (e.g. ModuleList
            # absent AND MemoryInfo present-but-not-covering) must name
            # both rather than stopping at whichever axis is checked
            # first. The memory-type axis is only even relevant when a
            # known module does NOT already settle the question --
            # module_context == RESOLVED means region coverage was never
            # consulted at all.
            reasons = []
            if not modules_available:
                reasons.append("ModuleListStream absent -- module ownership could not be checked")
            if module_context != MODULE_CONTEXT_RESOLVED:
                if not mem_info_available:
                    reasons.append(
                        "MemoryInfoListStream absent -- memory type/protection could not be "
                        "checked")
                elif region_type is None:
                    reasons.append("no MemoryInfo region covers this address")
            if not reasons:
                # Every axis that could have blocked confirmation is
                # clear -- module_context is therefore RESOLVED, or
                # (confirmed) UNREGISTERED with a region actually found.
                if module_context == MODULE_CONTEXT_RESOLVED:
                    reasons.append("a known module owns this address")
                elif pe_header_state == "pe_invalid":
                    reasons.append("the header failed structural PE validation")
                elif pe_header_state == "short_read":
                    reasons.append(
                        "too little of the header was captured to structurally validate")
                else:   # pe_header_state == "ok", but neither private nor executable
                    reasons.append(
                        f"the containing region ({region_type}, protect={region_protect}) is "
                        f"neither MEM_PRIVATE nor executable")
            diagnostics.append(Diagnostic(
                severity=SEVERITY_WARNING,
                message=("MZ header detected in the extracted bytes — not independently "
                         "confirmed as an injected PE (" + "; ".join(reasons) + ")"),
                code="EXTRACT_MZ_HEADER_DETECTED"))

    # Always PRESENT on this path -- collect_extract only ever returns
    # after a successful read (see cmd_extract's own try/except for the
    # failure path) -- but CommandResult.coverage is non-optional, so a
    # real CoverageReport is still built, for API consistency with every
    # other migrated command. A short read (read_region() returned fewer
    # bytes than requested -- the region extends past what's actually
    # backed in the dump) is NOT "complete": the source itself stays
    # PRESENT (there IS real data), but REGION_READ_TRUNCATED marks
    # coverage as partial rather than silently reporting the truncated
    # read as a full success -- see LimitationCode.REGION_READ_TRUNCATED's
    # own docstring for why the byte counts live on the record, not here.
    sources = {"requested_region": SourceObservation(
        name="requested_region", state=SourceState.PRESENT, record_count=1)}
    evaluation_sources = ["requested_region"]
    completeness_checks = ["requested_region"]
    if len(data) < size:
        completeness_checks.append(
            CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region"))
    # A DIFFERENT gap from REGION_READ_TRUNCATED above: pe_header_state ==
    # "short_read" means a structural PE parse over an MZ-prefixed
    # candidate could not settle the question (a required header offset
    # fell past what was actually examined) -- independent of whether the
    # raw byte read itself came up short, mirroring dumpex.commands.report's
    # own REPORT_PE_HEADER_VALIDATION_INCOMPLETE for the identical gap.
    if pe_header_state == "short_read":
        completeness_checks.append(CoverageLimitation(
            code=LimitationCode.EXTRACT_PE_HEADER_VALIDATION_INCOMPLETE,
            source="requested_region"))
    sources.update(pe_sources)
    evaluation_sources.extend(pe_sources)
    completeness_checks.extend(pe_completeness_checks)
    coverage = build_coverage_report(
        sources,
        evaluation_sources=tuple(evaluation_sources),
        completeness_checks=completeness_checks,
    )
    # No output_path here -- artifacts[0].path is the one authoritative
    # place the write-side path lives (see build_extract_artifact above).
    # A second copy in `summary` would need its own --redact-paths
    # handling to stay in sync with artifacts[].path's own redaction (see
    # envelope._redact_artifacts) instead of just leaking the full
    # absolute path unredacted every time --redact-paths is set.
    return CommandResult(kind="extract", records=[record], coverage=coverage,
                          summary={"count": 1},
                          diagnostics=diagnostics, artifacts=[artifact])


def render_extract_console(records, artifacts, diagnostics, coverage) -> None:
    """The `"[*] Reading ..."` preamble is NOT printed here -- it must
    print before collect_extract() is even attempted (see cmd_extract),
    so there is something to say even when the read itself fails. Takes
    the whole CoverageReport, not just a bool -- consumes its already-
    rendered `.reasons` (never re-derives a short-read fact from
    `records` itself) the same way render_modules_console/
    render_threads_console do, so a --extract user isn't left staring at
    a normal-looking "[+] Saved" line with no indication the read that
    produced it was actually truncated (coverage.status == "partial",
    exit code 3)."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))
    for d in diagnostics:
        print(YELLOW(f"[!] {d.message}"))
    artifact = artifacts[0]
    summary = f"{artifact.size_bytes} bytes  sha256={artifact.sha256}"
    print(GREEN(f"[+] Saved → {artifact.path}  ({summary})"))


def cmd_extract(mf, addr, size, output, auto_size=False, force=False) -> CommandResult:
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Reading 0x{size:x}{auto_note} bytes from 0x{addr:x} ...")
    try:
        result = collect_extract(mf, addr, size, output, auto_size=auto_size, force=force)
    except RegionReadError as e:
        print(RED(f"[!] Read failed: {e}"))
        sys.exit(1)
    except OutputWriteError as e:
        print(RED(f"[!] Write failed: {e}"))
        sys.exit(1)
    render_extract_console(result.records, result.artifacts, result.diagnostics, result.coverage)
    return result


def collect_strings(mf, addr: int, size: int, min_len: int, grep: "str | None",
                     encoding: str, auto_size: bool = False) -> CommandResult:
    """Read-then-scan, packaging each extracted string as a StringRecord
    regardless of --grep (see StringRecord's own docstring for why
    `matched_grep` is a flag, not a filter). Same RegionReadError-wrapped
    read as collect_extract -- see cmd_strings's own narrowed try/except.
    A malformed --grep pattern's re.error is raised here UNWRAPPED (after
    the read, compiling grep_re below) -- cmd_strings catches it
    separately from RegionReadError, with its own "Invalid --grep regex"
    message."""
    data = _read_region_or_raise(mf, addr, size)
    raw = _extract_strings_from_data(data, min_len=min_len, encoding=encoding)
    grep_re = re.compile(grep, re.IGNORECASE) if grep else None
    records = [
        StringRecord(offset=off, address=hex_address(addr + off), encoding=enc, text=s,
                     matched_grep=(bool(grep_re.search(s)) if grep_re else None))
        for off, enc, s in raw
    ]

    source = SourceObservation(
        name="requested_region",
        state=(SourceState.PRESENT if records else SourceState.PRESENT_EMPTY),
        record_count=len(records))
    completeness_checks = ["requested_region"]
    if len(data) < size:
        # Same short-read gap as collect_extract -- see
        # LimitationCode.REGION_READ_TRUNCATED's own docstring. Unlike
        # ExtractRecord, StringRecord carries no per-request byte counts
        # (it's one record per extracted STRING, not per request), so
        # requested_size/bytes_read/auto_sized live in `summary` instead.
        completeness_checks.append(
            CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region"))
    coverage = build_coverage_report(
        {"requested_region": source},
        evaluation_sources=("requested_region",),
        completeness_checks=completeness_checks,
    )
    shown = sum(1 for r in records if r.matched_grep is not False)
    return CommandResult(kind="strings", records=records, coverage=coverage,
                          summary={"count": len(records), "shown": shown,
                                   "requested_address": hex_address(addr),
                                   "requested_size": size, "bytes_read": len(data),
                                   "auto_sized": auto_size})


def render_strings_console(records, coverage) -> None:
    """The `"[*] Extracting strings ..."` preamble is NOT printed here --
    see render_extract_console's identical note on why it must print
    before collect_strings() is even attempted. Takes the whole
    CoverageReport for the same reason render_extract_console does --
    see its own docstring; a genuinely complete read (coverage.reasons ==
    []) prints nothing extra here, so this is purely additive and never
    changes existing compat-freeze console text."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))
    print(f"\n{BOLD('Offset'):<14} {BOLD('Enc'):<7} {BOLD('String')}")
    print("─" * 70)
    shown = 0
    for r in records:
        if r.matched_grep is False:
            continue
        addr = int(r.address, 16)
        # Extracted memory bytes. The extractor's own `[ -~]{n,}` /
        # `(?:[ -~]NUL){n,}` patterns admit printable ASCII only, so
        # nothing hostile reaches here TODAY -- escaped anyway: that is
        # an invariant of a different module, this is the console
        # boundary, and console_safe() is the identity function on
        # printable text so it costs nothing to not depend on it.
        line = f"0x{addr:<12x} {r.encoding:<7} {console_safe(r.text)}"
        print(YELLOW(line) if r.matched_grep else line)
        shown += 1
    print(f"\n{GREEN(f'[+] {shown} string(s) shown.')}")


def cmd_strings(mf, addr, size, min_len, grep, encoding, auto_size=False) -> CommandResult:
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Extracting strings from 0x{addr:x} (size=0x{size:x}{auto_note}, min={min_len}, enc={encoding})")
    try:
        result = collect_strings(mf, addr, size, min_len, grep, encoding, auto_size=auto_size)
    except RegionReadError as e:
        print(RED(f"[!] Read failed: {e}"))
        sys.exit(1)
    except re.error as e:
        print(RED(f"[!] Invalid --grep regex: {e}"))
        sys.exit(1)
    render_strings_console(result.records, result.coverage)
    return result
