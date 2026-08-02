"""--extract and --strings commands."""
import re
import sys
from pathlib import Path
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import read_region, _extract_strings_from_data, RegionReadError
from dumpex.core.safe_io import write_output_bytes, compute_bytes_summary
from dumpex.output.records import (
    ExtractRecord, StringRecord, Artifact, Diagnostic, SEVERITY_WARNING, hex_address,
)
from dumpex.output.coverage import (
    SourceObservation, SourceState, CoverageLimitation, LimitationCode, build_coverage_report,
)
from dumpex.output.command_result import CommandResult


class OutputWriteError(RuntimeError):
    """Raised by collect_extract() when writing the --output file itself
    fails (PermissionError, disk full, ...) -- distinguished from
    RegionReadError so cmd_extract's own try/except reports "Write
    failed", not "Read failed", for a problem that has nothing to do with
    reading the dump."""


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

    record = ExtractRecord(requested_address=hex_address(addr), requested_size=size,
                            auto_sized=auto_size, bytes_read=len(data),
                            mz_header_detected=mz_detected)
    diagnostics = []
    if mz_detected:
        diagnostics.append(Diagnostic(
            severity=SEVERITY_WARNING,
            message="MZ header detected — this looks like an injected PE!",
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
    source = SourceObservation(name="requested_region", state=SourceState.PRESENT, record_count=1)
    completeness_checks = ["requested_region"]
    if len(data) < size:
        completeness_checks.append(
            CoverageLimitation(code=LimitationCode.REGION_READ_TRUNCATED, source="requested_region"))
    coverage = build_coverage_report(
        {"requested_region": source},
        evaluation_sources=("requested_region",),
        completeness_checks=completeness_checks,
    )
    return CommandResult(kind="extract", records=[record], coverage=coverage,
                          summary={"count": 1, "output_path": out},
                          diagnostics=diagnostics, artifacts=[artifact])


def render_extract_console(records, artifacts, diagnostics) -> None:
    """The `"[*] Reading ..."` preamble is NOT printed here -- it must
    print before collect_extract() is even attempted (see cmd_extract),
    so there is something to say even when the read itself fails."""
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
    render_extract_console(result.records, result.artifacts, result.diagnostics)
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
                                   "requested_size": size, "bytes_read": len(data),
                                   "auto_sized": auto_size})


def render_strings_console(records) -> None:
    """The `"[*] Extracting strings ..."` preamble is NOT printed here --
    see render_extract_console's identical note on why it must print
    before collect_strings() is even attempted."""
    print(f"\n{BOLD('Offset'):<14} {BOLD('Enc'):<7} {BOLD('String')}")
    print("─" * 70)
    shown = 0
    for r in records:
        if r.matched_grep is False:
            continue
        addr = int(r.address, 16)
        line = f"0x{addr:<12x} {r.encoding:<7} {r.text}"
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
    render_strings_console(result.records)
    return result
