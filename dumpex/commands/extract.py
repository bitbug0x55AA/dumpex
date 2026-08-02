"""--extract and --strings commands."""
import re
import sys
from pathlib import Path
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW, CYAN
from dumpex.core.memory import read_region
from dumpex.core.safe_io import write_output_bytes, compute_bytes_summary
from dumpex.output.records import ExtractRecord, Artifact, Diagnostic, SEVERITY_WARNING, hex_address
from dumpex.output.coverage import SourceObservation, SourceState, build_coverage_report
from dumpex.output.command_result import CommandResult


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
    ExtractRecord's own docstring for why the two aren't merged. A raised
    read_region() exception is deliberately left unwrapped here (not
    caught into a coverage fact) -- see cmd_extract's own try/except:
    a bad --extract address/size is a usage error with nothing else in
    scope to report, not evidence-completeness gap."""
    data = read_region(mf, addr, size)
    mz_detected = data[:2] == b'MZ'
    out = output or f"region_0x{addr:x}.bin"

    artifact = build_extract_artifact("extract_output", "extracted_region", out, data,
                                       description=f"Bytes extracted from 0x{addr:x}")
    write_output_bytes(out, data, mf.filename, force, "--extract output")

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
    # real (if unconditionally COMPLETE) CoverageReport is still built,
    # for API consistency with every other migrated command.
    source = SourceObservation(name="requested_region", state=SourceState.PRESENT, record_count=1)
    coverage = build_coverage_report(
        {"requested_region": source},
        evaluation_sources=("requested_region",),
        completeness_checks=["requested_region"],
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
    except Exception as e:
        print(RED(f"[!] Read failed: {e}"))
        sys.exit(1)
    render_extract_console(result.records, result.artifacts, result.diagnostics)
    return result


def cmd_strings(mf, addr, size, min_len, grep, encoding, auto_size=False):
    auto_note = DIM(" (auto from region)") if auto_size else ""
    print(f"[*] Extracting strings from 0x{addr:x} (size=0x{size:x}{auto_note}, min={min_len}, enc={encoding})")
    try:
        data = read_region(mf, addr, size)
    except Exception as e:
        print(RED(f"[!] Read failed: {e}")); sys.exit(1)

    results = []
    if encoding in ("ascii", "both"):
        pat = rb'[ -~]{' + str(min_len).encode() + rb',}'
        results += [(m.start(), "ASCII", m.group().decode("ascii", errors="replace"))
                    for m in re.finditer(pat, data)]
    if encoding in ("unicode", "both"):
        pat = rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}'
        results += [(m.start(), "UTF16", m.group().decode("utf-16-le", errors="replace"))
                    for m in re.finditer(pat, data)]

    results.sort(key=lambda x: x[0])
    grep_re = re.compile(grep, re.IGNORECASE) if grep else None

    print(f"\n{BOLD('Offset'):<14} {BOLD('Enc'):<7} {BOLD('String')}")
    print("─" * 70)
    shown = 0
    for offset, enc, s in results:
        if grep_re and not grep_re.search(s):
            continue
        line = f"0x{addr + offset:<12x} {enc:<7} {s}"
        print(YELLOW(line) if grep_re else line)
        shown += 1
    print(f"\n{GREEN(f'[+] {shown} string(s) shown.')}")
