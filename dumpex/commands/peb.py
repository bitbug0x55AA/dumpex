"""--peb command."""
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD
from dumpex.output.records import PebRecord, hex_address
from dumpex.output.coverage import (
    observe_source, build_coverage_report, EvaluationRequirement, LimitationCode, SourceState,
)
from dumpex.output.command_result import CommandResult


def peb_is_present(coverage) -> bool:
    """True when mf.peb itself was present AND readable -- derived from
    the CoverageReport's own source state rather than a separately-
    returned flag, matching threads.py's thread_info_is_degraded()
    pattern. Deliberately PRESENT/PRESENT_EMPTY only, not `!= ABSENT`:
    a FAILED source was NOT successfully read (it raised while parsing),
    so treating it as "present" here would render a record's all-None
    fields as if they were a genuine (if uninformative) answer instead
    of surfacing the SOURCE_FAILED reason below."""
    return coverage.sources["peb"].state in (SourceState.PRESENT, SourceState.PRESENT_EMPTY)


def collect_peb(mf: MinidumpFile) -> CommandResult:
    """
    Pure data, no printing. Returns a CommandResult[PebRecord]. Unlike
    the old cmd_peb (which returned nothing at all when PEB couldn't be
    parsed), this always reports a PebRecord -- all fields None -- so
    `--peb --json out.json` on a dump without a PEB still produces a
    valid, schema-conformant result instead of silently no-op'ing.
    `--peb` has exactly one data source (mf.peb itself); when it's
    absent there is nothing to report at all, not merely an incomplete
    subset -- 'not_evaluated', not 'partial' (which would imply some
    real data was still gathered). The not_evaluated reason
    ("PEB could not be parsed (missing sysinfo or thread list in dump)")
    doesn't fit the generic "X not present in this dump" template, so it
    uses a dedicated code (PEB_UNAVAILABLE) via EvaluationRequirement
    rather than the automatic single-source default.
    """
    peb = mf.peb
    peb_source = observe_source("peb", present=bool(peb), items=[peb] if peb else [])
    sources = {"peb": peb_source}

    if not peb:
        coverage = build_coverage_report(
            sources,
            evaluation_sources=EvaluationRequirement(
                sources=("peb",), all_absent_code=LimitationCode.PEB_UNAVAILABLE),
        )
        return CommandResult(kind="peb", records=[PebRecord()], coverage=coverage, summary={"count": 1})

    env_vars = None
    if peb.environment_variables:
        env_vars = []
        for env in peb.environment_variables:
            k = env.get("name", "") if isinstance(env, dict) else env[0]
            v = env.get("value", "") if isinstance(env, dict) else env[1]
            env_vars.append({"name": k, "value": v})

    record = PebRecord(
        peb_address=hex_address(peb.address),
        being_debugged=peb.being_debugged,
        image_base_address=hex_address(peb.image_base_address),
        image_path=peb.image_path or None,
        command_line=peb.command_line or None,
        window_title=peb.window_title or None,
        dll_path=peb.dll_path or None,
        current_directory=peb.current_directory or None,
        standard_input=(hex_address(peb.standard_input) if peb.standard_input is not None else None),
        standard_output=(hex_address(peb.standard_output) if peb.standard_output is not None else None),
        standard_error=(hex_address(peb.standard_error) if peb.standard_error is not None else None),
        environment_variables=env_vars,
    )
    coverage = build_coverage_report(sources, evaluation_sources=("peb",))
    return CommandResult(kind="peb", records=[record], coverage=coverage, summary={"count": 1})


def render_peb_console(record: PebRecord, coverage) -> None:
    """Takes the whole CoverageReport, not a (present, reasons) pair --
    peb_present and the reason text both derive from it here, so there is
    no way to call this with one but not the other (a stale two-argument
    call site silently printing nothing, as an earlier (present, reasons)
    split with a defaulted reasons param allowed)."""
    if not peb_is_present(coverage):
        # The same rendered text JSON reports, sourced from coverage.py's
        # PEB_UNAVAILABLE template -- printed here rather than duplicated
        # as a separate literal, so console and JSON can never drift
        # apart on this wording.
        for reason in coverage.reasons:
            print(f"[!] {reason}")
        return

    print(f"\n{BOLD('═══ PEB ═══')}")
    print(f"  {'PEB Address':<24} {record.peb_address}")
    print(f"  {'BeingDebugged':<24} {record.being_debugged}")
    print(f"  {'ImageBaseAddress':<24} {record.image_base_address}")
    print(f"  {'ImagePath':<24} {record.image_path or '(none)'}")
    print(f"  {'CommandLine':<24} {record.command_line or '(none)'}")
    print(f"  {'WindowTitle':<24} {record.window_title or '(none)'}")
    print(f"  {'DllPath':<24} {record.dll_path or '(none)'}")
    print(f"  {'CurrentDirectory':<24} {record.current_directory or '(none)'}")
    print(f"  {'StandardInput':<24} {record.standard_input}")
    print(f"  {'StandardOutput':<24} {record.standard_output}")
    print(f"  {'StandardError':<24} {record.standard_error}")

    if record.environment_variables:
        print(f"\n  {BOLD('Environment Variables:')}")
        for env in record.environment_variables:
            print(f"    {env['name']}={env['value']}")


def cmd_peb(mf: MinidumpFile) -> CommandResult:
    result = collect_peb(mf)
    render_peb_console(result.records[0], result.coverage)
    return result
