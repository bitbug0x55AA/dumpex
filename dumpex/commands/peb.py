"""--peb command."""
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import BOLD
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.output.records import ProcessInfoRecord, hex_address

_PEB_MISSING_REASON = "PEB could not be parsed (missing sysinfo or thread list in dump)"


def collect_peb(mf: MinidumpFile):
    """
    Pure data, no printing. Returns (records, coverage_status,
    coverage_reasons, peb_present). Unlike the old cmd_peb (which
    returned nothing at all when PEB couldn't be parsed), this always
    reports a ProcessInfoRecord -- all fields None, coverage 'partial' --
    so `--peb --json out.json` on a dump without a PEB still produces a
    valid, schema-conformant result instead of silently no-op'ing.
    """
    peb = mf.peb
    if not peb:
        record = ProcessInfoRecord()
        coverage_status = derive_coverage_status(evaluated=True, complete=False)
        return [record], coverage_status, [_PEB_MISSING_REASON], False

    env_vars = None
    if peb.environment_variables:
        env_vars = []
        for env in peb.environment_variables:
            k = env.get("name", "") if isinstance(env, dict) else env[0]
            v = env.get("value", "") if isinstance(env, dict) else env[1]
            env_vars.append({"name": k, "value": v})

    record = ProcessInfoRecord(
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
    coverage_status = derive_coverage_status(evaluated=True, complete=True)
    return [record], coverage_status, [], True


def render_peb_console(record: ProcessInfoRecord, peb_present: bool) -> None:
    if not peb_present:
        print(f"[!] {_PEB_MISSING_REASON}")
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


def cmd_peb(mf: MinidumpFile):
    records, coverage_status, coverage_reasons, peb_present = collect_peb(mf)
    render_peb_console(records[0], peb_present)
    return records, coverage_status, coverage_reasons
