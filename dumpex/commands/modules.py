"""--modules command."""
import ntpath
from dumpex.ui.colors import BOLD, DIM, RED, GREEN, YELLOW
from dumpex.core.memory import get_modules
from dumpex.core.pe_utils import _pe_timestamp_to_str, _version_str
from dumpex.output.records import ModuleRecord, hex_address
from dumpex.output.coverage import observe_source, build_coverage_report
from dumpex.output.command_result import CommandResult

# Console badge per anomaly_flags entry -- kept as a small lookup table
# decoupled from record-building, replacing the colored_flags list that
# used to be built inline alongside plain_flags during collection.
_ANOMALY_BADGES = {
    "NO_NAME":       lambda: RED("[NO NAME]"),
    "OLD_TIMESTAMP": lambda: YELLOW("[OLD TIMESTAMP]"),
}


def collect_modules(mf) -> CommandResult:
    """
    Pure data, no printing. Returns a CommandResult[ModuleRecord].

    get_modules() returns [] both when ModuleListStream is entirely
    absent from the dump AND when it's present but genuinely empty --
    those are not the same claim. A dump captured without this stream
    must report 'not_evaluated', not 'complete' with zero modules. See
    dumpex.output.coverage for the shared model this now derives from.
    """
    raw_modules = get_modules(mf)   # [] if absent OR present-empty
    stream_present = bool(mf.modules)

    records = []
    for m in sorted(raw_modules, key=lambda x: x.baseaddress):
        # Module paths recorded in a minidump are from the ORIGINAL Windows
        # system (e.g. "C:\Windows\System32\foo.dll") -- os.path.basename
        # only splits on "/" on a POSIX analysis host, so it returns the
        # whole backslash-separated string unchanged there. ntpath.basename
        # always applies Windows path rules regardless of the host OS this
        # tool runs on (see dumpex.hunt.stomping.memory_scan._module_basename
        # for the same fix, applied there first).
        name     = m.name or "(unnamed)"
        ts_raw   = getattr(m, "timestamp", 0) or 0
        ts_str   = _pe_timestamp_to_str(ts_raw)
        ver_str  = _version_str(getattr(m, "versioninfo", None))
        checksum = getattr(m, "checksum", 0) or 0

        anomaly_flags = []
        if not m.name:
            anomaly_flags.append("NO_NAME")
        if ts_raw and ts_raw < 315532800:
            anomaly_flags.append("OLD_TIMESTAMP")

        records.append(ModuleRecord(
            name=ntpath.basename(name),
            full_path=m.name or None,
            base_address=hex_address(m.baseaddress),
            end_address=hex_address(m.endaddress),
            size=m.size,
            compiled_utc=ts_str,
            file_version=ver_str,
            checksum=checksum or None,
            anomaly_flags=anomaly_flags,
        ))

    source = observe_source("modules", present=stream_present, items=raw_modules)
    coverage = build_coverage_report(
        {"modules": source},
        evaluation_sources=("modules",),
        completeness_checks=["modules"],
    )
    return CommandResult(kind="modules", records=records, coverage=coverage,
                          summary={"count": len(records)})


def render_modules_console(records) -> None:
    for rec in records:
        badges = [_ANOMALY_BADGES[f]() for f in rec.anomaly_flags if f in _ANOMALY_BADGES]
        flag_str = "  " + " ".join(badges) if badges else ""

        print(f"\n  {BOLD(rec.name)}{flag_str}")
        print(f"  {'Full path':<18} {DIM(rec.full_path or '(unnamed)')}")
        print(f"  {'Base → End':<18} {rec.base_address} → {rec.end_address}  (size 0x{rec.size:x})")
        print(f"  {'Compiled (UTC)':<18} {rec.compiled_utc}")
        if rec.file_version:
            print(f"  {'File version':<18} {rec.file_version}")
        if rec.checksum:
            print(f"  {'Checksum':<18} 0x{rec.checksum:08x}")

    print(f"\n{GREEN(f'[+] {len(records)} module(s).')}")


def cmd_modules(mf) -> CommandResult:
    result = collect_modules(mf)
    render_modules_console(result.records)
    return result
