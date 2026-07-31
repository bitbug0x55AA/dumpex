"""--list command."""
from dumpex.ui.colors import BOLD, RED, GREEN, YELLOW
from dumpex.core.memory import get_memory_regions, prot_str
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.output.records import MemoryRegionRecord, hex_address
from dumpex.output.coverage import observe_source, build_coverage_report
from dumpex.output.command_result import CommandResult


def collect_regions(mf, filter_prot=None) -> CommandResult:
    """
    Pure data, no printing. Returns a CommandResult[MemoryRegionRecord].

    get_memory_regions() returns [] both when MemoryInfoListStream is
    entirely absent from the dump AND when it's present but genuinely
    empty -- those are not the same claim. A dump captured without this
    stream must report 'not_evaluated', not 'complete' with zero
    regions: the latter would read as "we looked at every region and
    there are none," which is a materially different (and false)
    statement about coverage. See dumpex.output.coverage for the shared
    model this now derives from (validated first here and on --modules
    before threads/sysinfo/pid/peb migrate onto it too).
    """
    raw_regions = get_memory_regions(mf)   # [] if absent OR present-empty
    stream_present = bool(mf.memory_info)

    records = []
    for r in raw_regions:
        p = prot_str(r.Protect)
        if filter_prot and filter_prot.upper() not in p.upper():
            continue
        records.append(MemoryRegionRecord(
            base_address=hex_address(r.BaseAddress),
            size=r.RegionSize,
            state=prot_str(r.State),
            protect=p,
            type=prot_str(r.Type),
            suspicious=any(s in p for s in SUSPICIOUS_PROTS),
        ))

    source = observe_source("memory_info", present=stream_present, items=raw_regions)
    coverage = build_coverage_report(
        {"memory_info": source},
        evaluation_sources=("memory_info",),
        completeness_checks=["memory_info"],
    )
    return CommandResult(kind="memory_regions", records=records, coverage=coverage,
                          summary={"count": len(records)})


def render_regions_console(records, coverage) -> None:
    """Takes the whole CoverageReport, not just `records` -- otherwise a
    MemoryInfoListStream that's absent entirely (not_evaluated, zero
    records) is visually indistinguishable from one that's genuinely
    present and empty (complete, zero records): both used to print the
    same green "[+] 0 region(s) shown." with no warning at all. Matches
    render_threads_console's contract of printing every coverage reason
    up front."""
    for reason in coverage.reasons:
        print(YELLOW(f"  [~] {reason}"))
    print(f"\n{BOLD('Address'):<24} {BOLD('Size'):<14} {BOLD('State'):<14} {BOLD('Protection'):<32} {BOLD('Type')}")
    print("─" * 100)
    for rec in records:
        color = RED if rec.suspicious else (lambda x: x)
        print(color(f"{rec.base_address:<24} 0x{rec.size:<12x} {rec.state:<14} {rec.protect:<32} {rec.type}"))
    print(f"\n{GREEN(f'[+] {len(records)} region(s) shown.')}")


def cmd_list(mf, filter_prot=None) -> CommandResult:
    result = collect_regions(mf, filter_prot)
    render_regions_console(result.records, result.coverage)
    return result
