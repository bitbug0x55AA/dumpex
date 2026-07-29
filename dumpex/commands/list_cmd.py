"""--list command."""
from dumpex.ui.colors import BOLD, RED, GREEN
from dumpex.core.memory import get_memory_regions, prot_str
from dumpex.rules_pkg.loader import SUSPICIOUS_PROTS
from dumpex.hunt._coverage import derive_coverage_status
from dumpex.output.records import MemoryRegionRecord, hex_address


def collect_regions(mf, filter_prot=None):
    """
    Pure data, no printing. Returns (records, coverage_status,
    coverage_reasons).

    get_memory_regions() returns [] both when MemoryInfoListStream is
    entirely absent from the dump AND when it's present but genuinely
    empty -- those are not the same claim. A dump captured without this
    stream must report 'not_evaluated', not 'complete' with zero
    regions: the latter would read as "we looked at every region and
    there are none," which is a materially different (and false)
    statement about coverage.
    """
    stream_present = bool(mf.memory_info)

    records = []
    for r in get_memory_regions(mf):
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

    if not stream_present:
        coverage_status = derive_coverage_status(evaluated=False, complete=False)
        return records, coverage_status, ["MemoryInfoListStream not present in this dump"]

    coverage_status = derive_coverage_status(evaluated=True, complete=True)
    return records, coverage_status, []


def render_regions_console(records) -> None:
    print(f"\n{BOLD('Address'):<24} {BOLD('Size'):<14} {BOLD('State'):<14} {BOLD('Protection'):<32} {BOLD('Type')}")
    print("─" * 100)
    for rec in records:
        color = RED if rec.suspicious else (lambda x: x)
        print(color(f"{rec.base_address:<24} 0x{rec.size:<12x} {rec.state:<14} {rec.protect:<32} {rec.type}"))
    print(f"\n{GREEN(f'[+] {len(records)} region(s) shown.')}")


def cmd_list(mf, filter_prot=None):
    records, coverage_status, coverage_reasons = collect_regions(mf, filter_prot)
    render_regions_console(records)
    return records, coverage_status, coverage_reasons
