"""Allocation-based structural correlation, plus live-execution (RIP/EIP)
and StartAddress correlation. Establishes relationships between signals —
never scores, never prints.
"""
from dumpex.core.memory import group_regions_by_allocation
from dumpex.hunt.injection.models import Correlation


def _region_for_addr(addr, regions):
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return r
    return None


def correlate(rwx: list, validated_pe_hits: list, thread_contexts: list,
              start_threads: list, regions: list) -> Correlation:
    """
    Structural correlation: signals are grouped and correlated by
    **AllocationBase** — the address a single VirtualAlloc/VirtualAllocEx
    call originally reserved — rather than by the BaseAddress of whichever
    individual MemoryInfo sub-region happened to carry each signal. See
    dumpex/hunt/injection/__init__.py's module docstring for why.
    """
    rwx_by_alloc = group_regions_by_allocation(rwx)
    pe_regions   = [h["region"] for h in validated_pe_hits]
    pe_by_alloc  = group_regions_by_allocation(pe_regions)

    rwx_alloc_bases = set(rwx_by_alloc)
    pe_alloc_bases  = set(pe_by_alloc)
    # Structural correlation: same ALLOCATION carries both an RWX
    # sub-region and a validated hidden PE header, regardless of whether
    # they're the same MemoryInfo sub-region.
    rwx_and_pe_alloc_bases = rwx_alloc_bases & pe_alloc_bases
    suspicious_alloc_bases = rwx_alloc_bases | pe_alloc_bases

    # Execution correlation via CURRENT RIP/EIP — the primary signal.
    rip_hits = []   # (thread_ctx, region)
    for tc in thread_contexts:
        r = _region_for_addr(tc["ip"], regions)
        if r is not None and r.AllocationBase in suspicious_alloc_bases:
            rip_hits.append((tc, r))
    rip_full_correlation = [(tc, r) for tc, r in rip_hits
                             if r.AllocationBase in rwx_and_pe_alloc_bases]

    # Secondary, weaker execution correlation via StartAddress.
    start_hits = []   # (thread_info, region)
    for ti in start_threads:
        r = _region_for_addr(ti.StartAddress or 0, regions)
        if r is not None and r.AllocationBase in suspicious_alloc_bases:
            start_hits.append((ti, r))

    return Correlation(
        rwx_by_alloc=rwx_by_alloc, pe_by_alloc=pe_by_alloc,
        rwx_and_pe_alloc_bases=rwx_and_pe_alloc_bases,
        suspicious_alloc_bases=suspicious_alloc_bases,
        rip_hits=rip_hits, rip_full_correlation=rip_full_correlation,
        start_hits=start_hits,
    )
