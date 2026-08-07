"""Allocation-based structural correlation, plus live-execution (RIP/EIP)
and StartAddress correlation. Establishes relationships between signals —
never scores, never prints.
"""
from dumpex.core.memory import group_regions_by_allocation
from dumpex.hunt.injection.memory_scan import region_ref
from dumpex.hunt.injection.models import Correlation, RipHitEvidence, StartHitEvidence


def _region_for_addr(addr, regions):
    """Search the FULL region list (every MemoryInfo entry, not just RWX/
    hidden-PE evidence) for the one containing `addr`, returning an
    immutable RegionRef -- the raw Region object never escapes this
    function."""
    for r in regions:
        if r.BaseAddress <= addr < r.BaseAddress + r.RegionSize:
            return region_ref(r)
    return None


def correlate(rwx: tuple, validated_pe_hits: tuple, thread_contexts: list,
              start_threads: tuple, regions: list) -> Correlation:
    """
    Structural correlation: signals are grouped and correlated by
    **AllocationBase** — the address a single VirtualAlloc/VirtualAllocEx
    call originally reserved — rather than by the BaseAddress of whichever
    individual MemoryInfo sub-region happened to carry each signal. See
    dumpex/hunt/injection/__init__.py's module docstring for why.
    """
    # Correlation.__post_init__ normalizes both of these into a
    # MappingProxyType with tuple values -- built here as plain dicts of
    # lists, group_regions_by_allocation()'s own natural return shape.
    rwx_by_alloc = group_regions_by_allocation(
        [ev.region for ev in rwx], key=lambda ref: ref.allocation_base)
    pe_regions   = [h.region for h in validated_pe_hits]
    pe_by_alloc  = group_regions_by_allocation(pe_regions, key=lambda ref: ref.allocation_base)

    rwx_alloc_bases = set(rwx_by_alloc)
    pe_alloc_bases  = set(pe_by_alloc)
    # Structural correlation: same ALLOCATION carries both an RWX
    # sub-region and a validated hidden PE header, regardless of whether
    # they're the same MemoryInfo sub-region.
    rwx_and_pe_alloc_bases = frozenset(rwx_alloc_bases & pe_alloc_bases)
    suspicious_alloc_bases = frozenset(rwx_alloc_bases | pe_alloc_bases)

    # Execution correlation via CURRENT RIP/EIP — the primary signal.
    rip_hits = []   # list[RipHitEvidence]
    for tc in thread_contexts:
        r = _region_for_addr(tc["ip"], regions)
        if r is not None and r.allocation_base in suspicious_alloc_bases:
            rip_hits.append(RipHitEvidence(
                thread_id=tc["ThreadId"], ip=tc["ip"], ip_reg=tc["ip_reg"], region=r))
    rip_full_correlation = [hit for hit in rip_hits
                             if hit.region.allocation_base in rwx_and_pe_alloc_bases]

    # Secondary, weaker execution correlation via StartAddress. `ti.
    # start_address` may be None (see UnbackedThreadEvidence's own
    # docstring) -- 0-substituted locally for this geometric lookup only,
    # same as thread_scan.py's own classification/Location resolution.
    # StartHitEvidence keeps the thread's TRUE start_address (possibly
    # None), never the substituted lookup value -- same "never fabricate a
    # known address" rule as UnbackedThreadEvidence itself.
    start_hits = []   # list[StartHitEvidence]
    for ti in start_threads:
        r = _region_for_addr(ti.start_address or 0, regions)
        if r is not None and r.allocation_base in suspicious_alloc_bases:
            start_hits.append(StartHitEvidence(
                thread_id=ti.thread_id, start_address=ti.start_address, region=r))

    return Correlation(
        rwx_by_alloc=rwx_by_alloc, pe_by_alloc=pe_by_alloc,
        rwx_and_pe_alloc_bases=rwx_and_pe_alloc_bases,
        suspicious_alloc_bases=suspicious_alloc_bases,
        rip_hits=tuple(rip_hits), rip_full_correlation=tuple(rip_full_correlation),
        start_hits=tuple(start_hits),
    )
