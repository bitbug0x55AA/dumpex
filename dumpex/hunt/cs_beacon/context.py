"""Independent memory-context corroboration for each config hit — the
score 1 -> 2 tier. A config's own bytes are inert DATA, so this looks for
evidence that the surrounding memory is actually part of a loaded, running
beacon rather than a bare copy of the config alone.
"""
from dumpex.core.memory import _get_region_at, prot_str
from dumpex.hunt.cs_beacon.config import CS_SUSPICIOUS_PRIVATE_PROTECTIONS
from dumpex.hunt.cs_beacon.models import CorroboratedHit


def _cs_context_corroborates(hit_region, regions: list, thread_contexts: list) -> "tuple[bool, list]":
    """
    Independent memory-context corroboration for a single config hit —
    the score 1 -> 2 tier. Returns (corroborated, reasons).

    Two signals, either is sufficient:
      1. The config's enclosing MemoryInfo region is executable, private
         memory — a bare config copy sitting in ordinary (non-executable)
         data memory doesn't get this; a beacon with its payload actually
         mapped alongside its config does.
      2. A thread's CURRENT RIP/EIP (get_thread_contexts — the live
         register state at dump time, not just a thread's start address)
         executes somewhere within the SAME allocation as the hit —
         checked by AllocationBase, not the narrower single MemoryInfo
         sub-region, since one VirtualAlloc can be split into multiple
         sub-regions with different protections (mirrors how
         dumpex/hunt/injection/ groups RWX+PE hits by allocation).

    hit_region may be None (VA not covered by MemoryInfoListStream) —
    both signals are then unavailable and this returns (False, []).
    """
    if hit_region is None:
        return False, []
    reasons = []
    if (prot_str(hit_region.Type) == 'MEM_PRIVATE'
            and prot_str(hit_region.Protect) in CS_SUSPICIOUS_PRIVATE_PROTECTIONS):
        reasons.append(f"enclosing region 0x{hit_region.BaseAddress:x} is executable, "
                        f"private memory ({prot_str(hit_region.Protect)})")
    alloc_base = hit_region.AllocationBase
    for tc in thread_contexts:
        r = _get_region_at(tc["ip"], regions)
        if r is not None and r.AllocationBase == alloc_base:
            reasons.append(f"thread {tc['ThreadId']} current {tc['ip_reg']}=0x{tc['ip']:x} "
                            f"executes within the same allocation (0x{alloc_base:x})")
            break
    return bool(reasons), reasons


def corroborate_hits(hits: list, regions: list, thread_contexts: list) -> list:
    """
    Resolve each Candidate's enclosing region and run the corroboration
    check above for it. Returns a list[CorroboratedHit] in the same order
    as `hits`.
    """
    enriched = []
    for candidate in hits:
        region = _get_region_at(candidate.hit_va, regions)
        corroborated, reasons = _cs_context_corroborates(region, regions, thread_contexts)
        enriched.append(CorroboratedHit(candidate, region, corroborated, reasons))
    return enriched
