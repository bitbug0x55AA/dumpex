"""Independent memory-context corroboration for each config hit — the
score 1 -> 2 tier. A config's own bytes are inert DATA, so this looks for
evidence that the surrounding memory is actually part of a loaded, running
beacon rather than a bare copy of the config alone.

Reads only the frozen `models.ConfigEvidence` hits scanner.py already
resolved a region for -- never a raw `mf`/parser dict. Builds
`models.CorroborationEvidence` (only for a hit that actually corroborates)
rather than deciding score/status itself; that decision belongs entirely
to aggregate.py.
"""
from dumpex.core.memory import _get_region_at, prot_str
from dumpex.hunt.cs_beacon.config import CS_SUSPICIOUS_PRIVATE_PROTECTIONS
from dumpex.hunt.cs_beacon.models import CorroborationEvidence


def _corroborates(hit, regions: list, thread_contexts: list) -> tuple:
    """
    Independent memory-context corroboration for a single config hit —
    the score 1 -> 2 tier. Returns a tuple of reason strings (empty when
    uncorroborated).

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

    `hit.region` may be None (VA not covered by MemoryInfoListStream) —
    both signals are then unavailable and this returns ().
    """
    region = hit.region
    if region is None:
        return ()
    reasons = []
    if region.type == 'MEM_PRIVATE' and region.protect in CS_SUSPICIOUS_PRIVATE_PROTECTIONS:
        reasons.append(f"enclosing region 0x{region.base_address:x} is executable, "
                        f"private memory ({region.protect})")
    for tc in thread_contexts:
        r = _get_region_at(tc["ip"], regions)
        if r is not None and getattr(r, "AllocationBase", None) == region.allocation_base:
            reasons.append(f"thread {tc['ThreadId']} current {tc['ip_reg']}=0x{tc['ip']:x} "
                            f"executes within the same allocation (0x{region.allocation_base:x})")
            break
    return tuple(reasons)


def corroborate(hits: tuple, regions: list, thread_contexts: list) -> tuple:
    """
    Run the corroboration check above for every hit. Returns a tuple of
    `models.CorroborationEvidence` -- one per CORROBORATED hit, in the
    same order as `hits` (never one for an uncorroborated hit at all).
    """
    corroborations = []
    for hit in hits:
        reasons = _corroborates(hit, regions, thread_contexts)
        if reasons:
            corroborations.append(CorroborationEvidence(hit=hit, reasons=reasons))
    return tuple(corroborations)
