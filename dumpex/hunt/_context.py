"""Memory-context classification shared by hunt modules that need to judge
whether an address is backed by a known module, a private allocation, or
neither — most notably yara_hunt's PE_In_Private_Memory suppression.

A prior, ad-hoc version of this check only special-cased "both ModuleList
and MemoryInfo missing" as unclassifiable; every other combination silently
fell through to "confirmed detection", including the case where MemoryInfo
IS present but simply doesn't cover the address in question (a genuine gap,
not a classification) while ModuleList is missing — that combination was
wrongly treated as a confirmed private-memory hit. The enum below makes
every combination an explicit, named outcome so there's no silent
fall-through case left uncovered.
"""
from enum import Enum
from dumpex.core.memory import addr_to_module, prot_str, _get_region_at


class MemoryContext(Enum):
    IMAGE        = "image"          # known module OR MemoryInfo says MEM_IMAGE — legitimate
    PRIVATE      = "private"        # MemoryInfo confirms MEM_PRIVATE — genuine private memory
    UNREGISTERED = "unregistered"   # ModuleList available (and complete); address isn't in
                                     # it — ModuleList's negative answer is itself the signal,
                                     # regardless of whether MemoryInfo happens to have a gap
    OTHER        = "other"          # MemoryInfo resolved to some other type (e.g. MEM_MAPPED)
                                     # — neither a known image nor confirmed private memory;
                                     # must not be treated as either
    UNKNOWN      = "unknown"        # neither context source can classify this address at all


# Only these represent a confidently-private address — callers deciding
# whether to treat a hit as a confirmed detection should gate on this set.
CONFIRMED_PRIVATE = frozenset({MemoryContext.PRIVATE, MemoryContext.UNREGISTERED})


def classify_memory_context(addr: int, modules: list, regions: list,
                             modules_available: bool, mem_info_available: bool) -> MemoryContext:
    """
    Classify `addr` using whichever of ModuleList / MemoryInfo streams are
    present in the dump.

      module found                            -> IMAGE
      region found, Type == MEM_IMAGE         -> IMAGE
      region found, Type == MEM_PRIVATE       -> PRIVATE
      region found, any other Type            -> OTHER
      region NOT found, ModuleList available  -> UNREGISTERED
      region NOT found, ModuleList unavailable -> UNKNOWN

    See module docstring and CONFIRMED_PRIVATE for how callers should act
    on the result.
    """
    module = addr_to_module(addr, modules) if modules_available else None
    if module is not None:
        return MemoryContext.IMAGE

    region = _get_region_at(addr, regions) if mem_info_available else None
    if region is not None:
        rtype = prot_str(region.Type)
        if "MEM_IMAGE" in rtype:
            return MemoryContext.IMAGE
        if "MEM_PRIVATE" in rtype:
            return MemoryContext.PRIVATE
        return MemoryContext.OTHER

    if modules_available:
        return MemoryContext.UNREGISTERED
    return MemoryContext.UNKNOWN
