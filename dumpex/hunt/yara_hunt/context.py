"""Memory-context classification policy specific to the PE_In_Private_Memory
rule: decides whether a hit should be suppressed (legitimately loaded
module), counted as context_unverified (can't be confidently classified),
or left as a confirmed private-memory hit. Builds on the generic
classifier in dumpex/hunt/_context.py.
"""
from dumpex.core.memory import prot_str, _get_region_at
from dumpex.hunt._context import MemoryContext, classify_memory_context, CONFIRMED_PRIVATE


def classify_pe_in_private_memory_hit(addr, modules, regions, modules_available,
                                       mem_info_available) -> "tuple[bool, bool, str]":
    """
    Returns (suppressed, unverified, memory_context_value) for one
    PE_In_Private_Memory match at `addr`.

    PE_In_Private_Memory's own rule description says it's only meaningful
    applied to MEM_PRIVATE/unregistered memory (condition is just "$mz at
    0 and $pe" — no memory-type awareness at all, since YARA matches raw
    segment bytes with no such context). Left unfiltered, it fires on
    every legitimately loaded module's MZ/PE header too, since the match
    is always at the scanned segment's own base address.
    classify_memory_context names every combination of ModuleList/
    MemoryInfo availability explicitly (see dumpex/hunt/_context.py) so
    there's no silent fall-through case: a MemoryInfo gap (region not
    found) with ModuleList missing is UNKNOWN, not a confirmed PRIVATE
    hit, and a region of some other type (e.g. MEM_MAPPED) is OTHER, not
    treated as either IMAGE or PRIVATE.
    """
    ctx = classify_memory_context(addr, modules, regions, modules_available, mem_info_available)

    if ctx == MemoryContext.IMAGE:
        return True, False, ctx.value

    if ctx not in CONFIRMED_PRIVATE:
        # OTHER or UNKNOWN — the address cannot be confidently classified
        # as private memory. Still recorded as a hit (an investigator
        # should see it) but must not, by itself, stand as a confirmed
        # detection. Which of the two it is matters for the message shown
        # later — UNKNOWN means neither context source could even be
        # consulted, OTHER means MemoryInfo WAS consulted and resolved to
        # some type that's neither MEM_IMAGE nor MEM_PRIVATE (e.g.
        # MEM_MAPPED) — those are different findings and must not share
        # one "no ModuleList/MemoryInfo" message.
        return False, True, ctx.value

    return False, False, ctx.value


def classify_scoped_hit(addr, modules, regions, modules_available,
                         mem_info_available) -> "tuple[bool, bool, str]":
    """
    Generalized private/unbacked-context classification for any YARA rule
    whose meta declares `dumpex_scope = "private_or_unbacked"` (see
    dumpex/hunt/yara_hunt/config.py's SCOPE_PRIVATE_OR_UNBACKED) —
    Shellcode_Bootstrap_x64, Win32_API_Hashing, Suspicious_VirtualAlloc_Sequence,
    LSASS_Dump_Keywords, WMI_Lateral_Movement, and any future rule carrying
    the same meta. These rules match on generic byte sequences or bare
    Windows API-name strings that are ROUTINE inside a legitimately loaded
    module — every DLL that documents/exports VirtualAllocEx contains that
    string, and a short call/pop bootstrap sequence occurs by pure
    coincidence in ntdll.dll-sized code — unlike PE_In_Private_Memory (see
    classify_pe_in_private_memory_hit above, kept separate and unchanged
    for backward compatibility with rule files/tests that predate this
    meta-driven mechanism), so a module-backed hit here must never reach
    triggered_rules at all.

    Returns (suppressed, unverified, memory_context_value):
      IMAGE (known module OR MemoryInfo says MEM_IMAGE)   -> suppressed
      PRIVATE or UNREGISTERED (confirmed non-module)       -> allowed
      OTHER (e.g. MEM_MAPPED) WITH executable protection   -> allowed —
          just as worth flagging as MEM_PRIVATE: unbacked AND executable
      OTHER without executable protection, or UNKNOWN       -> unverified
    """
    ctx = classify_memory_context(addr, modules, regions, modules_available, mem_info_available)

    if ctx == MemoryContext.IMAGE:
        return True, False, ctx.value

    if ctx in CONFIRMED_PRIVATE:   # PRIVATE or UNREGISTERED
        return False, False, ctx.value

    if ctx == MemoryContext.OTHER:
        region = _get_region_at(addr, regions)
        if region is not None and "EXECUTE" in prot_str(region.Protect):
            return False, False, ctx.value
        return False, True, ctx.value

    # UNKNOWN — neither context source available to classify this address.
    return False, True, ctx.value


def context_unverified_reason(contexts) -> str:
    """
    Build an accurate explanation for a set of MemoryContext values (see
    dumpex/hunt/_context.py) behind one or more context_unverified hits.
    UNKNOWN and OTHER are different findings and must not share one
    message: UNKNOWN means neither ModuleList nor MemoryInfo could
    classify the address at all; OTHER means MemoryInfo WAS available and
    resolved it to some type that's neither MEM_IMAGE nor MEM_PRIVATE
    (e.g. MEM_MAPPED) — that's a materially different situation from
    "no context available".
    """
    contexts = set(contexts)
    parts = []
    if "unknown" in contexts:
        parts.append("no ModuleList/MemoryInfo available to classify")
    if "other" in contexts:
        parts.append("region type is neither MEM_IMAGE nor MEM_PRIVATE, e.g. MEM_MAPPED")
    return "; ".join(parts) if parts else "context could not be verified"
