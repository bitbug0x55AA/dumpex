"""Memory-context classification policy specific to the PE_In_Private_Memory
rule: decides whether a hit should be suppressed (legitimately loaded
module), counted as context_unverified (can't be confidently classified),
or left as a confirmed private-memory hit. Builds on the generic
classifier in dumpex/hunt/_context.py.
"""
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
