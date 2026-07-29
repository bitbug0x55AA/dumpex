"""RIP/EIP correlation for the stomping hunter: does a thread's current
instruction pointer land inside a verified changed byte range, or inside
a section with an anomalous live protection state? Establishes
relationships between signals — never scores, never prints.
"""


def rip_in_ranges(thread_contexts: list, va_start: int, ranges: list) -> bool:
    """
    True if any thread's current RIP/EIP lands inside one of `ranges`
    (each an (offset, length) pair relative to va_start). Scans EVERY
    range passed in, not a display-truncated subset — a hit in e.g. the
    21st range must never be silently missed just because only the first
    20 are kept for display (see dumpex/hunt/stomping/config.py's
    MAX_DIFF_RANGES vs MAX_DIFF_RANGES_SCAN).
    """
    for off, length in ranges:
        change_va = va_start + off
        if any(change_va <= tc["ip"] < change_va + length for tc in thread_contexts):
            return True
    return False


def correlate_protection_leads_with_rip(protection_leads: list, thread_contexts: list) -> list:
    """
    Pair each protection-deviation lead with a thread whose current
    RIP/EIP executes inside that exact section's VA range, if any.
    Returns a list of (protection_lead_dict, thread_context) pairs.
    """
    rip_correlated = []
    for hit in protection_leads:
        for tc in thread_contexts:
            if hit["va_start"] <= tc["ip"] < hit["va_end"]:
                rip_correlated.append((hit, tc))
                break
    return rip_correlated
