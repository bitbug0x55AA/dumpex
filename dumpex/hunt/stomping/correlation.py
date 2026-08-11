"""RIP/EIP correlation for the stomping hunter: does a thread's current
instruction pointer land inside a verified changed byte range, or inside
a section with an anomalous live protection state? Establishes
relationships between signals — never scores, never prints.

Since the canonical-Report migration this is also the LAST place a raw
`get_thread_contexts()` dict is touched: both public functions here return
the immutable Evidence value objects dumpex/hunt/stomping/models.py
defines, so aggregate.py never sees a thread-context dict (and therefore
never needs `mf`, a thread list, or an address lookup to decide anything).

Display truncation of a verified change's differing byte ranges also
happens here, in `build_verified_changes()`, deliberately AFTER the RIP
scan has seen every range the diff produced -- see `rip_in_ranges()`.
"""
from dumpex.hunt.stomping.config import MAX_DIFF_RANGES
from dumpex.hunt.stomping.models import (
    RipCorrelatedLeadEvidence, ThreadHitRef, VerifiedChangeEvidence,
)


def rip_in_ranges(thread_contexts: list, va_start: int, ranges) -> bool:
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


def build_verified_changes(diffs, thread_contexts: list) -> tuple:
    """Turn each raw `SectionDiffResult` into the immutable
    `VerifiedChangeEvidence` the Report keeps: RIP correlation over the
    FULL range list, then display truncation to MAX_DIFF_RANGES with
    `total_ranges` keeping the real count.

    Order matters and is the whole reason both steps live here rather than
    in aggregate.py: correlating against an already-truncated list would
    silently drop a live-execution hit sitting in the 21st differing range,
    which is the difference between score 1 and score 2.
    """
    changes = []
    for diff in diffs:
        if not diff.all_ranges:
            continue
        rip_in_changed = rip_in_ranges(thread_contexts, diff.va_start, diff.all_ranges)
        changes.append(VerifiedChangeEvidence(
            module=diff.module, section=diff.section, va_start=diff.va_start,
            diff_ranges=diff.all_ranges[:MAX_DIFF_RANGES],
            ranges_truncated=(diff.ranges_truncated_by_scan
                              or len(diff.all_ranges) > MAX_DIFF_RANGES),
            total_ranges=len(diff.all_ranges), compared_len=diff.compared_len,
            rip_in_changed_range=rip_in_changed,
            disk_sha256=diff.disk_sha256, mem_sha256=diff.mem_sha256,
            file_offset=diff.file_offset))
    return tuple(changes)


def correlate_protection_leads_with_rip(protection_leads, thread_contexts: list) -> tuple:
    """
    Pair each protection-deviation lead with the FIRST thread whose current
    RIP/EIP executes inside that exact section's VA range, if any.

    Each returned `RipCorrelatedLeadEvidence` holds the SAME
    `ProtectionLeadEvidence` object it was given (never a copy), which is
    what lets `StompingEvidence` enforce the two buckets' relationship by
    identity instead of by equality.

    Computed unconditionally: whether this pairing is worth REPORTING as
    its own check is aggregate.py's decision (it is suppressed once a
    verified content diff already covers the same correlation with real
    byte-level evidence behind it), not this layer's.
    """
    correlated = []
    for lead in protection_leads:
        for tc in thread_contexts:
            if lead.va_start <= tc["ip"] < lead.va_end:
                correlated.append(RipCorrelatedLeadEvidence(
                    lead=lead, thread=ThreadHitRef.from_context(tc)))
                break
    return tuple(correlated)
