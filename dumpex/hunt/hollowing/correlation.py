"""
The one place this hunter's CORRELATION REQUIREMENT is expressed: DETECTED
needs anchor 1 (MEM_PRIVATE at the image base) firing together with at
least one of anchor 2 (a wiped/missing MZ header) or corroborator 3 (RWX
protection) at that SAME address. A single anomaly -- including either
anchor entirely on its own -- stays a lead and never scores.

Kept as its own module, separate from aggregate.py, for the same reason
`dumpex.hunt.stomping.correlation` and `dumpex.hunt.pipe.correlation` are:
deciding WHICH observations relate to each other is a different judgment
from turning a set of relationships into a score, a status, and a set of
`CheckResult`s. aggregate.py consumes what this returns; it never re-derives
the relationship, so there is exactly one statement of the rule the whole
hunter exists to enforce.

Pure: takes the typed evidence tuples `memory_scan.collect_signals()`
produced plus the image base, returns typed evidence. No dump, no resolver,
no rules, no printing.
"""
from dumpex.hunt.hollowing.models import StructuralCorrelationEvidence


def correlate(mem_private: tuple, wiped_headers: tuple, rwx: tuple,
              image_base: int) -> tuple:
    """`(StructuralCorrelationEvidence,)` when the correlation requirement
    is met, else `()`.

    The returned evidence holds the SAME anchor/corroborator instances it
    was passed (never copies), which is what
    `domain.HollowingEvidence`'s own identity check enforces -- so the
    correlation and the individual leads can never end up describing the
    same region differently.

    Note what is deliberately NOT here: corroborator 4 (the PEB-vs-module-
    list name mismatch). It is reported as a lead in its own right but has
    never been part of the scored correlation -- a name/case/redirection
    difference is routinely benign, so admitting it as a corroborator would
    let two weak signals reach DETECTED.
    """
    if not mem_private:
        return ()
    if not (wiped_headers or rwx):
        return ()
    return (StructuralCorrelationEvidence(
        image_base=image_base,
        mem_private=mem_private[0],
        wiped_header=wiped_headers[0] if wiped_headers else None,
        rwx=rwx[0] if rwx else None),)
