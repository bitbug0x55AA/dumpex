"""HandleDataStream scanning — the primary, scored signal (see
dumpex/hunt/pipe/__init__.py's module docstring). Only collects facts —
never scores, never prints.

Produces typed `dumpex.hunt.pipe.models` evidence rather than hand-rolled
dicts: this is the ONE place a raw `MinidumpHandleDescriptor` becomes a
`HandleRef` identity snapshot, and the ONE place a `framework_pipes` rule
match becomes a `FrameworkAttribution`. Nothing downstream ever needs the
live handle object again.
"""
from dumpex.core.memory import truncated_descriptor_count
from dumpex.hunt.pipe.patterns import canonical_pipe_name, is_pipe_handle_object_name, framework_match
from dumpex.hunt.pipe.models import (
    HandleScanResult, PipeHandleEvidence, dedupe_evidence, framework_attribution, handle_ref,
)


def _is_pipe_handle(h) -> bool:
    if not getattr(h, "ObjectName", None):
        return False
    type_name = (getattr(h, "TypeName", None) or "").lower()
    if type_name and "file" not in type_name:
        return False
    return is_pipe_handle_object_name(h.ObjectName)


def scan_handles(handles: list, known_framework_pipes, handle_stream) -> HandleScanResult:
    """
    Classify every open handle that looks like a named-pipe kernel
    object: canonicalize its name and check it against known C2/lateral-
    movement framework naming conventions.

    `handle_stream` is the parsed HandleDataStream (`mf.handles`) the
    `handles` list came out of, or None when the dump carries no usable
    one. REQUIRED, and deliberately not defaulted: the result's
    `dropped_descriptors` is the descriptor tail the `handles` list is
    MISSING, and the list alone can never show it -- a dropped descriptor
    is simply not in it, so a pipe handle among the dropped ones is
    absent from every check below with nothing to mark its absence. A
    default would let a caller silently omit the stream and get the
    pre-truncation-reporting behaviour back with every test still
    passing.

    Exact duplicates are collapsed (`dedupe_evidence`) -- two
    HandleDataStream entries identical in handle value, type, object name,
    and granted access are the same observed fact recorded twice, and the
    Report's own evidence buckets reject a duplicate outright (see
    dumpex.hunt.pipe.domain._require_items_of).
    """
    classified = []
    for h in handles:
        if not _is_pipe_handle(h):
            continue
        classified.append(PipeHandleEvidence(
            handle=handle_ref(h),
            canonical_name=canonical_pipe_name(h.ObjectName),
            framework=framework_attribution(framework_match(h.ObjectName,
                                                              known_framework_pipes))))
    return HandleScanResult(handles=dedupe_evidence(classified),
                             dropped_descriptors=truncated_descriptor_count(handle_stream))
