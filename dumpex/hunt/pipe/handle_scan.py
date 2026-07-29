"""HandleDataStream scanning — the primary, scored signal (see
dumpex/hunt/pipe/__init__.py's module docstring). Only collects facts —
never scores, never prints.
"""
from dumpex.hunt.pipe.patterns import canonical_pipe_name, is_pipe_handle_object_name, framework_match
from dumpex.hunt.pipe.models import HandleScan


def _is_pipe_handle(h) -> bool:
    if not getattr(h, "ObjectName", None):
        return False
    type_name = (getattr(h, "TypeName", None) or "").lower()
    if type_name and "file" not in type_name:
        return False
    return is_pipe_handle_object_name(h.ObjectName)


def scan_handles(handles: list, known_framework_pipes) -> HandleScan:
    """
    Classify every open handle that looks like a named-pipe kernel
    object: canonicalize its name and check it against known C2/lateral-
    movement framework naming conventions.
    """
    handle_pipe_hits = [h for h in handles if _is_pipe_handle(h)]

    handle_classified = []
    for h in handle_pipe_hits:
        handle_classified.append({
            "handle": h, "canonical_name": canonical_pipe_name(h.ObjectName),
            "framework_match": framework_match(h.ObjectName, known_framework_pipes),
        })

    framework_handle_hits = [hc for hc in handle_classified if hc["framework_match"]]

    return HandleScan(handle_pipe_hits=handle_pipe_hits, handle_classified=handle_classified,
                       framework_handle_hits=framework_handle_hits)
