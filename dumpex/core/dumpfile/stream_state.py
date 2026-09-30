"""Stream-state observation: whether a stream-backed source is failed,
absent, empty or present, and the three-way handle-evidence state.

Both take the stream's recorded parser failure as an argument; the bound
entry points `dumpex.core.memory.observe_stream` and
`dumpex.core.memory.handle_stream_evidence` look it up through the legacy
module's `stream_failure`.
"""
from minidump.constants import MINIDUMP_STREAM_TYPE

from dumpex.core.dumpfile.loader import has_stream_directory
from dumpex.output.coverage import SourceObservation, SourceState


# The one "captured but unusable" sub-case with no parser exception
# behind it -- see handle_stream_state() for when it applies.
UNPARSED_HANDLE_STREAM_DETAIL = (
    "the dump declares a HandleDataStream but no parsed stream is available")


def handle_stream_state(mf, failure_detail) -> "tuple[str, object, str | None]":
    """-> (state, parsed_stream_or_None, failure_detail_or_None), where
    state is "absent" (the dump never carried a HandleDataStream),
    "failed" (it carried one that could not be parsed), or "parsed".
    `failure_detail` is the HandleDataStream parser failure recorded for
    `mf` (None when none was); dumpex.core.memory.handle_stream_evidence
    looks it up through its own stream_failure.

    The one place any consumer of handle evidence asks that question, so
    a dump whose handle stream is CORRUPT can never be described as one
    captured without handle data. `mf.handles` is None in both cases, so
    absence of the parsed object alone cannot decide it: the recorded
    parser failure is consulted FIRST (a stream that raised is failed
    evidence even if something else later attached an object to
    `mf.handles`), then the parsed object, and only then the dump's own
    directory table.

    That last check is what keeps "absent" a positive claim rather than an
    inference: a directory entry with neither a parsed stream nor a
    recorded failure means the stream was captured but never made it
    through the loader -- unreachable through today's `open_dump()`, but
    if it ever happens it is failed evidence, not "this dump was not
    captured with handle data". The two send an analyst to different next
    steps, so this fails closed toward the honest one.
    """
    if failure_detail is not None:
        return "failed", None, failure_detail
    parsed = getattr(mf, "handles", None)
    if parsed is not None:
        return "parsed", parsed, None
    if has_stream_directory(mf, MINIDUMP_STREAM_TYPE.HandleDataStream):
        return "failed", None, UNPARSED_HANDLE_STREAM_DETAIL
    return "absent", None, None


def stream_observation(name: str, failure_detail, obj, items: list) -> SourceObservation:
    """The observe_source() every command currently hand-rolls via
    `bool(mf.X)` plus `len(items)`, extended with SourceState.FAILED for
    a stream-backed source: FAILED (with the parser's own detail) when
    `failure_detail` -- the stream's entry in mf._dumpex_stream_failures,
    looked up by dumpex.core.memory.observe_stream -- is not None,
    otherwise exactly observe_source()'s existing absent/present_empty/
    present inference over `obj`/`items`."""
    if failure_detail is not None:
        return SourceObservation(name=name, state=SourceState.FAILED, record_count=None,
                                  detail=failure_detail)
    if not obj:
        return SourceObservation(name=name, state=SourceState.ABSENT, record_count=None)
    items = items or []
    if not items:
        return SourceObservation(name=name, state=SourceState.PRESENT_EMPTY, record_count=0)
    return SourceObservation(name=name, state=SourceState.PRESENT, record_count=len(items))
