"""Strict v2 JSON encoder.

Unlike dumpex/ui/structured.py's `_json_safe` (which has a deliberate,
documented `str(obj)` fallback for anything it doesn't recognize -- the
right call for v1.1, which has to serialize whatever a hunt module hands
it, including live minidump/ctypes objects), the v2 contract requires
every value to already be a plain JSON scalar, list, or dict by the time
it reaches this module. `_ensure_json_safe` walks the document and
raises TypeError -- loudly, with a path to the offending value -- for
anything else, so a record type that forgot to convert one of its own
fields (an enum, a raw minidump object, a set) fails a test immediately
instead of silently shipping a stringified repr() in a case JSON file.
"""
import json

_JSON_SCALAR_TYPES = (str, int, float, bool, type(None))


def _ensure_json_safe(obj, _path: str = "$") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"{_path}: dict key {k!r} is not a string")
            _ensure_json_safe(v, f"{_path}.{k}")
        return
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            _ensure_json_safe(v, f"{_path}[{i}]")
        return
    if isinstance(obj, _JSON_SCALAR_TYPES):
        return
    raise TypeError(
        f"{_path}: object of type {type(obj).__name__!r} is not a plain JSON "
        f"scalar/list/dict. The v2 serializer never falls back to str(obj) -- "
        f"add an explicit to_dict()/field conversion for this type at its "
        f"source (the record/collector that produced it) instead of loosening "
        f"this check."
    )


def to_json(envelope) -> str:
    """envelope: anything with a .to_dict() returning a plain-Python
    structure (dumpex.output.envelope.Envelope in practice)."""
    doc = envelope.to_dict()
    _ensure_json_safe(doc)
    return json.dumps(doc, indent=2, ensure_ascii=False)
