"""
Deterministic, JSON-safe projection of arbitrary Python values, plus the
golden file I/O and structural diff every baseline section shares.

`stable()` never embeds anything that varies between runs, machines or
supported Python versions: no object addresses, no set iteration order,
and no module path for a function or class (a module path is structural
metadata the relocation is allowed to change -- see `surface.py`).
"""
import collections.abc
import dataclasses
import enum
import functools
import inspect
import json
import os
import re
import types
import typing

from tests.fixtures.decomposition_baseline import GOLDEN_DIR


def qualname(obj) -> str:
    return getattr(obj, "__qualname__", None) or getattr(obj, "__name__", None) or type(obj).__name__


def annotation_text(annotation) -> "str | None":
    """An annotation as text that reads the same on every supported Python
    version (`Optional[X]` and `X | None` both become `X | None`)."""
    if annotation is inspect.Parameter.empty or annotation is inspect.Signature.empty:
        return None
    if isinstance(annotation, str):
        return annotation
    if annotation is type(None):
        return "None"
    if isinstance(annotation, typing.ForwardRef):
        return annotation.__forward_arg__
    origin, args = typing.get_origin(annotation), typing.get_args(annotation)
    if origin is typing.Union or (hasattr(types, "UnionType") and origin is types.UnionType):
        return " | ".join(annotation_text(a) for a in args)
    if origin is collections.abc.Callable and args:
        params, returns = args[:-1], args[-1]
        if len(params) == 1 and isinstance(params[0], list):
            params = params[0]
        inner = "..." if params == (Ellipsis,) else ", ".join(annotation_text(p) for p in params)
        return f"Callable[[{inner}], {annotation_text(returns)}]"
    if origin is not None and args:
        name = getattr(origin, "__qualname__", None) or repr(origin).replace("typing.", "")
        return f"{name}[{', '.join(annotation_text(a) for a in args)}]"
    if isinstance(annotation, type):
        return annotation.__qualname__
    return repr(annotation).replace("typing.", "")


def stable(value):
    """`value` as nested JSON-compatible data with a fixed ordering."""
    if value is None or isinstance(value, (bool, int, float, str)) and not isinstance(value, enum.Enum):
        return value
    if isinstance(value, enum.Enum):
        return {"__enum__": f"{type(value).__qualname__}.{value.name}"}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, tuple) and hasattr(value, "_fields"):
        return {"__namedtuple__": type(value).__qualname__,
                "fields": {n: stable(getattr(value, n)) for n in value._fields}}
    if isinstance(value, (tuple, list)):
        return [stable(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return {"__set__": sorted((stable(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))}
    if isinstance(value, (dict, types.MappingProxyType)):
        return {"__dict__": [[stable(k), stable(v)] for k, v in value.items()]}
    if isinstance(value, re.Pattern):
        return {"__pattern__": value.pattern if isinstance(value.pattern, str) else value.pattern.hex(),
                "flags": value.flags}
    if isinstance(value, property):
        return {"__property__": qualname(value.fget)}
    if isinstance(value, (staticmethod, classmethod)):
        return {"__" + type(value).__name__ + "__": qualname(value.__func__)}
    if isinstance(value, functools.partial):
        return {"__partial__": qualname(value.func), "args": stable(value.args),
                "keywords": stable(value.keywords)}
    if inspect.isclass(value):
        return {"__class__": qualname(value)}
    if callable(value) and hasattr(value, "__qualname__"):
        return {"__callable__": qualname(value)}
    if dataclasses.is_dataclass(value):
        return {"__dataclass__": type(value).__qualname__,
                "fields": {f.name: stable(getattr(value, f.name)) for f in dataclasses.fields(value)}}
    return {"__object__": type(value).__qualname__}


def signature(fn) -> "dict | None":
    """Parameter names, kinds, defaults and annotations of `fn`, or None
    when the callable has no introspectable signature."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    params = []
    for p in sig.parameters.values():
        entry = {"name": p.name}
        if p.kind is not inspect.Parameter.POSITIONAL_OR_KEYWORD:
            entry["kind"] = p.kind.name
        if p.default is not inspect.Parameter.empty:
            entry["default"] = stable(p.default)
        ann = annotation_text(p.annotation)
        if ann is not None:
            entry["annotation"] = ann
        params.append(entry)
    out = {"parameters": params}
    ret = annotation_text(sig.return_annotation)
    if ret is not None:
        out["returns"] = ret
    return out


# ── Golden files ──────────────────────────────────────────────────────────


def golden_path(name: str) -> str:
    return os.path.join(GOLDEN_DIR, name)


def dumps(data) -> bytes:
    """The one serialization every golden JSON file uses: sorted keys,
    one-space indent, ASCII escapes, LF newlines, trailing newline."""
    return (json.dumps(data, indent=1, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def load_golden(name: str):
    with open(golden_path(name), "rb") as fh:
        return json.loads(fh.read().decode("ascii"))


def committed_golden(name: str):
    """The committed golden `name`, or None when it does not exist yet."""
    return load_golden(name) if os.path.exists(golden_path(name)) else None


def roundtrip(data):
    """`data` exactly as it reads back from its golden serialization, so a
    live capture and a loaded golden compare like for like."""
    return json.loads(dumps(data).decode("ascii"))


# ── Structural diff ───────────────────────────────────────────────────────


def diff(expected, actual, path="$", limit=40) -> list:
    """Human-readable paths at which `actual` differs from `expected`
    (both JSON data), at most `limit` of them. Empty means equal."""
    out = []
    _diff(expected, actual, path, out, limit)
    return out


def _diff(expected, actual, path, out, limit):
    if len(out) >= limit:
        return
    if type(expected) is not type(actual):
        out.append(f"{path}: expected {_short(expected)}, got {_short(actual)}")
        return
    if isinstance(expected, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in actual:
                out.append(f"{path}.{key}: missing (expected {_short(expected[key])})")
            elif key not in expected:
                out.append(f"{path}.{key}: unexpected {_short(actual[key])}")
            else:
                _diff(expected[key], actual[key], f"{path}.{key}", out, limit)
            if len(out) >= limit:
                return
        return
    if isinstance(expected, list):
        if len(expected) != len(actual):
            out.append(f"{path}: expected {len(expected)} item(s), got {len(actual)}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            _diff(e, a, f"{path}[{i}]", out, limit)
            if len(out) >= limit:
                return
        return
    if expected != actual:
        out.append(f"{path}: expected {_short(expected)}, got {_short(actual)}")


def _short(value) -> str:
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= 160 else text[:157] + "..."


def assert_matches_golden(name: str, actual) -> None:
    """Assert live data equals the committed golden `name`, naming the
    differing paths and the regeneration command on failure."""
    expected = load_golden(name)
    differences = diff(expected, roundtrip(actual))
    assert not differences, (
        f"{name} differs from the committed baseline:\n  " + "\n  ".join(differences)
        + "\nIf this change is an approved behaviour change, regenerate with "
        "`python scripts/update_decomposition_baseline.py` and review the diff; a "
        "relocation commit must not change this file.")
