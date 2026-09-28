"""
Serialization and validation baseline for every record dataclass.

For each sample in `record_samples.SAMPLES` this captures:

* ``to_dict``  -- the wire projection (or, for a dataclass without one, its
                  stable field projection);
* ``probes``   -- every constructor field replaced, one at a time, with
                  `None` and with an object no validator can accept,
                  recording the exact rejection (exception type and
                  message), or that the value was accepted and whether the
                  wire projection then still succeeded.

* ``cross_field_probes`` -- every string field whose value belongs to a
                  module-level vocabulary replaced by each other member of
                  that vocabulary, and every boolean flipped, one at a
                  time: well-typed values that break a relation between
                  fields (a state that requires or forbids another field),
                  so cross-field invariants are exercised as well.

For each variant in `record_variants.VARIANTS` -- the same class in
another state -- it captures a digest of the projection, the cross-field
probes, and ``fill_probes``: every field that is `None` in the variant set
to the value the class's populated sample carries. A state that forbids
fields (an uncollected profile, an unavailable capability) is exercised
through exactly those fields.

The probes are what make a lost or weakened validator visible: a field
whose rejection turns into acceptance, or whose message changes, shows up
as a golden difference even when no existing focused test names it.

``functions`` covers the module-level record helpers over fixed inputs.
"""
import dataclasses

from dumpex.output import records as rec

from tests.fixtures.decomposition_baseline.record_samples import SAMPLES
from tests.fixtures.decomposition_baseline.record_variants import VARIANTS
from tests.fixtures.decomposition_baseline.stable import stable


class _Unacceptable:
    """A value of no type any validator accepts, with a fixed repr."""

    def __repr__(self):
        return "<unacceptable>"


_PROBE_VALUES = (("none", None), ("unacceptable", _Unacceptable()))


def _outcome(fn):
    try:
        value = fn()
    except Exception as exc:   # noqa: BLE001 -- the exception IS the characterized outcome
        return {"outcome": "rejected", "error": [type(exc).__name__, str(exc)]}
    return {"outcome": "accepted", "value": value}


def _projection(obj):
    to_dict = getattr(obj, "to_dict", None)
    return to_dict() if callable(to_dict) else stable(obj)


def _baseline_names(target: str) -> list:
    """The committed export and private value names of `target`, or --
    before a baseline exists -- the names its namespace binds."""
    from tests.fixtures.decomposition_baseline.stable import committed_golden
    contract = (committed_golden("surface_contract.json") or {}).get(target)
    if contract is None:
        import importlib
        return sorted(n for n in vars(importlib.import_module(target)) if not n.startswith("__"))
    return sorted({*contract["exports"], *contract["private_values"]})


def _vocabularies() -> dict:
    """{member: sorted names of the string vocabularies of records and
    coverage that contain it} -- tuples, frozensets, dict keys and
    str-valued enums among the baseline's names, each resolved to wherever
    it is defined now (see surface.Locator)."""
    import enum
    from tests.fixtures.decomposition_baseline.surface import baseline_object
    out = {}
    for target in ("dumpex.output.records", "dumpex.output.coverage"):
        for name in _baseline_names(target):
            try:
                value = baseline_object(target, name)
            except LookupError:
                continue
            if isinstance(value, type) and issubclass(value, enum.Enum):
                members = [m.value for m in value]
            elif isinstance(value, (tuple, frozenset, set, list, dict)):
                members = list(value)
            else:
                continue
            if not members or not all(isinstance(m, str) for m in members):
                continue
            for member in members:
                out.setdefault(member, set()).add(f"{target}.{name}")
    return out


def _vocabulary_members(vocabularies: dict) -> dict:
    """{vocabulary name: sorted members}."""
    out = {}
    for member, names in vocabularies.items():
        for name in names:
            out.setdefault(name, set()).add(member)
    return {name: sorted(members) for name, members in out.items()}


def _cross_field_values(value, vocabularies, members_of):
    """Replacement values that stay well-typed but can break a relation
    to another field: every other member of each vocabulary the current
    string belongs to, and the opposite of a boolean."""
    if isinstance(value, bool):
        return [("flip", not value)]
    if isinstance(value, str) and value in vocabularies:
        others = sorted({m for name in vocabularies[value] for m in members_of[name]} - {value})
        return [(f"vocab:{m}", m) for m in others]
    return []


def _describe(sample, field, value) -> str:
    built = _outcome(lambda: dataclasses.replace(sample, **{field: value}))
    if built["outcome"] == "rejected":
        return "rejected " + ": ".join(built["error"])
    projected = _outcome(lambda: _projection(built["value"]))
    return ("accepted" if projected["outcome"] == "accepted"
            else "accepted; to_dict raised " + ": ".join(projected["error"]))


def _record_entry(name, factory, vocabularies, members_of):
    sample = factory()
    entry = {"to_dict": stable(_projection(sample)), "probes": {}, "cross_field_probes": {}}
    for field in dataclasses.fields(sample):
        if not field.init:
            continue
        entry["probes"][field.name] = {
            label: _describe(sample, field.name, value) for label, value in _PROBE_VALUES}
        current = getattr(sample, field.name)
        if hasattr(current, "value") and isinstance(getattr(current, "value"), str):
            current = current.value
        cross = {label: _describe(sample, field.name, value)
                 for label, value in _cross_field_values(current, vocabularies, members_of)}
        if cross:
            entry["cross_field_probes"][field.name] = cross
    return entry


def _variant_entry(factory, vocabularies, members_of) -> dict:
    import hashlib
    import json
    variant = factory()
    populated = SAMPLES[type(variant).__qualname__]()
    projection = json.dumps(stable(_projection(variant)), sort_keys=True).encode("utf-8")
    entry = {"to_dict_sha256": hashlib.sha256(projection).hexdigest(),
             "cross_field_probes": {}, "fill_probes": {}}
    for field in dataclasses.fields(variant):
        if not field.init:
            continue
        current = getattr(variant, field.name)
        if hasattr(current, "value") and isinstance(getattr(current, "value"), str):
            current = current.value
        cross = {label: _describe(variant, field.name, value)
                 for label, value in _cross_field_values(current, vocabularies, members_of)}
        if cross:
            entry["cross_field_probes"][field.name] = cross
        filler = getattr(populated, field.name)
        if current is None and filler is not None:
            entry["fill_probes"][field.name] = _describe(variant, field.name, filler)
    return entry


def _functions():
    addresses = [0, 1, 0x7FFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x1_0000_0000_0000_0000, -1,
                 None, True, "0x10"]
    hex_cases = []
    for value in addresses:
        result = _outcome(lambda: rec.hex_address(value))
        if result["outcome"] == "accepted":
            result["value"] = stable(result["value"])
        hex_cases.append([stable(value), result])
    handle_cases = []
    for status in (*rec.HANDLE_NAME_STATUSES, "bogus"):
        for value in (None, "", r"\Device\X", "Unnamed"):
            result = _outcome(lambda: rec.handle_name_display(value, status))
            if result["outcome"] == "accepted":
                result["value"] = stable(result["value"])
            handle_cases.append([status, value, result])
    return {"hex_address": hex_cases, "handle_name_display": handle_cases}


def capture_record_corpus() -> dict:
    vocabularies = _vocabularies()
    members_of = _vocabulary_members(vocabularies)
    return {
        "records": {name: _record_entry(name, factory, vocabularies, members_of)
                    for name, factory in SAMPLES.items()},
        "variants": {name: _variant_entry(factory, vocabularies, members_of)
                     for name, factory in VARIANTS.items()},
        "functions": _functions(),
    }
