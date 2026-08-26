"""Immutable Cobalt Strike scan and configuration evidence.

Raw segments, regions, TLV fields, locations, and thread context are reduced to
plain values. Candidate retention and scan gaps remain explicit for coverage.
"""
from dataclasses import dataclass, field

from dumpex.core.memory import prot_str
from dumpex.hunt._domain import require_recursively_immutable, as_tuple


# ── Shared field validators -- same two-layer defense every other migrated
# hunter's own models.py applies: an exact field TYPE check (so a poison
# reference is refused at the earliest, most specific point, with a message
# naming the field) plus a `require_recursively_immutable` depth walk.

def _require_type(value, expected, field_name: str) -> None:
    if not isinstance(value, expected):
        expected_names = (expected.__name__ if isinstance(expected, type)
                          else " or ".join(t.__name__ for t in expected))
        raise TypeError(
            f"{field_name} must be a {expected_names}, got {type(value).__name__}: {value!r}")


def _require_optional_type(value, expected, field_name: str) -> None:
    if value is not None:
        _require_type(value, expected, field_name)


def _require_str(value, field_name: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a str, got {type(value).__name__}: {value!r}")


def _require_bytes(value, field_name: str) -> None:
    # Exact type, not isinstance: a `bytearray` is mutable in place and a
    # `memoryview` keeps whatever buffer it was cut from alive and
    # writable -- neither may sit inside a "frozen" evidence object.
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes, got {type(value).__name__}: {value!r}")


def _require_count(value, field_name: str) -> None:
    # bool is excluded explicitly: it is an int subclass, and a stray
    # boolean where an address/size/field-id was meant is a caller bug.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            f"{field_name} must be a non-negative int, got {type(value).__name__}: {value!r}")
    if value < 0:
        raise ValueError(f"{field_name} must be a non-negative int, got {value}")


def _require_optional_count(value, field_name: str) -> None:
    if value is not None:
        _require_count(value, field_name)


# ── Region identity ─────────────────────────────────────────────────────

def region_ref(region) -> "RegionRef | None":
    """The ONE place a raw MemoryInfo region becomes an immutable
    `RegionRef` -- `state`/`protect`/`type` go through `prot_str()` here,
    once, so no projector ever calls it on a live region again. `None` when
    `region` itself is `None` (the hit VA is not covered by
    MemoryInfoListStream at all)."""
    if region is None:
        return None
    return RegionRef(base_address=region.BaseAddress,
                      allocation_base=getattr(region, "AllocationBase", None),
                      size=region.RegionSize, state=prot_str(region.State),
                      protect=prot_str(region.Protect), type=prot_str(region.Type))


@dataclass(frozen=True)
class RegionRef:
    """Immutable snapshot of the MemoryInfo region enclosing a config hit's
    VA. `state`/`protect`/`type` are `prot_str()`-resolved once at scan
    time (see `region_ref()` above)."""
    base_address:    int
    allocation_base: "int | None"
    size:            int
    state:           str      # prot_str(region.State),   resolved once at scan time
    protect:         str      # prot_str(region.Protect), resolved once at scan time
    type:            str      # prot_str(region.Type),    resolved once at scan time

    def __post_init__(self):
        _require_count(self.base_address, "RegionRef.base_address")
        _require_optional_count(self.allocation_base, "RegionRef.allocation_base")
        _require_count(self.size, "RegionRef.size")
        for attribute in ("state", "protect", "type"):
            _require_str(getattr(self, attribute), f"RegionRef.{attribute}")


# ── One TLV field ────────────────────────────────────────────────────────

_VALID_FIELD_TYPES = (1, 2, 3)   # uint16 / uint32 / bytes -- see parser.py


@dataclass(frozen=True)
class ConfigField:
    """Frozen snapshot of one TLV field, exactly as parser.py's
    `_cs_decode_and_parse_tlv()` already decoded it -- `field_id`/`name`/
    `type`/`value`/`raw` all come straight from that already-parsed dict,
    never re-derived here. Building this is the ONE freeze point where a
    candidate's parser-owned `dict` becomes part of the immutable domain
    model.

    `value` is `int` for type 1/2 fields and `str` (either decoded text or
    a NUL-stripped hex string -- see parser._cs_decode_type3_value) for
    type 3. `raw` is the field's full, un-stripped payload bytes -- see
    this module's own docstring for why it is retained here even though it
    never reaches a public dict.
    """
    field_id: int
    name:     str
    type:     int
    value:    "int | str"
    raw:      bytes

    def __post_init__(self):
        _require_count(self.field_id, "ConfigField.field_id")
        _require_str(self.name, "ConfigField.name")
        if self.type not in _VALID_FIELD_TYPES:
            raise ValueError(
                f"ConfigField.type must be one of {_VALID_FIELD_TYPES}, got {self.type!r}")
        if isinstance(self.value, bool) or not isinstance(self.value, (int, str)):
            raise TypeError(
                f"ConfigField.value must be an int or str, got "
                f"{type(self.value).__name__}: {self.value!r}")
        _require_bytes(self.raw, "ConfigField.raw")
        require_recursively_immutable(self, "ConfigField")


def config_field_from_parsed(field_id: int, rec: dict) -> ConfigField:
    """`ConfigField` from one entry of parser.py's own `fields` dict
    (`{name, type, raw, value}`) -- the ONE conversion point scanner.py
    calls for every field of an accepted hit."""
    return ConfigField(field_id=field_id, name=rec["name"], type=rec["type"],
                        value=rec["value"], raw=rec["raw"])


def _require_config_fields(value, field_name: str) -> tuple:
    """Normalize to a tuple (preserving parse order -- see this module's
    own docstring on field identity/order) and require every item to be a
    `ConfigField`, with no duplicate field_id."""
    items = as_tuple(value, field_name)
    seen_ids = set()
    for index, item in enumerate(items):
        if not isinstance(item, ConfigField):
            raise TypeError(
                f"{field_name}[{index}] must be a ConfigField, got "
                f"{type(item).__name__}: {item!r}")
        if item.field_id in seen_ids:
            raise ValueError(
                f"{field_name}[{index}] duplicates field_id 0x{item.field_id:04x} -- "
                f"parser.py's own duplicate-field-id check should have already rejected this")
        seen_ids.add(item.field_id)
    return items


# ── One structurally-valid config hit ───────────────────────────────────

@dataclass(frozen=True)
class ConfigEvidence:
    """One structurally-valid (sanity-checked) beacon config found by
    scanner.py -- the evidence behind the `cs_beacon.structural_config`
    check. `fields` preserves parser.py's own parse order (see this
    module's own docstring on field identity/order); `region` is the
    enclosing MemoryInfo region's `RegionRef`, or `None` when the hit VA is
    not covered by MemoryInfoListStream at all -- resolved once, at scan
    time (see scanner.scan_segments), never re-looked-up later.
    """
    xor_key:    int
    hit_va:     int
    hit_fo:     int
    fields:     tuple
    cs_version: str
    region:     "RegionRef | None" = None

    def __post_init__(self):
        _require_count(self.xor_key, "ConfigEvidence.xor_key")
        _require_count(self.hit_va, "ConfigEvidence.hit_va")
        _require_count(self.hit_fo, "ConfigEvidence.hit_fo")
        object.__setattr__(self, "fields",
                            _require_config_fields(self.fields, "ConfigEvidence.fields"))
        _require_str(self.cs_version, "ConfigEvidence.cs_version")
        _require_optional_type(self.region, RegionRef, "ConfigEvidence.region")
        require_recursively_immutable(self, "ConfigEvidence")

    def field(self, field_id: int) -> "ConfigField | None":
        """The `ConfigField` for `field_id`, or `None` -- the one lookup
        every projector needs, without any of them re-building a dict from
        `self.fields` on every call."""
        for item in self.fields:
            if item.field_id == field_id:
                return item
        return None


# ── Independent memory-context corroboration ────────────────────────────

@dataclass(frozen=True)
class CorroborationEvidence:
    """Independent memory-context corroboration for ONE `ConfigEvidence`
    hit -- the score 1 -> 2 tier. `hit` is the SAME `ConfigEvidence`
    instance the Report's own `evidence.hits` bucket holds (never a copy),
    enforced by identity in `domain.CSBeaconEvidence`. Only ever
    constructed when at least one corroborating reason was found -- an
    uncorroborated hit has no `CorroborationEvidence` at all, mirroring
    `dumpex.hunt.hollowing.models.StructuralCorrelationEvidence`'s own
    "only construct when the signal fires" rule.
    """
    hit:     ConfigEvidence
    reasons: tuple = field(default_factory=tuple)

    def __post_init__(self):
        _require_type(self.hit, ConfigEvidence, "CorroborationEvidence.hit")
        reasons = as_tuple(self.reasons, "CorroborationEvidence.reasons")
        for index, reason in enumerate(reasons):
            _require_str(reason, f"CorroborationEvidence.reasons[{index}]")
        if not reasons:
            raise ValueError(
                "CorroborationEvidence requires at least one reason -- an uncorroborated hit "
                "must not have a CorroborationEvidence at all")
        object.__setattr__(self, "reasons", reasons)
        require_recursively_immutable(self, "CorroborationEvidence")
