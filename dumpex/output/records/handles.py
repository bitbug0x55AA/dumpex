"""`--handles` records and the handle-name display rule.

See docs/developer/recon_process_sysinfo_handles_contract.md §5.2 for the
frozen JSON shape. One record per HandleDataStream descriptor whose Handle
value is usable (§5.2.2 -- the ONE normalization failure that discards a
descriptor); every other field degrades to null in place rather than
costing the record.
"""
from dataclasses import dataclass

from dumpex.output.records.common import _require_hex_address, _require_optional_nonneg_int


HANDLE_NAME_STATUSES = ("ok", "unnamed", "unreadable")
# ^ §5.2.1's three-way discriminator, exported because both the record
# and its console renderer (dumpex.commands.handles) branch on it, and a
# fourth value invented at either end would silently mean "not ok".

# The console/summary labels for the two non-"ok" statuses. Frozen here,
# next to the vocabulary itself, so `by_type` bucketing and the console's
# Type/Object columns can never disagree about what an unnamed or
# unreadable name is called (§5.6 requires both to distinguish them, and
# the two must never merge into one bucket).
HANDLE_NAME_STATUS_LABELS = {
    "unnamed":    "(unnamed)",
    "unreadable": "(unreadable)",
}

# Those two labels are dumpex's own words, but a captured name is an
# arbitrary string from the dump and can be either of them verbatim.
# Every projection of a name to display text goes through
# handle_name_display() below, which reserves the labels for the null-name
# statuses and suffixes a captured name that collides -- so the labels
# always mean "the dump recorded no name" / "the name could not be read",
# in the summary and in the console table alike (§5.6).
HANDLE_RESERVED_NAME_LABELS = frozenset(HANDLE_NAME_STATUS_LABELS.values())
HANDLE_CAPTURED_NAME_SUFFIX = " [captured name]"


def handle_name_display(value: "str | None", status: str) -> str:
    """§5.6: a name is printed as itself when it read, and otherwise as
    the label for ITS OWN status -- never a shared placeholder that would
    tell a reader a handle is anonymous when its name was actually lost.
    Each of a record's two names goes through this independently.

    A captured name equal to one of the two reserved labels is suffixed
    rather than printed as-is: the labels are claims about EVIDENCE ("no
    name was recorded" / "the name could not be read"), and a dump must
    not be able to make dumpex state either one about a handle whose name
    read perfectly well. The record layer is unaffected -- `type_name`
    and `type_name_status` there are already unambiguous; this is purely
    the display projection, shared by the console table and
    `summary.by_type` so the two can never describe the same handle
    differently.

    A captured name that ALREADY ends with the suffix is suffixed too,
    which is what makes this projection injective: without it, a dump
    carrying both `(unnamed)` and `(unnamed) [captured name]` would map
    them to the same label, and the two call sites would then have to
    disambiguate separately -- which is exactly how they drifted apart
    once already (the summary appended a second suffix while the console
    table showed the two handles identically). Injective here means
    neither call site needs any cross-row state to stay consistent:

        f(x) = x + s   if x is a reserved label or x ends with s
        f(x) = x       otherwise

    f(x1) == f(x2) forces x1 == x2 -- x1 + s == x2 would require x2 to
    end with s, in which case f(x2) is x2 + s, not x2."""
    if status != "ok":
        return HANDLE_NAME_STATUS_LABELS[status]
    if value in HANDLE_RESERVED_NAME_LABELS or value.endswith(HANDLE_CAPTURED_NAME_SUFFIX):
        return value + HANDLE_CAPTURED_NAME_SUFFIX
    return value


@dataclass(frozen=True)
class HandleRecord:
    """One `--handles` record -- §5.2. `handle` is a fixed-width hex
    string (§1.3) and is never null: it is the record's only identity and
    §5.4's sort key, so a descriptor without a usable one is discarded by
    the collector instead of reaching this type. `attributes`/
    `granted_access` stay RAW, undecoded masks as plain integers on the
    wire (§5.2) -- console rendering formats granted_access as hex, which
    is a presentation choice, not this record's type.

    The two `*_status` fields are §5.2.1's independent discriminators:
    `null` alone cannot distinguish "this handle has no name" from "this
    handle's name could not be read", and the two fail independently
    (separate RVAs, separate bounded reads), so each name carries its
    own. All nine combinations are representable, and the pairing rule --
    a value is non-null if and only if its status is "ok" -- is enforced
    here rather than left to the collector's discipline, since a record
    claiming "ok" with a null value (or a decoded name filed as
    "unreadable") would make the console and every JSON consumer
    contradict the coverage limitations derived from the same statuses."""
    handle:              str
    type_name:           "str | None"
    type_name_status:    str
    object_name:         "str | None"
    object_name_status:  str
    attributes:          "int | None"
    granted_access:      "int | None"
    handle_count:        "int | None"
    pointer_count:       "int | None"

    def __post_init__(self):
        _require_hex_address(self.handle, "HandleRecord.handle")
        for field_name in ("type_name", "object_name"):
            value = getattr(self, field_name)
            status = getattr(self, f"{field_name}_status")
            if status not in HANDLE_NAME_STATUSES:
                raise ValueError(
                    f"HandleRecord.{field_name}_status must be one of {HANDLE_NAME_STATUSES}, "
                    f"got {status!r}")
            if status == "ok":
                # Non-empty specifically: §1.4 forbids "" on the wire, and
                # §5.2.1 files a successfully-read zero-length name as
                # "unnamed" (nothing was lost), never as "ok".
                if not isinstance(value, str) or not value:
                    raise ValueError(
                        f"HandleRecord.{field_name} must be a non-empty string when "
                        f"{field_name}_status is 'ok', got {value!r}")
            elif value is not None:
                raise ValueError(
                    f"HandleRecord.{field_name} must be None when {field_name}_status is "
                    f"{status!r}, got {value!r}")
        # Non-negative rather than merely int: all four come from unsigned
        # fixed-width descriptor fields, so a negative value would mean a
        # signedness bug upstream, not evidence worth publishing.
        _require_optional_nonneg_int(self.attributes, "HandleRecord.attributes")
        _require_optional_nonneg_int(self.granted_access, "HandleRecord.granted_access")
        _require_optional_nonneg_int(self.handle_count, "HandleRecord.handle_count")
        _require_optional_nonneg_int(self.pointer_count, "HandleRecord.pointer_count")

    def to_dict(self) -> dict:
        return {
            "handle":              self.handle,
            "type_name":           self.type_name,
            "type_name_status":    self.type_name_status,
            "object_name":         self.object_name,
            "object_name_status":  self.object_name_status,
            "attributes":          self.attributes,
            "granted_access":      self.granted_access,
            "handle_count":        self.handle_count,
            "pointer_count":       self.pointer_count,
        }
