"""Shared primitives of every record: address formatting and the field
validators more than one evidence domain applies.

The wire type rule every record in :mod:`dumpex.output.records` follows:
memory addresses and pointers are normalized lowercase hex strings (see
:func:`hex_address`); other numeric values, including dump-file offsets
and bitfields, remain JSON integers. Missing values are ``None``, never an
empty string. Mutable fields are copied when projected so callers cannot
mutate records through a serialized result.

A validator only one domain applies lives with that domain's records.
"""
import re


def hex_address(n) -> "str | None":
    """Normalize an address-like int to a fixed-width (16 hex digit,
    zero-padded), lowercase "0x..." string, or None if `n` is None -- the
    one formatting helper every address-typed field goes through, so the
    normalized form never has to be re-derived ad hoc per command.
    Fixed-width rather than minimal-width so two addresses always compare
    equal-length as strings (matches the convention dumpex/commands/
    modules.py and threads.py's console output already used, e.g.
    `0x{m.baseaddress:016x}`, before this record type existed)."""
    return None if n is None else f"0x{n:016x}"


# Field-shape validators -- not shared with dumpex.output.coverage's own
# similarly-named helpers, since the two modules are otherwise fully
# decoupled by design. Each mirrors a constraint the output schema's $defs
# already enforce on the wire, so the Python model cannot construct (and
# freely .to_dict()) a shape its own schema rejects.

_HEX_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{16}$")


def _require_nonneg_int(value, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative plain int (not bool), got {value!r}")


def _require_bool(value, field_name: str) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a bool, got {value!r}")


def _require_hex_address(value, field_name: str) -> None:
    if not isinstance(value, str) or not _HEX_ADDRESS_RE.match(value):
        raise ValueError(
            f"{field_name} must be a normalized hex address string (\"0x\" + 16 lowercase hex "
            f"digits, see hex_address()), got {value!r}")


def _require_optional_hex_address(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not _HEX_ADDRESS_RE.match(value)):
        raise ValueError(
            f"{field_name} must be None or a normalized hex address string (\"0x\" + 16 "
            f"lowercase hex digits, see hex_address()), got {value!r}")


def _require_optional_diff_str(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, str) or not value):
        raise ValueError(f"{field_name} must be None or a non-empty string, got {value!r}")


def _require_optional_diff_int(value, field_name: str) -> None:
    # bool is a subclass of int in Python -- explicitly excluded, since
    # the wire's JSON "integer" type rejects true/false (see hunt/coverage
    # modules' identical `isinstance(x, bool)` exclusion elsewhere).
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        raise ValueError(f"{field_name} must be None or a plain int (not bool), got {value!r}")


def _require_optional_diff_bool(value, field_name: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{field_name} must be None or a bool, got {value!r}")


def _require_optional_nonneg_int(value, field_name: str) -> None:
    if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
        raise ValueError(f"{field_name} must be None or a non-negative plain int (not bool), "
                          f"got {value!r}")


# The retained-text cap every enrichment projection and PE correlation
# observation carrying dump-derived text obeys. Text is kept exactly as
# captured up to this length and marked truncated past it; console
# escaping happens at the console boundary, never here.
ENRICHMENT_TEXT_CAP = 200


def _require_bounded_text(value, field_name: str, cap: int) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > cap:
        raise ValueError(f"{field_name} must be at most {cap} characters, got {len(value)}")
