"""Every hunter that renders a process memory address -- in its
wire-shaped finding facts (``report_facts.py``) or in its console
projection (``report_console.py``) -- routes that address through the
shared ``hex_address()`` helper, so it shows the same fixed-width,
zero-padded 16-hex-digit form on every surface, identical to that
hunter's ``report_record.py`` and ``--json`` output for the same value.
A field formatted with a bare ``0x{...:x}`` is variable width: a low
address misaligns against a high one in the same run, and the console
then disagrees with the JSON for the same value.

The address vocabulary is defined once here, so a reviewer reads the same
list the guard enforces and a hunter -- or a new console renderer in an
existing one -- cannot reintroduce a variable-width address unnoticed.
"""
import ast
import pathlib
import re

import pytest

_HUNT_ROOT = pathlib.Path(__file__).resolve().parents[2] / "dumpex" / "hunt"

# Field labels (matched case-insensitively) that name a process memory
# address. A `<word>_` prefix on any of them is also covered (so `pipe_va`,
# `container_VA`, `StartAddr` need no separate entry beyond their stem).
# NOT addresses, and deliberately absent: `size`, `tid`, `handle`,
# `granted_access`, `region_offset`, `entrypoint_rva` (an RVA has no
# established image base), `distance`, `xor_key`, and dump-file offsets.
ADDRESS_FIELD_NAMES = frozenset({
    "va", "image_base", "base_address", "base", "region",
    "va_start", "va_end", "rip", "eip", "ip", "startaddr", "startaddress",
})

# Accessor / bare-variable stems that resolve to an address inside a
# `0x{...:x}` replacement field -- caught regardless of the literal text
# before the `0x` (e.g. `{thread.ip_reg}=0x{thread.ip:x}`, `VA 0x{m.seg_va:x}`,
# `[f"0x{va:x}" for va in regions]`), which a name-before-`=` scan cannot
# see. A `<word>_` prefix is allowed, so `hit_va`, `seg_va`, `pipe_va`
# match on the `va` stem.
ADDRESS_ATTR_NAMES = frozenset({
    "va", "ip", "rip", "eip", "image_base", "base_address",
    "va_start", "va_end", "start_address",
})
# The subset of the above narrow enough to flag as a bare local variable
# (no attribute access) -- `base`/`region`/`address` alone are too generic
# to assume they hold a VA when used as a plain name.
NAKED_ADDRESS_VAR_STEMS = frozenset({"va", "ip", "rip", "eip"})

# The format spec that makes an address variable-width: a bare `x` (or
# `#x`), i.e. no fill/width. `:016x` and wider are fixed-width and fine;
# `hex_address()` is preferred over both.
_BARE_HEX_SPEC = r":#?x\}"

_NAME_ALT = "|".join(sorted((re.escape(n) for n in ADDRESS_FIELD_NAMES), key=len, reverse=True))
_NAMED_BARE_HEX = re.compile(
    rf"(?i)(?<![\w.])(?:\w+_)?(?:{_NAME_ALT})\s*=\s*0x\{{[^{{}}]*{_BARE_HEX_SPEC}")

_ATTR_ALT = "|".join(sorted((re.escape(n) for n in ADDRESS_ATTR_NAMES), key=len, reverse=True))
_ATTR_BARE_HEX = re.compile(
    rf"(?i)0x\{{[^{{}}]*\.(?:\w+_)?(?:{_ATTR_ALT})\b[^{{}}]*{_BARE_HEX_SPEC}")

_NAKED_ALT = "|".join(sorted((re.escape(n) for n in NAKED_ADDRESS_VAR_STEMS), key=len, reverse=True))
# `0x{ [word_]stem : x }` -- the whole replacement field is a plain
# address-named variable, formatted bare-hex.
_NAKED_VAR_BARE_HEX = re.compile(
    rf"(?i)0x\{{(?:\w+_)?(?:{_NAKED_ALT})\b\s*{_BARE_HEX_SPEC}")

_ALL_PATTERNS = (_NAMED_BARE_HEX, _ATTR_BARE_HEX, _NAKED_VAR_BARE_HEX)


def _projection_modules(basename: str):
    return sorted(_HUNT_ROOT.glob(f"*/{basename}"))


def _fstring_texts(source: str):
    """Every joined-string (f-string) literal source slice in `source`."""
    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            out.append(ast.get_source_segment(source, node) or "")
    return out


def _bare_hex_address_offenders(source: str):
    offenders = []
    for text in _fstring_texts(source):
        for pattern in _ALL_PATTERNS:
            offenders += pattern.findall(text)
    return offenders


@pytest.mark.parametrize(
    "module",
    [*_projection_modules("report_facts.py"), *_projection_modules("report_console.py")],
    ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_address_field_is_rendered_at_variable_width(module):
    offenders = _bare_hex_address_offenders(module.read_text(encoding="utf-8"))
    assert not offenders, (
        f"{module.relative_to(_HUNT_ROOT.parent.parent)} formats an address-typed field "
        f"with a bare 0x{{...:x}} -- use hex_address() (or at least :016x): {offenders}")


def test_every_hunter_report_projection_uses_the_shared_helper():
    """Every hunter's fact projector routes addresses through the one
    helper (injection included, as the reference)."""
    for module in _projection_modules("report_facts.py"):
        source = module.read_text(encoding="utf-8")
        assert "hex_address" in source, (
            f"{module.parent.name}/report_facts.py does not reference hex_address")


def test_guard_patterns_actually_match_a_bare_hex_address():
    """A live check that the regexes above are not silently inert."""
    assert _NAMED_BARE_HEX.search('f"VA=0x{hit.hit_va:x}"')
    assert _NAMED_BARE_HEX.search('f"pipe_va=0x{ev.pipe_va:x}"')
    assert _NAMED_BARE_HEX.search('f"Region=0x{ev.region.base_address:x}"')
    assert _ATTR_BARE_HEX.search('f"{t.ip_reg}=0x{t.ip:x}"')
    assert _ATTR_BARE_HEX.search('f"Beacon config @ 0x{hit.hit_va:x}"')
    assert _ATTR_BARE_HEX.search('f"container_VA=0x{h.location.va:x}"')
    assert _NAKED_VAR_BARE_HEX.search('f"0x{va:x}"')
    assert _NAKED_VAR_BARE_HEX.search('f"regions: 0x{seg_va:x}"')
    # hex_address() form, :016x, and non-address fields must NOT match.
    assert not _NAMED_BARE_HEX.search('f"VA={hex_address(hit.hit_va)}"')
    assert not _ATTR_BARE_HEX.search('f"VA=0x{r.base_address:016x}"')
    assert not _NAKED_VAR_BARE_HEX.search('f"0x{va:016x}"')
    assert not _NAKED_VAR_BARE_HEX.search('f"0x{rva:x}"')
    assert not _NAMED_BARE_HEX.search('f"size=0x{r.size:x} region_offset=0x{o:x}"')
    assert not _ATTR_BARE_HEX.search('f"entrypoint_rva=0x{pe.address_of_entry_point:x}"')
    assert not _ATTR_BARE_HEX.search('f"File_offset=0x{h.location.file_offset:x}"')
