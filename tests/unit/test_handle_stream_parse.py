"""Unit tests for dumpex.core.memory.parse_handle_stream() -- issue #37
contract §5.1: a dumpex-owned, bounded, validated HandleDataStream parse
that never walks ObjectInfos, never does an unbounded string read, and
never emits the library's '<STRING_DECODE_FAILED>' placeholder.
"""
import io
import os
import struct

import pytest

import dumpex.core.memory as memory
from dumpex.core.memory import (
    parse_handle_stream, HandleStreamFramingError, ParsedHandleDataStream,
    ParsedHandleDescriptor,
)


class _Location:
    def __init__(self, rva, data_size):
        self.Rva = rva
        self.DataSize = data_size


class _Directory:
    def __init__(self, rva, data_size):
        self.Location = _Location(rva, data_size)


def _minidump_string_bytes(s: str) -> bytes:
    encoded = s.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def _build_handle_stream(descriptors, *, size_of_header=16, size_of_descriptor=32,
                          number_of_descriptors=None, extra_trailing_bytes=b""):
    """Build raw HandleDataStream bytes (header + fixed-size descriptor
    array + a trailing string data area) plus its (rva=0, data_size)
    framing -- data_size covers the header+descriptor array only, never
    the string area, matching real minidumps (strings are read via their
    own absolute RVA into the whole file, independent of the stream's
    own declared size). Each descriptor dict may omit type_name/
    object_name (-> Rva 0, i.e. unnamed) or set them to a string
    ("" is a legal, present-but-empty name, distinct from None)."""
    n = number_of_descriptors if number_of_descriptors is not None else len(descriptors)
    header = struct.pack("<IIII", size_of_header, size_of_descriptor, n, 0)

    desc_area_size = size_of_header + len(descriptors) * size_of_descriptor
    strings_blob = bytearray()
    desc_bytes = bytearray()
    for d in descriptors:
        if "type_name" in d and d["type_name"] is not None:
            type_rva = desc_area_size + len(strings_blob)
            strings_blob += _minidump_string_bytes(d["type_name"])
        else:
            type_rva = 0
        if "object_name" in d and d["object_name"] is not None:
            object_rva = desc_area_size + len(strings_blob)
            strings_blob += _minidump_string_bytes(d["object_name"])
        else:
            object_rva = 0
        fixed = struct.pack("<QIIIIII", d["handle"], type_rva, object_rva,
                             d.get("attributes", 0), d.get("granted_access", 0),
                             d.get("handle_count", 1), d.get("pointer_count", 1))
        if size_of_descriptor == 40:
            fixed += struct.pack("<II", 0, 0)   # ObjectInfoRva, Reserved0 -- never walked
        elif size_of_descriptor != 32:
            fixed = fixed[:size_of_descriptor] if len(fixed) >= size_of_descriptor else \
                fixed + b"\x00" * (size_of_descriptor - len(fixed))
        desc_bytes += fixed

    header_and_descs_bytes = size_of_header + len(descriptors) * size_of_descriptor
    # size_of_header may legitimately exceed 16 -- pad with filler between
    # the 16-byte parsed header and the declared SizeOfHeader.
    padded_header = header + b"\x00" * (size_of_header - 16)
    body = padded_header + bytes(desc_bytes) + bytes(strings_blob) + extra_trailing_bytes
    return body, header_and_descs_bytes


def _parse(descriptors, **kwargs):
    body, data_size = _build_handle_stream(descriptors, **kwargs)
    directory = _Directory(rva=0, data_size=data_size)
    file_handle = io.BytesIO(body)
    return parse_handle_stream(directory, file_handle)


# ── descriptor size derivation (issue #86) ───────────────────────────────

def test_descriptor_sizes_match_ms_defined_layout():
    # dumpex's SizeOfDescriptor branch relies on these being 32 and 40; an
    # upstream layout change should fail loudly here, not silently misread
    # every descriptor in a stream.
    v1_size, v2_size = memory._handle_descriptor_layout()
    assert v1_size == 32
    assert v2_size == 40


def test_layout_is_cached_across_calls():
    first = memory._handle_descriptor_layout()
    second = memory._handle_descriptor_layout()
    assert first is second


def test_layout_derivation_is_not_done_at_import_time():
    # The layout check must run lazily, from inside parse_handle_stream(),
    # not at module import -- a failure here must be isolated to the
    # handle-stream code path by open_dump()'s per-stream try/except, not
    # able to take down `import dumpex.core.memory` (and therefore every
    # dumpex command) the way a top-level assert/computation would. No
    # bare top-level call to _descriptor_class_size or the layout function
    # outside of a function body/definition.
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(memory))
    for node in tree.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            assert name not in ("_descriptor_class_size", "_handle_descriptor_layout"), (
                f"{name}() must not be called at module top level")


def test_upstream_parse_failure_is_isolated_to_handle_stream(monkeypatch):
    # A descriptor class whose parse() raises must not propagate out of
    # parse_handle_stream() as anything other than a normal exception
    # any caller (including open_dump()'s per-stream dispatch) already
    # knows how to catch -- it must not be able to crash import.
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)

    class _BrokenDescriptor:
        @staticmethod
        def parse(buff):
            raise RuntimeError("simulated upstream parse failure")

    monkeypatch.setattr(memory, "MINIDUMP_HANDLE_DESCRIPTOR", _BrokenDescriptor)
    with pytest.raises(memory.HandleDescriptorLayoutError, match="RuntimeError"):
        _parse([{"handle": 0x1}])


def test_simulated_upstream_size_drift_raises_single_attributable_error(monkeypatch):
    # A wrong-but-non-crashing descriptor size (e.g. an upstream layout
    # change that adds a field) must raise ONE error naming both the
    # affected struct and the size it now parses as -- in-process
    # counterpart to the python -O subprocess test above, without the
    # subprocess overhead, covering the "size changed" branch directly
    # rather than only the "parse() raised" branch.
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)

    class _GrownDescriptor:
        @staticmethod
        def parse(buff):
            buff.read(36)   # 4 bytes more than the MS-defined 32

    monkeypatch.setattr(memory, "MINIDUMP_HANDLE_DESCRIPTOR", _GrownDescriptor)
    with pytest.raises(memory.HandleDescriptorLayoutError,
                        match="MINIDUMP_HANDLE_DESCRIPTOR.*36"):
        _parse([{"handle": 0x1}])


def test_size_selection_follows_derived_constants_not_literal(monkeypatch):
    # Force the derived v2 size away from the literal 40 dumpex used to
    # hardcode. The SELECTION path must follow the (patched) derived
    # constants, not a literal baked into the comparison -- proving the
    # branch tracks the derived value rather than merely happening to
    # equal it under today's installed library.
    monkeypatch.setattr(memory, "_handle_descriptor_layout", lambda: (32, 48))

    result = _parse([{"handle": 0x99, "type_name": "Mutant", "object_name": None}],
                     size_of_descriptor=48)
    assert result.header.SizeOfDescriptor == 48
    assert result.handles[0].TypeName == "Mutant"

    # The old-standard 40-byte stride must now be REJECTED: under the
    # patched layout it matches neither derived size.
    with pytest.raises(HandleStreamFramingError):
        _parse([{"handle": 0x1}], size_of_descriptor=40)


def test_equal_derived_sizes_raise_layout_error(monkeypatch):
    # If v1 and v2 ever derive to the same size, the v2 branch becomes
    # permanently unreachable -- every v2 stream would silently parse as
    # v1. This must be caught explicitly rather than left to coincidence.
    monkeypatch.setattr(memory, "_HANDLE_DESCRIPTOR_LAYOUT_CACHE", None)
    monkeypatch.setattr(memory, "_descriptor_class_size", lambda cls: 32)
    with pytest.raises(memory.HandleDescriptorLayoutError, match="never be reachable"):
        memory._handle_descriptor_layout()


def test_descriptor_class_size_rejects_size_attribute_mismatch():
    class _MismatchedDescriptor:
        size = 999

        @staticmethod
        def parse(buff):
            buff.read(32)

    with pytest.raises(memory.HandleDescriptorLayoutError, match="999"):
        memory._descriptor_class_size(_MismatchedDescriptor)


def test_descriptor_class_size_rejects_probe_overflow():
    class _RunawayDescriptor:
        @staticmethod
        def parse(buff):
            buff.read(memory._DESCRIPTOR_PROBE_BYTES)   # consumes the whole probe

    with pytest.raises(memory.HandleDescriptorLayoutError, match="probe buffer"):
        memory._descriptor_class_size(_RunawayDescriptor)


def test_layout_check_survives_python_dash_o():
    # `assert` statements are compiled out entirely under `python -O` /
    # PYTHONOPTIMIZE=1 -- this is a REQUIRED regression test (not merely
    # nice-to-have) because a layout drift check written as a bare
    # `assert` would pass every test in this file under normal `pytest`
    # while providing zero protection in an optimized interpreter. Runs a
    # real subprocess with -O and a descriptor class that parses to the
    # wrong size, and asserts the explicit HandleDescriptorLayoutError
    # still fires. Uses tempfile (not the tmp_path fixture) so this test
    # doesn't depend on pytest's own basetemp directory being writable.
    import subprocess
    import sys
    import tempfile

    script_body = (
        "import dumpex.core.memory as memory\n"
        "\n"
        "class _WrongSizeDescriptor:\n"
        "    @staticmethod\n"
        "    def parse(buff):\n"
        "        buff.read(36)   # neither 32 nor 40\n"
        "\n"
        "memory.MINIDUMP_HANDLE_DESCRIPTOR = _WrongSizeDescriptor\n"
        "memory._HANDLE_DESCRIPTOR_LAYOUT_CACHE = None\n"
        "try:\n"
        "    memory._handle_descriptor_layout()\n"
        "except memory.HandleDescriptorLayoutError as e:\n"
        "    assert 'MINIDUMP_HANDLE_DESCRIPTOR' in str(e)\n"
        "    assert '36' in str(e)\n"
        "    print('LAYOUT_ERROR_RAISED')\n"
        "else:\n"
        "    print('NO_ERROR_RAISED')\n"
    )
    fd, script_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script_body)
        result = subprocess.run(
            [sys.executable, "-O", script_path],
            capture_output=True, text=True, timeout=30,
        )
    finally:
        os.remove(script_path)

    assert "LAYOUT_ERROR_RAISED" in result.stdout, (
        f"stdout={result.stdout!r} stderr={result.stderr!r}")
    assert "NO_ERROR_RAISED" not in result.stdout


# ── basic shape ────────────────────────────────────────────────────────

def test_parses_header_and_returns_expected_type():
    result = _parse([{"handle": 0x234, "type_name": "File", "object_name": r"\Device\NamedPipe\mypipe"}])
    assert isinstance(result, ParsedHandleDataStream)
    assert result.header.NumberOfDescriptors == 1
    assert result.header.SizeOfDescriptor == 32
    assert len(result.handles) == 1


@pytest.mark.parametrize("size_of_descriptor", [32, 40], ids=["v1", "v2"])
def test_descriptor_fields_are_preserved(size_of_descriptor):
    # Symmetric v1/v2 coverage (issue #86 AC 6): every documented field
    # must round-trip identically regardless of which descriptor version
    # produced the stream.
    result = _parse([{"handle": 0x234, "type_name": "File", "object_name": r"\Device\NamedPipe\mypipe",
                       "attributes": 0x40, "granted_access": 0x1200a9,
                       "handle_count": 3, "pointer_count": 32}],
                     size_of_descriptor=size_of_descriptor)
    assert result.header.SizeOfDescriptor == size_of_descriptor
    h = result.handles[0]
    assert isinstance(h, ParsedHandleDescriptor)
    assert h.Handle == 0x234
    assert h.TypeName == "File"
    assert h.ObjectName == r"\Device\NamedPipe\mypipe"
    assert h.Attributes == 0x40
    assert h.GrantedAccess == 0x1200a9
    assert h.HandleCount == 3
    assert h.PointerCount == 32
    assert h.ObjectInfos == []   # never walked, regardless of descriptor version


def test_v2_multiple_descriptors_all_fields_correct_no_misalignment():
    # Regression for a stride bug where descriptors after the first could
    # silently misread if a parser consumed a different byte count than
    # header.SizeOfDescriptor for one descriptor -- each descriptor here
    # carries distinct field values so any cross-descriptor misalignment
    # shows up as a wrong value, not just a wrong count.
    descriptors = [
        {"handle": 0x10, "type_name": "File",  "object_name": "A",
         "attributes": 0x1, "granted_access": 0x1, "handle_count": 1, "pointer_count": 1},
        {"handle": 0x20, "type_name": "Key",   "object_name": "B",
         "attributes": 0x2, "granted_access": 0x2, "handle_count": 2, "pointer_count": 2},
        {"handle": 0x30, "type_name": "Event", "object_name": "C",
         "attributes": 0x3, "granted_access": 0x3, "handle_count": 3, "pointer_count": 3},
    ]
    result = _parse(descriptors, size_of_descriptor=40)
    assert [h.Handle for h in result.handles] == [0x10, 0x20, 0x30]
    assert [h.TypeName for h in result.handles] == ["File", "Key", "Event"]
    assert [h.ObjectName for h in result.handles] == ["A", "B", "C"]
    assert [h.Attributes for h in result.handles] == [0x1, 0x2, 0x3]
    assert [h.GrantedAccess for h in result.handles] == [0x1, 0x2, 0x3]
    assert [h.HandleCount for h in result.handles] == [1, 2, 3]
    assert [h.PointerCount for h in result.handles] == [1, 2, 3]


def test_v2_descriptor_parses_and_object_info_rva_is_never_walked():
    result = _parse([{"handle": 0x99, "type_name": "Mutant", "object_name": None}],
                     size_of_descriptor=40)
    assert result.header.SizeOfDescriptor == 40
    h = result.handles[0]
    assert h.TypeName == "Mutant"
    assert h.ObjectInfos == []


def test_multiple_descriptors_preserve_stream_order():
    result = _parse([
        {"handle": 0x10, "type_name": "File", "object_name": None},
        {"handle": 0x20, "type_name": "Key", "object_name": None},
        {"handle": 0x30, "type_name": "Event", "object_name": None},
    ])
    assert [h.Handle for h in result.handles] == [0x10, 0x20, 0x30]
    assert [h.TypeName for h in result.handles] == ["File", "Key", "Event"]


# ── name resolution: unnamed / present-empty / ok / unreadable ──────────

def test_unnamed_handle_rva_zero_gives_none_and_rva_zero():
    result = _parse([{"handle": 0x1, "type_name": None, "object_name": None}])
    h = result.handles[0]
    assert h.TypeName is None
    assert h.TypeNameRva == 0
    assert h.ObjectName is None
    assert h.ObjectNameRva == 0


def test_present_but_empty_name_is_empty_string_not_none():
    # A non-zero RVA whose MINIDUMP_STRING.Length is 0 is a SUCCESSFUL
    # read of an empty name -- distinct from "no name at all" (Rva == 0)
    # and from "unreadable" (Rva != 0, read failed). See #37 §5.2.1.
    result = _parse([{"handle": 0x1, "type_name": "", "object_name": None}])
    h = result.handles[0]
    assert h.TypeName == ""
    assert h.TypeNameRva != 0


def test_two_names_fail_independently():
    result = _parse([{"handle": 0x1, "type_name": "File", "object_name": None}])
    h = result.handles[0]
    assert h.TypeName == "File"
    assert h.ObjectName is None
    assert h.ObjectNameRva == 0


def test_unreadable_name_rva_points_past_end_of_buffer():
    body, data_size = _build_handle_stream([{"handle": 0x1}])
    # Patch a bogus, out-of-range TypeNameRva directly into the descriptor
    # bytes (offset 8, 4 bytes, little-endian) rather than through the
    # builder, since the builder only ever emits valid RVAs.
    body = bytearray(body)
    struct.pack_into("<I", body, 16 + 8, len(body) + 10_000)
    directory = _Directory(rva=0, data_size=data_size)
    result = parse_handle_stream(directory, io.BytesIO(bytes(body)))
    h = result.handles[0]
    assert h.TypeName is None   # unreadable, never '<STRING_DECODE_FAILED>'
    assert h.TypeNameRva != 0   # still distinguishable from "unnamed"


def test_unreadable_name_length_exceeds_budget():
    body, data_size = _build_handle_stream([{"handle": 0x1}])
    body = bytearray(body)
    # Point TypeNameRva just past the descriptor area and write a
    # MINIDUMP_STRING whose declared Length exceeds MAX_HANDLE_STRING_BYTES.
    rva = len(body)
    struct.pack_into("<I", body, 16 + 8, rva)
    body += struct.pack("<I", memory.MAX_HANDLE_STRING_BYTES + 2) + b"A" * 4
    directory = _Directory(rva=0, data_size=data_size)
    result = parse_handle_stream(directory, io.BytesIO(bytes(body)))
    assert result.handles[0].TypeName is None


def test_decode_failure_never_reaches_placeholder_string():
    body, data_size = _build_handle_stream([{"handle": 0x1}])
    body = bytearray(body)
    rva = len(body)
    struct.pack_into("<I", body, 16 + 8, rva)
    # Length=1 (odd byte count) -- cannot decode as UTF-16LE.
    body += struct.pack("<I", 1) + b"\x41"
    directory = _Directory(rva=0, data_size=data_size)
    result = parse_handle_stream(directory, io.BytesIO(bytes(body)))
    assert result.handles[0].TypeName is None
    assert result.handles[0].TypeName != "<STRING_DECODE_FAILED>"


# ── framing validation (§5.1.1 rules 1-3): parse failure ─────────────────

def test_stream_smaller_than_header_raises_framing_error():
    directory = _Directory(rva=0, data_size=8)
    with pytest.raises(HandleStreamFramingError):
        parse_handle_stream(directory, io.BytesIO(b"\x00" * 8))


def test_header_short_read_raises_framing_error():
    directory = _Directory(rva=0, data_size=16)
    with pytest.raises(HandleStreamFramingError):
        parse_handle_stream(directory, io.BytesIO(b"\x00" * 10))


def test_size_of_header_below_sixteen_raises_framing_error():
    body, _ = _build_handle_stream([{"handle": 0x1}], size_of_header=16)
    body = bytearray(body)
    struct.pack_into("<I", body, 0, 8)   # SizeOfHeader = 8, below the 16-byte minimum
    directory = _Directory(rva=0, data_size=len(body))
    with pytest.raises(HandleStreamFramingError):
        parse_handle_stream(directory, io.BytesIO(bytes(body)))


def test_size_of_header_beyond_data_size_raises_framing_error():
    directory = _Directory(rva=0, data_size=16)
    body = struct.pack("<IIII", 1000, 32, 0, 0)   # SizeOfHeader > DataSize
    with pytest.raises(HandleStreamFramingError):
        parse_handle_stream(directory, io.BytesIO(body))


def test_unrecognized_size_of_descriptor_raises_framing_error():
    body, data_size = _build_handle_stream([{"handle": 0x1}])
    body = bytearray(body)
    struct.pack_into("<I", body, 4, 24)   # neither 32 nor 40
    directory = _Directory(rva=0, data_size=data_size)
    with pytest.raises(HandleStreamFramingError):
        parse_handle_stream(directory, io.BytesIO(bytes(body)))


def test_size_of_header_larger_than_sixteen_is_honored_not_hardcoded():
    # The descriptor array must start at Location.Rva + SizeOfHeader, not
    # a hardcoded +16 -- a header the producer declared as larger carries
    # fields dumpex does not parse, and reading from +16 anyway would
    # silently misread every descriptor.
    result = _parse([{"handle": 0xABCD, "type_name": "File", "object_name": None}],
                     size_of_header=24)
    assert result.header.SizeOfHeader == 24
    assert result.handles[0].Handle == 0xABCD
    assert result.handles[0].TypeName == "File"


# ── truncation (§5.1.1 rules 4-5): not an error, just capped ─────────────

def test_number_of_descriptors_beyond_what_data_size_supports_is_truncated():
    descriptors = [{"handle": i} for i in range(1, 4)]
    body, real_data_size = _build_handle_stream(descriptors)
    # Declare more descriptors than the stream's own DataSize can hold.
    directory = _Directory(rva=0, data_size=real_data_size)
    body2, _ = _build_handle_stream(descriptors, number_of_descriptors=10)
    result = parse_handle_stream(directory, io.BytesIO(body2))
    assert result.header.NumberOfDescriptors == 10
    assert len(result.handles) == 3   # only what fit in DataSize was read
    assert result.header.NumberOfDescriptors - len(result.handles) == 7


def test_trailing_partial_descriptor_is_not_parsed():
    descriptors = [{"handle": 1}, {"handle": 2}]
    body, data_size = _build_handle_stream(descriptors)
    # Widen DataSize to include 20 extra bytes -- less than one whole
    # 32-byte descriptor -- without actually providing descriptor data
    # for it.
    body += b"\x00" * 20
    directory = _Directory(rva=0, data_size=data_size + 20)
    result = parse_handle_stream(directory, io.BytesIO(body))
    assert len(result.handles) == 2   # the trailing partial descriptor is skipped


def test_number_of_descriptors_capped_at_max_handle_descriptors(monkeypatch):
    monkeypatch.setattr(memory, "MAX_HANDLE_DESCRIPTORS", 2)
    descriptors = [{"handle": i} for i in range(1, 6)]
    body, data_size = _build_handle_stream(descriptors)
    directory = _Directory(rva=0, data_size=data_size)
    result = parse_handle_stream(directory, io.BytesIO(body))
    assert len(result.handles) == 2
    assert result.header.NumberOfDescriptors == 5


# ── empty stream ──────────────────────────────────────────────────────────

def test_zero_descriptors_returns_empty_handles_list():
    result = _parse([])
    assert result.header.NumberOfDescriptors == 0
    assert result.handles == []
