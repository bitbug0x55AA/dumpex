"""Unit tests for dumpex.commands.process -- issue #40's collect/render/
command vertical slice over docs/recon_process_sysinfo_handles_contract.md
§3.

Builds on the same fixture style tests/unit/test_process_identity_snapshot.py
and tests/unit/test_iat_parser.py already use: a fake MinidumpFile whose
`memory_segments_64`/`get_reader()` are backed by a plain {va: bytes} map,
so no real .dmp is required.
"""
import io
import struct
import contextlib
import dataclasses

import pytest

from tests.fixtures.fakes import (
    FakeMF, MiscInfo, Peb, Module, FakeStream, Segment, build_pe_header, TEXT_SECTION_RX,
    Thread, Ctx, ExceptionStream,
)

from dumpex.commands.process import collect_process, cmd_process, render_process_console
from dumpex.output import records as records_module
from dumpex.output.coverage import (
    build_coverage_report, exit_code_for, CoverageStatus, LimitationCode, render_limitation,
    SourceObservation, SourceState,
)


IMAGE_BASE = 0x00007ff600010000


# ── Memory fixture plumbing (mirrors test_process_identity_snapshot.py) ──

class _FakeSegment:
    def __init__(self, start, data):
        self.start_address = start
        self.data = data
        self.end_address = start + len(data)

    def remaining_len(self, position):
        if not (self.start_address <= position < self.end_address):
            return None
        return self.end_address - position


class _FakeBufferedReader:
    def __init__(self, segments: dict):
        self._segments = [_FakeSegment(start, data) for start, data in segments.items()]
        self.current_segment = None
        self.current_position = None

    def move(self, address):
        for seg in self._segments:
            if seg.start_address <= address < seg.end_address:
                self.current_segment = seg
                self.current_position = address
                return
        raise Exception("not in process memory space")

    def read(self, size):
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception("read over segment boundary")
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class _FakeReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


def _mf(*, misc_info=None, peb=None, modules=None, memory=None):
    mf = FakeMF()
    mf.misc_info = misc_info
    mf.peb = peb
    mf.modules = FakeStream(modules, "modules") if modules is not None else None
    mf._dumpex_stream_failures = {}
    memory = memory or {}
    mf.memory_segments_64 = (
        FakeStream([Segment(va, va, len(data)) for va, data in memory.items()], "memory_segments")
        if memory else None)
    mf.memory_segments = None
    reader = _FakeReader(_FakeBufferedReader(memory))
    mf.get_reader = lambda: reader
    return mf


# ── PE/IAT byte builders (mirrors tests/unit/test_iat_parser.py) ────────

def _descriptor(original_first_thunk, name_rva, first_thunk):
    return struct.pack('<IIIII', original_first_thunk, 0, 0, name_rva, first_thunk)


_TERMINATOR = _descriptor(0, 0, 0)


def _cstr(name: str) -> bytes:
    return name.encode('ascii') + b'\x00'


def _hint_name(name: str, hint: int = 0) -> bytes:
    return struct.pack('<H', hint) + _cstr(name)


def _thunk64(value: int) -> bytes:
    return struct.pack('<Q', value)


def _pad(data: bytes, length: int = 600) -> bytes:
    """Pad a name string's backing bytes to comfortably exceed
    dumpex.core.pe_utils.MAX_IAT_NAME_LENGTH (512) -- a real captured PE
    image page is far larger than any one string inside it, and the fake
    buffered reader (like the real one) raises rather than short-reading
    when a bounded name read runs past its OWN segment's end."""
    return data.ljust(length, b"\x00")


def _patch_data_directories(header: bytes, directories: dict) -> bytes:
    """Patch a build_pe_header() PE32+ image's NumberOfRvaAndSizes (16) and
    its 16 (rva, size) directory entries -- `directories` maps index ->
    (rva, size), unset indices stay (0, 0)."""
    e_lfanew = 0x80
    coff_off = e_lfanew + 4
    opt_off = coff_off + 20
    num_rva_off = opt_off + 108
    dir_off = opt_off + 112
    buf = bytearray(header)
    struct.pack_into('<I', buf, num_rva_off, 16)
    for i in range(16):
        rva, size = directories.get(i, (0, 0))
        struct.pack_into('<II', buf, dir_off + i * 8, rva, size)
    return bytes(buf)


def _truncate_directory_table(header: bytes, entries_captured: int) -> bytes:
    """Cut a _patch_data_directories()-patched header off right after the
    `entries_captured`-th (rva, size) pair -- simulating a capture that
    stops partway through a data directory table whose OWN declared
    NumberOfRvaAndSizes (16, from _patch_data_directories()) is larger
    than what was actually captured (§3.5.2/§8.3 item 6b)."""
    e_lfanew = 0x80
    coff_off = e_lfanew + 4
    opt_off = coff_off + 20
    dir_off = opt_off + 112
    return header[:dir_off + entries_captured * 8]


def _build_valid_image_with_one_import(image_base=IMAGE_BASE):
    """One structurally valid PE32+ image, KERNEL32.dll!CreateFileW
    imported by name, IAT/import directories both declared and correct."""
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    dll_name_rva = 0x4000
    int_rva = 0x5000      # Import Name Table (OriginalFirstThunk)
    name_hint_rva = 0x6000

    header = build_pe_header([TEXT_SECTION_RX], image_base=image_base, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 16)})

    descr = _descriptor(int_rva, dll_name_rva, iat_dir_rva)

    memory = {
        image_base: header,
        image_base + import_dir_rva: descr + _TERMINATOR,
        image_base + dll_name_rva: _pad(_cstr("KERNEL32.dll")),
        image_base + int_rva: _thunk64(name_hint_rva) + _thunk64(0),
        image_base + name_hint_rva: _pad(_hint_name("CreateFileW")),
        image_base + iat_dir_rva: _thunk64(0x00007ffb12345678) + _thunk64(0),
    }
    return memory


def _build_valid_image_no_imports(image_base=IMAGE_BASE):
    """A structurally valid PE32+ image that declares NO import directory
    at all (index 1's RVA is zero -- a determined 'no imports' claim,
    §3.5.2)."""
    header = build_pe_header([TEXT_SECTION_RX], image_base=image_base, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (0, 0), 12: (0, 0)})
    return {image_base: header}


# ── P1 regression: parse_iat()'s read callback must clamp to captured
# bytes, not request MAX_IAT_NAME_LENGTH/thunk-width unconditionally and
# treat a segment boundary as "failed" ──────────────────────────────────

def test_iat_name_and_symbol_recovered_from_exactly_sized_captured_segments():
    """DLL name and symbol name each sit in a segment sized to hold
    EXACTLY their own bytes (no trailing padding) -- a real captured PE
    page is usually much larger than any one string inside it, but the
    dump's OWN capture can legitimately stop right at a page boundary.
    Both names are fully present in the dump; they must be recovered, not
    reported as IAT_NAME_READ_FAILED."""
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    dll_name_rva = 0x4000
    int_rva = 0x5000
    name_hint_rva = 0x6000

    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 16)})
    descr = _descriptor(int_rva, dll_name_rva, iat_dir_rva)

    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + dll_name_rva: _cstr("KERNEL32.dll"),          # exactly sized, no padding
        IMAGE_BASE + int_rva: _thunk64(name_hint_rva) + _thunk64(0),
        IMAGE_BASE + name_hint_rva: _hint_name("CreateFileW"),      # exactly sized, no padding
        IMAGE_BASE + iat_dir_rva: _thunk64(0x00007ffb12345678) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []

    entry = result.records[0].iat.entries[0]
    assert entry.dll == "KERNEL32.dll"
    assert entry.symbol == "CreateFileW"
    assert entry.resolved_target_va == "0x00007ffb12345678"


def test_iat_name_recovered_when_a_captured_segment_immediately_follows():
    """Same shape as the previous test, but the DLL name's own segment is
    immediately followed (CONTIGUOUS, no gap) by another captured
    segment -- the layout every full-memory dump's own VirtualQuery-
    derived region table produces at a protection-attribute boundary
    inside one mapped image (.text RX | .rdata R | .data RW are adjacent
    descriptors). va_range_captured_bytes() would report a captured
    length spanning INTO that neighbour; the read must still stay
    bounded to the name's own segment (where the NUL terminator already
    is) rather than requesting bytes read_region()'s underlying reader
    would raise trying to serve across the segment boundary."""
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    dll_name_rva = 0x4000
    int_rva = 0x5000
    name_hint_rva = 0x6000

    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 16)})
    descr = _descriptor(int_rva, dll_name_rva, iat_dir_rva)
    dll_name_bytes = _cstr("KERNEL32.dll")

    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + dll_name_rva: dll_name_bytes,
        # Contiguous neighbour segment, immediately after the name's own
        # bytes end -- no gap.
        IMAGE_BASE + dll_name_rva + len(dll_name_bytes): b"\x00" * 0x40,
        IMAGE_BASE + int_rva: _thunk64(name_hint_rva) + _thunk64(0),
        IMAGE_BASE + name_hint_rva: _hint_name("CreateFileW"),
        IMAGE_BASE + iat_dir_rva: _thunk64(0x00007ffb12345678) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []

    entry = result.records[0].iat.entries[0]
    assert entry.dll == "KERNEL32.dll"
    assert entry.symbol == "CreateFileW"
    assert entry.resolved_target_va == "0x00007ffb12345678"


def test_iat_descriptor_partial_capture_is_short_read_not_directory_read_failed():
    """The first import descriptor's own 20-byte structure is only
    HALF captured (its segment holds 10 bytes) -- a genuine short read,
    distinct from a totally unreadable directory. Must be reported as
    IAT_DIRECTORY_SHORT_READ, never IAT_DIRECTORY_READ_FAILED (which
    claims nothing about the import table was recovered at all)."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0, 0)})
    descr = _descriptor(0x5000, 0x4000, 0x3000)
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: (descr + _TERMINATOR)[:10],   # only 10 of 20 bytes captured
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.IAT_DIRECTORY_SHORT_READ in codes
    assert LimitationCode.IAT_DIRECTORY_READ_FAILED not in codes


# ── P2 fix: main image PE header is read/parsed exactly once ────────────

def test_main_image_header_is_read_exactly_once_across_snapshot_and_iat_walk():
    mf = _complete_mf()
    read_calls = []
    real_reader = mf.get_reader()

    class _CountingBufferedReader:
        def __init__(self, inner):
            self._inner = inner

        @property
        def current_segment(self):
            # A live proxy, not a stale copy taken at construction time --
            # dumpex.core.memory.read_region_spanning() reads this
            # straight after move(), so a snapshot frozen before the
            # first move() would always see the inner reader's initial
            # (pre-move) None/None state.
            return self._inner.current_segment

        @property
        def current_position(self):
            return self._inner.current_position

        def move(self, address):
            return self._inner.move(address)

        def read(self, size):
            read_calls.append((self._inner.current_position, size))
            return self._inner.read(size)

    counting = _CountingBufferedReader(real_reader._buffered)
    mf.get_reader = lambda: _FakeReader(counting)

    collect_process(mf)
    header_reads = [c for c in read_calls if c[0] == IMAGE_BASE]
    assert len(header_reads) == 1, f"main image header read more than once: {header_reads}"
    # A loose sanity bound on the TOTAL read count, not just reads at
    # IMAGE_BASE itself -- catches a regression where some later change
    # starts reading from IMAGE_BASE + 1 (or any other non-zero offset)
    # instead, which the header_reads filter above would not detect on
    # its own since it only ever matches position == IMAGE_BASE exactly.
    assert len(read_calls) < 20, f"unexpectedly many reads for one small IAT walk: {read_calls}"


def test_clamped_reader_is_hoisted_not_rebuilt_per_read():
    """dumpex.core.memory.clamped_reader(mf) must construct its
    MinidumpBufferedReader ONCE and reuse it across every read the IAT
    walk issues -- not reconstruct one (via mf.get_reader()) per bounded
    read, which would re-trigger the underlying reader's own per-
    construction setup for what can be thousands of reads in one walk
    (MAX_IAT_READ_OPERATIONS = 8192)."""
    mf = _complete_mf()
    get_reader_calls = []
    real_get_reader = mf.get_reader

    def counting_get_reader():
        get_reader_calls.append(1)
        return real_get_reader()

    mf.get_reader = counting_get_reader
    collect_process(mf)
    # One get_reader() call for the shared process-identity snapshot's
    # own main-image header read (dumpex.core.memory.read_region(), a
    # one-shot call), and exactly one more for the IAT walk's single
    # hoisted clamped_reader() -- never one per bounded read inside it.
    assert len(get_reader_calls) <= 2, f"get_reader() called {len(get_reader_calls)} times: expected <= 2"


# ── Basic empty-dump / not_evaluated shape ───────────────────────────────

def test_empty_dump_is_not_evaluated():
    mf = _mf()
    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status.value) == 4
    assert any(lim.code == LimitationCode.PROCESS_SOURCES_ABSENT
               for lim in result.coverage.limitations)


def test_empty_dump_still_returns_exactly_one_all_null_record():
    mf = _mf()
    result = collect_process(mf)
    assert result.summary == {"count": 1}
    assert len(result.records) == 1
    record = result.records[0]
    assert record.process_name is None
    assert record.pid is None
    assert record.process_path is None
    assert record.command_line is None
    assert record.process_start_utc is None
    assert record.image_base_address is None
    assert record.iat.table_present is None
    assert record.iat.entries == ()
    assert record.identity_evidence["diagnostics"] == []


# ── Complete process record with imports (§8.3 baseline) ────────────────

def _complete_mf():
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe",
              command_line=r'"C:\Samples\malware.exe" -k')
    mod = Module(IMAGE_BASE, 0x6000, r"C:\Samples\malware.exe")
    memory = _build_valid_image_with_one_import()
    return _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)


def test_complete_process_record_with_imports():
    mf = _complete_mf()
    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status.value) == 0
    assert result.coverage.limitations == []

    record = result.records[0]
    assert record.process_name == "malware.exe"
    assert record.pid == 4242
    assert record.process_path == r"C:\Samples\malware.exe"
    assert record.command_line == '"C:\\Samples\\malware.exe" -k'
    assert record.process_start_utc == "2026-08-14 01:15:05 UTC"
    assert record.image_base_address == "0x00007ff600010000"

    assert record.iat.import_directory_present is True
    assert record.iat.table_present is True
    assert record.iat.has_entries is True
    assert record.iat.dll_count == 1
    assert record.iat.entry_count == 1
    entry = record.iat.entries[0]
    assert entry.dll == "KERNEL32.dll"
    assert entry.import_by == "name"
    assert entry.symbol == "CreateFileW"
    assert entry.ordinal is None
    assert entry.resolved_target_va == "0x00007ffb12345678"
    assert entry.slot_in_bounds is True

    ev = record.identity_evidence
    assert ev["selected_path_source"] == "peb"
    assert ev["module_claim"]["match_state"] == "resolved"
    assert ev["diagnostics"] == []


def test_complete_process_record_console_prints_import_count():
    mf = _complete_mf()
    result = collect_process(mf)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(result.records[0], result.coverage)
    out = buf.getvalue()
    assert "1 import(s) across 1 DLL(s)" in out
    assert "malware.exe" in out
    assert "4242 (0x1092)" in out


# ── Valid process with no imports ────────────────────────────────────────

def test_valid_pe_with_no_imports_is_complete_not_partial():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mod = Module(IMAGE_BASE, 0x6000, r"C:\a.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status.value) == 0

    record = result.records[0]
    assert record.iat.import_directory_present is False
    assert record.iat.has_entries is False
    assert record.iat.entries == ()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    assert "(none -- this image declares no imports)" in buf.getvalue()


# ── Each source absent independently ─────────────────────────────────────

def test_misc_info_absent_yields_dedicated_limitation():
    peb = Peb(IMAGE_BASE, r"C:\a.exe")
    mf = _mf(peb=peb)
    result = collect_process(mf)
    assert any(lim.code == LimitationCode.PROCESS_MISC_INFO_UNAVAILABLE
               for lim in result.coverage.limitations)
    assert result.records[0].pid is None


def test_peb_absent_yields_dedicated_limitation():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    mf = _mf(misc_info=misc)
    result = collect_process(mf)
    assert any(lim.code == LimitationCode.PROCESS_PEB_UNAVAILABLE
               for lim in result.coverage.limitations)
    assert result.records[0].process_path is None
    assert result.records[0].image_base_address is None


def test_modules_absent_with_no_peb_path_yields_fallback_unavailable():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, None)   # no PEB path -> fallback needed
    mf = _mf(misc_info=misc, peb=peb, modules=None)
    result = collect_process(mf)
    assert any(lim.code == LimitationCode.PROCESS_MODULE_FALLBACK_UNAVAILABLE
               for lim in result.coverage.limitations)
    assert any(lim.code == LimitationCode.PROCESS_PATH_UNAVAILABLE
               for lim in result.coverage.limitations)


def test_modules_absent_is_silent_when_peb_path_present():
    """§3.7.4: modules is a pure observer when the fallback was never
    needed -- absent modules must not affect status at all."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=None, memory=memory)
    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert result.coverage.limitations == []


# ── All identity sources absent (via all-invalid, not merely None) ──────

def test_all_five_fields_invalid_exits_4_but_retains_per_field_reasons():
    """§8.3 item 5: PID=0, ProcessCreateTime beyond uint32, unaligned image
    base, empty path/command line -- both source OBJECTS still exist, so
    the per-field reasons must survive alongside the aggregate code."""
    misc = MiscInfo(process_id=0, process_create_time=0x1_0000_0000)
    peb = Peb(0x00007ff600010abc, "", command_line="")
    mf = _mf(misc_info=misc, peb=peb)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.NOT_EVALUATED
    assert exit_code_for(result.coverage.status.value) == 4

    codes = [lim.code for lim in result.coverage.limitations]
    assert codes[0] == LimitationCode.PROCESS_SOURCES_ABSENT
    assert LimitationCode.PROCESS_PID_UNAVAILABLE in codes
    assert LimitationCode.PROCESS_START_TIME_INVALID in codes
    assert LimitationCode.PROCESS_IMAGE_BASE_INVALID in codes
    assert LimitationCode.PROCESS_COMMAND_LINE_UNAVAILABLE in codes
    assert LimitationCode.PROCESS_PATH_UNAVAILABLE in codes

    ev = result.records[0].identity_evidence
    assert ev["misc_info_claim"]["raw_pid"] == 0
    assert ev["misc_info_claim"]["raw_process_create_time"] == 0x1_0000_0000
    assert ev["peb_claim"]["raw_image_base_address"] == "0x00007ff600010abc"


def test_pid_zero_preserves_raw_value_and_does_not_count_as_available():
    misc = MiscInfo(process_id=0, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, memory=memory)
    result = collect_process(mf)
    assert result.records[0].pid is None
    assert result.records[0].identity_evidence["misc_info_claim"]["raw_pid"] == 0
    assert any(lim.code == LimitationCode.PROCESS_PID_UNAVAILABLE
               for lim in result.coverage.limitations)
    # start time/path/cmdline/image base all still available -> partial, not not_evaluated
    assert result.coverage.status == CoverageStatus.PARTIAL


# ── PEB/module base conflict: fallback never erases a preferred claim ───

def test_peb_module_base_conflict_stays_complete_with_diagnostic_only():
    """§8.3 item 6: a same-named module at a DIFFERENT base must not
    overwrite the PEB's own image_base_address, must not downgrade
    coverage, and must surface as a diagnostic."""
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\Samples\malware.exe")
    other_base = 0x00007ff700000000
    mod = Module(other_base, 0x6000, r"C:\Windows\Temp\malware.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status.value) == 0
    assert result.coverage.limitations == []

    record = result.records[0]
    assert record.image_base_address == "0x00007ff600010000"   # unchanged, still the PEB's own claim

    ev = record.identity_evidence
    codes = [d["code"] for d in ev["diagnostics"]]
    assert "PROCESS_MODULE_BASE_CONFLICT" in codes
    conflict = next(d for d in ev["diagnostics"] if d["code"] == "PROCESS_MODULE_BASE_CONFLICT")
    assert conflict["details"]["module_base"] == "0x00007ff700000000"
    assert conflict["details"]["peb_base"] == "0x00007ff600010000"


# ── Module fallback (peb path absent) ────────────────────────────────────

def test_module_fallback_supplies_path_and_fires_source_fallback_diagnostic():
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, None)   # no PEB path at all
    mod = Module(IMAGE_BASE, 0x6000, r"C:\Windows\Temp\malware.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    record = result.records[0]
    assert record.process_path == r"C:\Windows\Temp\malware.exe"
    assert record.process_name == "malware.exe"
    ev = record.identity_evidence
    assert ev["selected_path_source"] == "module"
    codes = [d["code"] for d in ev["diagnostics"]]
    assert "PROCESS_PATH_SOURCE_FALLBACK" in codes
    # PROCESS_PATH_UNAVAILABLE must NOT fire -- the fallback succeeded.
    assert not any(lim.code == LimitationCode.PROCESS_PATH_UNAVAILABLE
                    for lim in result.coverage.limitations)


def test_module_fallback_with_pathless_module_stays_path_unavailable():
    """The module resolved by exact base has NO usable path of its own
    (whitespace-only, normalizes to null) -- the fallback did not
    actually produce anything, so this must stay PROCESS_PATH_UNAVAILABLE
    (not a successful fallback), and no PROCESS_PATH_SOURCE_FALLBACK
    diagnostic (which would falsely claim ModuleListStream supplied a
    path) may appear."""
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, None)   # no PEB path at all
    mod = Module(IMAGE_BASE, 0x6000, "   ")   # resolved by base, but path is whitespace-only
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    record = result.records[0]
    assert record.process_path is None
    assert record.process_name is None
    ev = record.identity_evidence
    assert ev["selected_path_source"] is None
    assert ev["module_claim"]["match_state"] == "resolved"
    codes = [d["code"] for d in ev["diagnostics"]]
    assert "PROCESS_PATH_SOURCE_FALLBACK" not in codes
    assert any(lim.code == LimitationCode.PROCESS_PATH_UNAVAILABLE
               for lim in result.coverage.limitations)


# ── IAT: import directory present, IAT directory absent ─────────────────

def test_iat_directory_read_failed_when_nothing_captured_for_first_descriptor():
    """The Import Directory is declared present (RVA nonzero), but
    NOTHING is captured at that address at all -- a failure on the very
    FIRST descriptor read means nothing about the import table was ever
    recovered, which is IAT_DIRECTORY_READ_FAILED, distinct from
    IAT_DESCRIPTOR_READ_FAILED (a LATER descriptor failing after earlier
    ones succeeded)."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 20), 12: (0, 0)})
    memory = {IMAGE_BASE: header}   # nothing captured at import_dir_rva at all
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.IAT_DIRECTORY_READ_FAILED in codes
    assert LimitationCode.IAT_DESCRIPTOR_READ_FAILED not in codes
    assert result.records[0].iat.entries == ()


def test_iat_descriptor_read_failed_for_a_later_descriptor():
    """The FIRST descriptor is fully captured and real (non-terminator);
    the SECOND descriptor's own address has nothing captured there at
    all -- a failure past the first descriptor is IAT_DESCRIPTOR_READ_
    FAILED, not IAT_DIRECTORY_READ_FAILED (which claims nothing at all
    was recovered -- false here, since the first descriptor WAS)."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 100), 12: (0, 0)})   # capacity for 5
    descr = _descriptor(0, 1, 0)   # real (non-terminator): Name=1; no thunk walk (FirstThunk=0)
    memory = {
        IMAGE_BASE: header,
        # Only the FIRST descriptor's own 20 bytes are captured; nothing
        # at import_dir_rva + 20 (the second descriptor's own address).
        IMAGE_BASE + import_dir_rva: descr,
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.IAT_DIRECTORY_READ_FAILED not in codes
    descriptor_failed = next(lim for lim in result.coverage.limitations
                              if lim.code == LimitationCode.IAT_DESCRIPTOR_READ_FAILED)
    assert descriptor_failed.affected_count == 1
    assert result.records[0].iat.dll_count == 1   # the first descriptor was still counted


def test_iat_descriptor_short_read_for_a_later_descriptor():
    """The second descriptor's own address is captured, but only
    PARTIALLY (10 of its own 20 bytes) -- a short read, not a total
    failure, and (being the second descriptor, not the first)
    IAT_DESCRIPTOR_SHORT_READ, not IAT_DIRECTORY_SHORT_READ."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 100), 12: (0, 0)})
    descr = _descriptor(0, 1, 0)
    second_descr = _descriptor(0, 1, 0)
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr,
        # Second descriptor's own segment: only 10 of its 20 bytes.
        IMAGE_BASE + import_dir_rva + 20: second_descr[:10],
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.IAT_DIRECTORY_SHORT_READ not in codes
    short_read = next(lim for lim in result.coverage.limitations
                       if lim.code == LimitationCode.IAT_DESCRIPTOR_SHORT_READ)
    assert short_read.affected_count == 1
    assert result.records[0].iat.dll_count == 1


def test_iat_thunk_short_read_when_thunk_segment_partially_captured():
    """A thunk slot's own address is captured, but with fewer bytes than
    the 8-byte (PE32+) thunk width needs -- a short read, distinct from
    IAT_THUNK_READ_FAILED (nothing captured there at all)."""
    import_dir_rva = 0x2000
    int_rva = 0x5000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0, 0)})
    descr = _descriptor(int_rva, 0, 0)   # OriginalFirstThunk=int_rva -> using_int, thunk walk runs
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        # The thunk slot's own segment has only 4 of the 8 bytes a PE32+
        # thunk needs.
        IMAGE_BASE + int_rva: _thunk64(0x1234)[:4],
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    short_read = next(lim for lim in result.coverage.limitations
                       if lim.code == LimitationCode.IAT_THUNK_SHORT_READ)
    assert short_read.affected_count == 1
    assert any(lim.code == LimitationCode.IAT_UNTERMINATED_TABLE
               for lim in result.coverage.limitations)


def test_import_present_iat_directory_absent_is_diagnostic_not_limitation():
    """§8.3 item 6: an image with an import directory but no IAT directory
    yields table_present: false, slot_in_bounds: null on every entry, one
    IAT_BOUNDS_CHECK_UNAVAILABLE diagnostic, and exit 0 with entries still
    fully reported."""
    import_dir_rva = 0x2000
    dll_name_rva = 0x4000
    int_rva = 0x5000
    name_hint_rva = 0x6000

    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0, 0)})
    descr = _descriptor(int_rva, dll_name_rva, 0x7000)   # FirstThunk arbitrary, no IAT range to check
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + dll_name_rva: _pad(_cstr("KERNEL32.dll")),
        IMAGE_BASE + int_rva: _thunk64(name_hint_rva) + _thunk64(0),
        IMAGE_BASE + name_hint_rva: _pad(_hint_name("CreateFileW")),
        IMAGE_BASE + 0x7000: _thunk64(0x1234) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    assert exit_code_for(result.coverage.status.value) == 0
    assert result.coverage.limitations == []

    record = result.records[0]
    assert record.iat.table_present is False
    assert record.iat.has_entries is True
    assert len(record.iat.entries) == 1
    assert record.iat.entries[0].slot_in_bounds is None
    diag_codes = [d.code for d in record.iat.diagnostics]
    assert "IAT_BOUNDS_CHECK_UNAVAILABLE" in diag_codes


# ── IAT diagnostics reach the default console (P2 fix) ───────────────────

def test_iat_slot_out_of_bounds_diagnostic_prints_on_default_console():
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 8)})
    descr = _descriptor(0, 0, iat_dir_rva)   # OriginalFirstThunk=0 -> import_by "unavailable"
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        # table_size declared as 8 (one slot) but two real thunks are present.
        IMAGE_BASE + iat_dir_rva: _thunk64(0x1111) + _thunk64(0x2222) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    record = result.records[0]
    assert result.coverage.status == CoverageStatus.COMPLETE   # a diagnostic, not a limitation
    diag_codes = [d.code for d in record.iat.diagnostics]
    assert "IAT_SLOT_OUT_OF_DIRECTORY_BOUNDS" in diag_codes

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    out = buf.getvalue()
    assert "[!]" in out
    assert "IAT slot(s) fall outside the declared IAT directory range" in out


# ── §8.3 6b/6b2-style collector-level IAT limitation mapping ────────────

def test_iat_entries_truncated_via_dll_count_budget_carries_scope_and_budget():
    """Exceeding MAX_IAT_DLLS forces IAT_ENTRIES_TRUNCATED with a real
    scope/budget_limit/budget_consumed attribution -- proving the
    IatTruncation -> CoverageLimitation mapping in collect_process()
    actually wires all three fields, not just the code."""
    from dumpex.core.pe_utils import MAX_IAT_DLLS

    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    descriptor_count = MAX_IAT_DLLS + 2
    header = _patch_data_directories(header, {1: (import_dir_rva, descriptor_count * 20 + 20), 12: (0, 0)})
    # OriginalFirstThunk=0 and FirstThunk=0 -> no thunk walk at all (each
    # descriptor contributes zero entries, so nothing here can trip
    # IAT_CYCLE_DETECTED); Name=i+1 (distinct, nonzero) only so each
    # descriptor is a "real" one, never mistaken for the all-zero
    # terminator pattern -- each still counts against MAX_IAT_DLLS.
    descriptors = b"".join(_descriptor(0, i + 1, 0) for i in range(descriptor_count)) + _TERMINATOR
    memory = {IMAGE_BASE: header, IMAGE_BASE + import_dir_rva: descriptors}
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    truncated = next(lim for lim in result.coverage.limitations
                      if lim.code == LimitationCode.IAT_ENTRIES_TRUNCATED)
    assert truncated.scope == "iat_dlls"
    assert truncated.budget_limit == MAX_IAT_DLLS
    assert truncated.budget_consumed == MAX_IAT_DLLS
    assert "budget: iat_dlls" in render_limitation(truncated)


def test_iat_thunk_read_failed_carries_affected_count():
    """A thunk slot whose own address is never captured by any segment at
    all -> IAT_THUNK_READ_FAILED (clamped read returns b'' -- a genuine
    failure, distinct from the P1 short-capture case where SOME bytes
    were captured)."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0, 0)})
    # OriginalFirstThunk points at an RVA with NOTHING captured there at all.
    descr = _descriptor(0x9000, 0, 0x9000)
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    thunk_failed = next(lim for lim in result.coverage.limitations
                         if lim.code == LimitationCode.IAT_THUNK_READ_FAILED)
    assert thunk_failed.affected_count == 1
    assert any(lim.code == LimitationCode.IAT_UNTERMINATED_TABLE
               for lim in result.coverage.limitations)


def test_iat_name_read_failed_when_nothing_captured_at_name_address():
    """Companion to the P1 fix: a DLL name RVA pointing at an address with
    NOTHING captured there at all (not merely a short segment) is a
    genuine IAT_NAME_READ_FAILED -- distinct from the P1 case where the
    name's own bytes ARE in the dump but the naive request size exceeded
    the captured segment. The sibling FirstThunk array IS captured and
    readable, so the entry itself is still reported (dll: null, everything
    else intact) -- a failed name read never drops the whole entry."""
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0, 0)})
    # OriginalFirstThunk=0 (import_by "unavailable", no name lookup via
    # INT) but Name points at an address with no captured segment at all.
    descr = _descriptor(0, 0x9000, iat_dir_rva)
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + iat_dir_rva: _thunk64(0x1234) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    name_failed = next(lim for lim in result.coverage.limitations
                        if lim.code == LimitationCode.IAT_NAME_READ_FAILED)
    assert name_failed.affected_count == 1
    entry = result.records[0].iat.entries[0]
    assert entry.dll is None
    assert entry.resolved_target_va == "0x0000000000001234"


def test_iat_cycle_detected_stops_the_whole_walk():
    """Two descriptors declaring the identical OriginalFirstThunk RVA --
    the second visit to that exact thunk-array address is a genuine
    structural cycle (§39), and the ENTIRE walk stops, not just the
    second descriptor."""
    import_dir_rva = 0x2000
    int_rva = 0x5000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 60), 12: (0, 0)})
    descr1 = _descriptor(int_rva, 0, 0)
    descr2 = _descriptor(int_rva, 0, 0)   # identical OriginalFirstThunk -> revisits same address
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr1 + descr2 + _TERMINATOR,
        IMAGE_BASE + int_rva: _thunk64(0x1234) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert any(lim.code == LimitationCode.IAT_CYCLE_DETECTED for lim in result.coverage.limitations)
    # Only the FIRST descriptor's own entry is ever appended -- the cycle
    # is detected at the SECOND descriptor's first thunk address, before
    # any entry for it is produced, and the walk stops immediately.
    assert result.records[0].iat.entry_count == 1


def test_iat_bounds_exceeded_when_descriptor_found_past_declared_capacity():
    """The Import Directory's own declared Size only has room for ONE
    descriptor, but a SECOND real (non-terminator) descriptor is found at
    that offset -- reading even one byte past the header's own declared
    capacity would mean reading memory the Import Directory never claimed
    as its own, so the walk refuses to even attempt it (§39)."""
    import_dir_rva = 0x2000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 20), 12: (0, 0)})   # room for 1 descriptor
    descr = _descriptor(0, 1, 0)   # real (non-terminator): Name=1; no thunk walk (FirstThunk=0)
    memory = {
        IMAGE_BASE: header,
        # Two real descriptors present in the dump, but the header only
        # declares room for one.
        IMAGE_BASE + import_dir_rva: descr + descr,
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert any(lim.code == LimitationCode.IAT_BOUNDS_EXCEEDED for lim in result.coverage.limitations)
    assert any(lim.code == LimitationCode.IAT_UNTERMINATED_TABLE for lim in result.coverage.limitations)
    # Only the in-capacity descriptor was ever read.
    assert result.records[0].iat.dll_count == 1


def test_iat_table_present_true_with_overflowed_address_does_not_crash_the_record():
    """A normalized image base large enough that the IAT Directory's own
    declared RVA overflows a real 64-bit address when added to it
    (bounds_exceeded, dumpex.core.pe_utils's own `_addr()` guard) --
    table_present resolves True (the RVA is declared and nonzero) even
    though table_va/table_size themselves stay None. The whole pipeline,
    including IatRecord construction (whose own constructor invariants
    must tolerate this exact combination -- see test_output_records.py's
    test_iat_record_allows_table_present_true_with_both_null), must not
    raise, and the real import entry recovered from the import walk's own
    (non-overflowing) RVAs must still be reported."""
    huge_base = 0xFFFFFFFFFFFF0000   # matches tests/unit/test_iat_parser.py's own fixture:
                                       # leaves headroom for the import walk's small RVAs,
                                       # not enough for the IAT directory's own huge RVA below
    import_dir_rva = 0x1000
    int_rva, name_rva, first_thunk_rva = 0x1100, 0x1200, 0x1300

    header = build_pe_header([TEXT_SECTION_RX], image_base=huge_base, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (0xFFFFFFFF, 0x100)})
    descr = _descriptor(int_rva, name_rva, first_thunk_rva)
    memory = {
        huge_base: header,
        huge_base + import_dir_rva: descr + _TERMINATOR,
        huge_base + name_rva: _cstr("A.dll"),
        huge_base + int_rva: _thunk64(0x8000000000000001) + _thunk64(0),   # ordinal import
        huge_base + first_thunk_rva: _thunk64(0x999) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(huge_base, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)   # must not raise
    record = result.records[0]
    assert record.iat.table_present is True
    assert record.iat.table_va is None
    assert record.iat.table_size is None
    assert record.iat.entry_count == 1


# ── §8.3 item 6b: determined vs. undetermined import-directory presence ─

def test_determined_no_imports_console_text_survives_an_unrelated_iat_directory_gap():
    """index 1 (import directory) IS captured with RVA=0 -- a DETERMINED
    'this image declares no imports' claim -- while index 12 (IAT
    directory) is never captured at all. The determined claim must not
    be revoked by the unrelated, narrower index-12 gap: console still
    prints the 'declares no imports' text, while IAT_DIRECTORY_TABLE_
    INCOMPLETE independently drives coverage to partial/exit 3 for the
    index-12 gap alone (§3.5.2's outcome table, §8.3 item 6b second
    bullet)."""
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (0, 0)})   # captured, RVA=0 -> determined false
    header = _truncate_directory_table(header, entries_captured=6)   # index 12 never captured
    memory = {IMAGE_BASE: header}
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert exit_code_for(result.coverage.status.value) == 3
    incomplete = next(lim for lim in result.coverage.limitations
                       if lim.code == LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE)
    assert incomplete.affected_count == 10   # 16 declared - 6 captured

    record = result.records[0]
    assert record.iat.import_directory_present is False
    assert record.iat.table_present is None
    assert record.iat.entries == ()

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    out = buf.getvalue()
    assert "(none -- this image declares no imports)" in out
    assert "(unavailable -- see coverage below)" not in out


def test_undetermined_import_directory_never_prints_declares_no_imports():
    """index 1 is NEVER captured at all (only 0 of 16 declared entries
    present) -- import_directory_present is undetermined (null), which
    must NEVER be reported as the positive 'declares no imports' claim."""
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (0x9000, 20)})
    header = _truncate_directory_table(header, entries_captured=0)
    memory = {IMAGE_BASE: header}
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    record = result.records[0]
    assert record.iat.import_directory_present is None
    incomplete = next(lim for lim in result.coverage.limitations
                       if lim.code == LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE)
    assert incomplete.affected_count == 16

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    out = buf.getvalue()
    assert "(unavailable -- see coverage below)" in out
    assert "declares no imports" not in out


# ── P3: renderer takes no `mf` -- structurally cannot re-read evidence ──

def test_render_process_console_has_no_way_in_for_the_dump():
    """No parameter names the dump, and no `*args`/`**kwargs` catch-all
    could smuggle one in. The exact parameter list is deliberately NOT
    pinned: adding a rendering option is not a regression, and asserting
    the full list only fires on renames while staying green for real
    breaks."""
    import inspect
    signature = inspect.signature(render_process_console)
    assert not ({"mf", "minidump", "dump", "reader"} & set(signature.parameters))
    catch_alls = [name for name, p in signature.parameters.items()
                  if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)]
    assert catch_alls == []


def test_render_process_console_output_survives_the_dump_being_gutted():
    """The behavioural half: a record rendered after the dump object it
    came from has been destroyed is byte-identical to one rendered while
    the dump was intact. An implementation that reached back for evidence
    -- through a captured reference, a closure or a record attribute --
    would change its output or raise here, whatever its signature says.
    """
    mf = _complete_mf()
    result = collect_process(mf)
    record = result.records[0]

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    before = buf.getvalue()

    def _tripwire(*args, **kwargs):
        raise AssertionError("render_process_console() re-read the dump")

    mf.misc_info = None
    mf.peb = None
    mf.modules = None
    mf.memory_segments_64 = None
    mf.memory_segments = None
    mf._dumpex_stream_failures = {}
    mf.get_reader = _tripwire

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    assert buf.getvalue() == before


# ── P3: MiscInfo absent -> pid stays null, never substituted from a TID ─

def test_pid_never_substituted_from_thread_or_exception_stream():
    """#40's scope explicitly does not carry --pid's legacy thread-list/
    exception-TID fallback -- pid must stay null even when the dump
    otherwise has plenty of thread/exception evidence to fall back to."""
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(peb=peb)   # misc_info absent entirely; PID has no source at all
    # Tempting fallback data a legacy --pid thread-list/exception-TID
    # fallback would have used -- present specifically to prove it is
    # ignored, not merely absent-by-omission.
    mf.threads = FakeStream([Thread(4321, Ctx(0x1000))], "threads")
    mf.exception = ExceptionStream(9999)
    result = collect_process(mf)
    assert result.records[0].pid is None
    assert result.records[0].identity_evidence["misc_info_claim"]["pid"] is None


# ── P3: module name conflict at the command layer ─────────────────────────

def test_module_name_conflict_diagnostic_reaches_the_record():
    """§37's PROCESS_MODULE_IDENTITY_MISMATCH: the PEB image path's own
    basename disagrees with the module resolved at the exact same base."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\a.exe")
    mod = Module(IMAGE_BASE, 0x6000, r"C:\Samples\other.exe")   # same base, different name
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.COMPLETE
    codes = [d["code"] for d in result.records[0].identity_evidence["diagnostics"]]
    assert "PROCESS_MODULE_IDENTITY_MISMATCH" in codes


# ── P3: peb_extended is positively populated, not just null-checked ─────

def test_peb_extended_positive_fill_under_verbose():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe", address=0x7ff0000,
              being_debugged=True, window_title="cmd.exe", dll_path=r"C:\a.dll",
              standard_input=0x10, standard_output=0x14, standard_error=0x18)
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf, verbose=True)
    ext = result.records[0].peb_extended
    assert ext["peb_address"] == "0x0000000007ff0000"
    assert ext["being_debugged"] is True
    assert ext["window_title"] == "cmd.exe"
    assert ext["dll_path"] == r"C:\a.dll"
    assert ext["standard_input"] == "0x0000000000000010"
    assert ext["standard_output"] == "0x0000000000000014"
    assert ext["standard_error"] == "0x0000000000000018"


# ── Main image invalid PE / read failure ─────────────────────────────────

def test_main_image_invalid_pe_suppresses_iat_walk():
    """A FULLY captured (the whole MAIN_IMAGE_PE_READ_MAX budget) but
    structurally invalid header -- e_lfanew points implausibly far past
    the captured 4096 bytes -- is a genuine structural defect, not a
    capture-length gap, so this must classify as PE_INVALID, not
    SHORT_READ."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    data = bytearray(4096)
    data[0:2] = b"MZ"
    struct.pack_into('<I', data, 0x3C, 0x2000)   # e_lfanew way past plausible range
    memory = {IMAGE_BASE: bytes(data)}
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    assert result.coverage.status == CoverageStatus.PARTIAL
    assert exit_code_for(result.coverage.status.value) == 3
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ not in codes
    assert LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE not in codes

    record = result.records[0]
    assert record.iat.table_present is None
    assert record.iat.entries == ()
    assert record.identity_evidence["main_image_pe"]["checked"] is True
    assert record.identity_evidence["main_image_pe"]["valid"] is False


# ── §3.4.4 short-capture vs. structurally-invalid classification ────────
# (P2 fix: a short capture must never be misreported as a structural
# defect just because parse_pe_header()'s free-text `reason` happens not
# to contain the word "truncated".)

def test_main_image_non_mz_short_capture_is_pe_invalid_not_short_read():
    """72 bytes captured, well under the 4096-byte budget, but data[:2]
    != b'MZ' with len(data) already >= 0x40 -- this is a DETERMINISTIC
    rejection (parse_pe_header()'s own insufficient_data=False for this
    exact case), not a capture-length gap: more bytes would not change
    the verdict. This is the classification the P2 fix corrects -- a
    prior version of the short-capture heuristic (bare `captured_bytes <
    budget`) mistook this for SHORT_READ, suppressing a genuine
    hollowing/header-stomping signal (no PE at the PEB-reported base at
    all) as a mere collection gap."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    memory = {IMAGE_BASE: b"NOTAPE\x00\x00" + b"\x00" * 64}   # 72 bytes total, well under 4096
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ not in codes
    # PE_INVALID suppresses the IAT walk entirely (§3.7.2) -- no
    # self-contradictory "data directory table not captured" limitation
    # for an image that was never a PE header to begin with.
    assert LimitationCode.IAT_DIRECTORY_TABLE_INCOMPLETE not in codes


def test_main_image_short_capture_truncated_dos_header_is_short_read():
    """A plausible e_lfanew whose own 24-byte COFF-header window runs past
    a PARTIAL capture -> parse_pe_header()'s own insufficient_data=True
    for this exact case (more bytes WOULD change the verdict) -- must
    classify as SHORT_READ because the capture itself (256 bytes) is
    short of the full budget."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    data = bytearray(256)
    data[0:2] = b"MZ"
    struct.pack_into('<I', data, 0x3C, 0x300)   # e_lfanew + 24 > len(data), but a plausible offset
    memory = {IMAGE_BASE: bytes(data)}
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID not in codes


def test_main_image_bad_machine_at_partial_capture_is_pe_invalid():
    """A fully legal MZ/PE/COFF header up through the Machine field, with
    an UNRECOGNIZED Machine value, captured well short of the 4096-byte
    budget (512 bytes) -- insufficient_data=False (the Machine field
    itself is fully present and simply wrong), so this must be PE_INVALID
    even though the capture itself is short. A bare `captured_bytes <
    budget` heuristic would misclassify this as SHORT_READ."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    header = build_pe_header([TEXT_SECTION_RX], machine=0xDEAD, size_of_image=0x6000)
    memory = {IMAGE_BASE: header[:512]}   # far short of MAIN_IMAGE_PE_READ_MAX (4096)
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ not in codes


# ── Regression: dumpex's OWN read budget must never masquerade as a
# structural defect (a prior version of the fix conjoined `insufficient_
# data` with `captured_bytes < MAIN_IMAGE_PE_READ_MAX`, misclassifying a
# fully-present-in-the-dump header that is merely LARGER than the 4096
# -byte budget as PE_INVALID and silently dropping its entire IAT walk) ─

def test_main_image_section_table_beyond_budget_is_short_read_and_recovers_imports():
    """A structurally valid, fully-present-in-the-dump header whose
    section table needs MORE than MAIN_IMAGE_PE_READ_MAX (4096) bytes to
    finish (96 sections -- the PE spec's own cap) -- captured_bytes ends
    up EXACTLY 4096 (dumpex's own budget, not a fact about the image).
    Must classify as SHORT_READ, never PE_INVALID, and the IAT walk must
    still run and recover the image's real imports."""
    sections = [dict(TEXT_SECTION_RX) for _ in range(96)]
    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    dll_name_rva = 0x4000
    int_rva = 0x5000
    name_hint_rva = 0x6000

    header = build_pe_header(sections, image_base=IMAGE_BASE, size_of_image=0x60000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 16)})
    assert len(header) > 4096   # sanity: the fixture actually exceeds the budget
    descr = _descriptor(int_rva, dll_name_rva, iat_dir_rva)

    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + dll_name_rva: _cstr("KERNEL32.dll"),
        IMAGE_BASE + int_rva: _thunk64(name_hint_rva) + _thunk64(0),
        IMAGE_BASE + name_hint_rva: _hint_name("CreateFileW"),
        IMAGE_BASE + iat_dir_rva: _thunk64(0x00007ffb12345678) + _thunk64(0),
    }
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID not in codes

    record = result.records[0]
    assert record.iat.entries != ()
    entry = record.iat.entries[0]
    assert entry.dll == "KERNEL32.dll"
    assert entry.symbol == "CreateFileW"


def test_main_image_e_lfanew_near_boundary_at_full_capture_is_short_read():
    """A plausible e_lfanew (<= 0x1000) whose own 24-byte window runs past
    a FULLY-BUDGETED capture (captured_bytes == MAIN_IMAGE_PE_READ_MAX
    exactly) -- still a genuine capture-length gap (insufficient_data is
    structural, not tied to which budget stopped the read), so this must
    stay SHORT_READ even at the full 4096-byte budget."""
    data = bytearray(4096)
    data[0:2] = b"MZ"
    struct.pack_into('<I', data, 0x3C, 0xFF0)   # plausible, but 0xFF0 + 24 > 4096
    memory = {IMAGE_BASE: bytes(data)}
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_SHORT_READ in codes
    assert LimitationCode.PROCESS_MAIN_IMAGE_PE_INVALID not in codes


def test_main_image_read_failed_when_nothing_captured_at_base():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory={})   # image base normalizes, nothing captured there

    result = collect_process(mf)
    codes = [lim.code for lim in result.coverage.limitations]
    assert LimitationCode.PROCESS_MAIN_IMAGE_READ_FAILED in codes
    assert result.records[0].identity_evidence["main_image_pe"]["checked"] is False
    assert result.records[0].identity_evidence["main_image_pe"]["valid"] is None


# ── Console branch selection ──────────────────────────────────────────────

def test_console_unavailable_branch_when_import_directory_undetermined():
    """A short header capture that never reaches the data-directory count
    field at all leaves import_directory_present undetermined -- console
    must print the generic unavailable text, never the false-positive
    'declares no imports' text."""
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    truncated = header[:0x60]   # cuts off well before NumberOfRvaAndSizes
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory={IMAGE_BASE: truncated})

    result = collect_process(mf)
    record = result.records[0]
    assert record.iat.import_directory_present is None

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, result.coverage)
    out = buf.getvalue()
    assert "(unavailable -- see coverage below)" in out
    assert "declares no imports" not in out


# ── cmd_process wiring ────────────────────────────────────────────────────

def test_cmd_process_collects_and_renders():
    mf = _complete_mf()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = cmd_process(mf)
    assert "PROCESS" in buf.getvalue()
    assert result.records[0].pid == 4242


# ── Collector purity ──────────────────────────────────────────────────────

def test_collect_process_does_not_mutate_mf():
    mf = _complete_mf()
    misc_before = mf.misc_info
    peb_before = mf.peb
    modules_before = mf.modules
    collect_process(mf)
    assert mf.misc_info is misc_before
    assert mf.peb is peb_before
    assert mf.modules is modules_before


def test_collect_process_is_deterministic_across_calls():
    mf = _complete_mf()
    first = collect_process(mf).records[0].to_dict()
    second = collect_process(mf).records[0].to_dict()
    assert first == second


# ── #98 console-projection helpers ──────────────────────────────────────
# These build a ProcessRecord DIRECTLY rather than going through a fake
# dump, for the cases whose whole point is a rendering decision over a
# particular identity_evidence shape (an unregistered base with an
# ambiguous name candidate, a PE header that was never checked, a
# hostile string in one specific field). Driving those from dump bytes
# would need a fixture per case and would still only reach the renderer
# through the same record.


def _rendered(result, *, verbose=False) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(result.records[0], result.coverage, verbose=verbose)
    return buf.getvalue()


def _rendered_record(record, *, verbose=False) -> str:
    coverage = build_coverage_report({"process_identity": SourceObservation(
        name="process_identity", state=SourceState.PRESENT, record_count=1)})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(record, coverage, verbose=verbose)
    return buf.getvalue()


def _identity_evidence(*, peb_path=r"C:\Samples\malware.exe", peb_name="malware.exe",
                       module_path=r"C:\Samples\malware.exe", module_name="malware.exe",
                       match_state="resolved", ambiguous=False, candidate=None,
                       main_image_pe=None, selected_path_source="peb") -> dict:
    return {
        "misc_info_claim": {"pid": 4242, "process_create_time_utc": None,
                            "raw_pid": 4242, "raw_process_create_time": None},
        "peb_claim": {"image_base_address": "0x00007ff600010000", "image_path": peb_path,
                      "name": peb_name, "raw_image_base_address": None,
                      "raw_image_path": None, "raw_command_line": None},
        "module_claim": {"match_state": match_state,
                         "base_address": ("0x00007ff600010000"
                                          if match_state == "resolved" else None),
                         "name": module_name, "path": module_path,
                         "name_matched_candidate": candidate,
                         "name_matched_candidate_ambiguous": ambiguous},
        "main_image_pe": main_image_pe or {"checked": True, "valid": True, "reason": None},
        "selected_path_source": selected_path_source,
        "diagnostics": [],
    }


def _process_record(*, entries=(), identity_evidence=None, peb_extended=None,
                    process_path=r"C:\Samples\malware.exe", process_name="malware.exe"):
    iat = records_module.IatRecord(
        table_present=bool(entries),
        table_va="0x00007ff600021000" if entries else None,
        table_size=(8 * len(entries)) or None,
        import_directory_present=bool(entries),
        import_directory_va="0x00007ff600020000" if entries else None,
        import_directory_size=40 if entries else None, has_entries=bool(entries),
        dll_count=len({e.dll for e in entries}) if entries else 0,
        entry_count=len(entries), entries=tuple(entries), diagnostics=())
    return records_module.ProcessRecord(
        process_name=process_name, pid=4242, process_path=process_path,
        command_line=r'"C:\Samples\malware.exe" -k',
        process_start_utc="2026-08-14 01:15:05 UTC",
        image_base_address="0x00007ff600010000", iat=iat,
        identity_evidence=identity_evidence or _identity_evidence(),
        peb_extended=peb_extended)


def _process_record_with_entries(entries):
    return _process_record(entries=entries)


def _identity_record(*, peb_name, module_name, match_state, ambiguous=False,
                     main_image_pe=None):
    candidate = None
    if match_state == "unregistered" and ambiguous:
        candidate = {"base_address": "0x00007ff700000000", "name": peb_name,
                     "path": r"C:\Windows\Temp\%s" % peb_name}
    return _process_record(identity_evidence=_identity_evidence(
        peb_name=peb_name, module_name=module_name, match_state=match_state,
        ambiguous=ambiguous, candidate=candidate, main_image_pe=main_image_pe))


def _empty_peb_extended(**overrides) -> dict:
    base = {"peb_address": "0x0000000000001000", "being_debugged": False,
            "window_title": None, "dll_path": None, "standard_input": None,
            "standard_output": None, "standard_error": None}
    base.update(overrides)
    return base


def _hostile_verbose_record(field: str, hostile: str):
    """One record with `hostile` planted in exactly one dump-derived
    field, so a passing case names the field that is actually escaped
    rather than averaging several together."""
    identity_kwargs = {}
    peb_extended = _empty_peb_extended()
    entry_kwargs = {"dll": "KERNEL32.dll", "import_by": "name", "symbol": "CreateFileW",
                    "ordinal": None, "iat_slot_va": "0x00007ff600021018",
                    "resolved_target_va": "0x00007ffb12345678", "slot_in_bounds": True}
    if field == "peb_path":
        identity_kwargs["peb_path"] = hostile
    elif field == "peb_name":
        identity_kwargs["peb_name"] = hostile
        identity_kwargs["module_name"] = "malware.exe"
    elif field == "module_path":
        identity_kwargs["module_path"] = hostile
    elif field == "module_name":
        identity_kwargs["module_name"] = hostile
    elif field == "pe_reason":
        identity_kwargs["main_image_pe"] = {"checked": True, "valid": False,
                                            "reason": hostile}
    elif field == "window_title":
        peb_extended = _empty_peb_extended(window_title=hostile)
    elif field == "dll_path":
        peb_extended = _empty_peb_extended(dll_path=hostile)
    elif field in ("dll", "symbol"):
        entry_kwargs[field] = hostile
    else:                                        # pragma: no cover -- guard
        raise AssertionError(f"unknown field {field!r}")

    entry = records_module.ImportEntryRecord(**entry_kwargs)
    record = _process_record(entries=[entry],
                             identity_evidence=_identity_evidence(**identity_kwargs),
                             peb_extended=peb_extended)
    # The record layer must keep the exact decoded value -- escaping is a
    # console projection, and --json is where evidence is read.
    if field in ("dll", "symbol"):
        assert getattr(record.iat.entries[0], field) == hostile
    return record


# ── --verbose rendering ────────────────────────────────────────────────

def test_verbose_console_prints_iat_table_identity_checks_and_extended_peb():
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)
    assert "KERNEL32.dll" in out
    assert "CreateFileW" in out
    assert "Identity Verification" in out
    assert "Extended PEB" in out
    assert "[OK] a valid PE header was found at the PEB image base" in out


# ── #98: the verbose IAT table explains its own address pair ────────────

def test_verbose_iat_table_has_headers_for_all_four_columns():
    """The pre-#98 rendering was `<address> -> <address>` with no header
    and no legend, so which of the two was the slot and which the target
    was only recoverable from the source."""
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)

    header = next(l for l in out.splitlines() if "IAT Slot VA" in l and "DLL" in l)
    for column in ("DLL", "Imported API", "IAT Slot VA", "Resolved Target VA"):
        assert column in header
    assert header.index("DLL") < header.index("Imported API") < \
           header.index("IAT Slot VA") < header.index("Resolved Target VA")


def test_verbose_iat_legend_states_which_address_is_which():
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    out = " ".join(_rendered(result, verbose=True).split())

    assert "IAT Slot VA -> Resolved Target VA" in out
    assert "the slot is the address where the import pointer is stored" in out.lower()
    assert "the target is the address stored in that slot" in out.lower()


def test_verbose_iat_row_keeps_the_slot_and_target_in_their_own_columns():
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    entry = result.records[0].iat.entries[0]
    out = _rendered(result, verbose=True)

    row = next(l for l in out.splitlines() if entry.iat_slot_va in l and "KERNEL32" in l)
    tokens = row.split()
    assert tokens.index(entry.iat_slot_va) < tokens.index(entry.resolved_target_va)
    # The addresses are two independent tokens, never fused by a column
    # that ran out of width.
    assert f"{entry.iat_slot_va}{entry.resolved_target_va}" not in row


def test_verbose_iat_marks_an_out_of_bounds_slot_without_calling_it_a_verdict():
    """`slot_in_bounds is False` is an observation (§3.5.5 files it as a
    diagnostic, never a limitation). It must be visible in the table, and
    it must not read as a hooking verdict or a coverage failure."""
    entry = records_module.ImportEntryRecord(
        dll="KERNEL32.dll", import_by="name", symbol="CreateFileW", ordinal=None,
        iat_slot_va="0x00007ff600021018", resolved_target_va="0x00007ffb12345678",
        slot_in_bounds=False)
    in_bounds = dataclasses.replace(entry, symbol="CloseHandle", slot_in_bounds=True)
    record = _process_record_with_entries([entry, in_bounds])

    out = _rendered_record(record, verbose=True)
    marked = next(l for l in out.splitlines() if "CreateFileW" in l)
    unmarked = next(l for l in out.splitlines() if "CloseHandle" in l)
    assert marked.rstrip().endswith("*")
    assert not unmarked.rstrip().endswith("*")
    assert "outside the recorded import directory bounds" in " ".join(out.split())
    for verdict in ("hook", "malicious", "suspicious", "tamper"):
        assert verdict not in out.lower()


def test_verbose_iat_footnote_is_absent_when_every_slot_is_in_bounds():
    record = _process_record_with_entries([records_module.ImportEntryRecord(
        dll="KERNEL32.dll", import_by="name", symbol="CloseHandle", ordinal=None,
        iat_slot_va="0x00007ff600021018", resolved_target_va="0x00007ffb12345678",
        slot_in_bounds=True)])
    out = _rendered_record(record, verbose=True)
    assert "outside the recorded import directory" not in out
    assert "*" not in out


# ── #98: Identity Verification replaces the Evidence Matrix ─────────────

def test_identity_block_shows_the_selected_value_not_the_source_name():
    """The old matrix printed "peb" in a column headed `Selected`, i.e. a
    SOURCE NAME where a reader expects the selected VALUE."""
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)

    selected = next(l for l in out.splitlines() if "Selected path" in l)
    assert r"C:\Samples\malware.exe" in selected
    assert selected.split()[2] != "peb"
    source = next(l for l in out.splitlines() if l.strip().startswith("Source"))
    assert "PEB" in source


def test_identity_block_states_each_check_as_a_conclusion():
    mf = _complete_mf()
    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)

    assert "[OK] PEB image base is registered in ModuleList" in out
    assert "[OK] PEB and ModuleList process names agree" in out
    assert "[OK] a valid PE header was found at the PEB image base" in out
    assert "[OK] no competing module shares this process name" in out
    # The internal claim vocabulary is no longer the LEAD, but the raw
    # per-source claims stay available underneath.
    assert "Raw claims" in out
    assert "(resolved)" in out


def test_identity_block_renders_an_unregistered_base_as_a_conflict_not_a_verdict():
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\Samples\malware.exe")
    other_base = 0x00007ff700000000
    mod = Module(other_base, 0x6000, r"C:\Windows\Temp\malware.exe")
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=_build_valid_image_no_imports())

    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)

    assert "[!!] no module is registered at the PEB image base" in out
    assert "0x00007ff700000000" in out          # the competing registration
    # An identity conflict is an observation: it never becomes a verdict,
    # a trust boolean, or a coverage/exit-code change.
    assert "peb_trusted" not in out
    for verdict in ("malicious", "injected", "hollowed"):
        assert verdict not in out.lower()
    assert result.coverage.status == collect_process(mf).coverage.status


def test_identity_block_reports_unavailable_checks_as_unavailable():
    """Absent ModuleListStream: every ModuleList-dependent check has to
    read as "could not be evaluated", never as agreement and never as a
    conflict."""
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\Samples\malware.exe")
    mf = _mf(misc_info=misc, peb=peb, memory=_build_valid_image_no_imports())

    result = collect_process(mf, verbose=True)
    out = _rendered(result, verbose=True)

    assert "[--] PEB image base could not be compared with ModuleList" in out
    assert "[--] PEB and ModuleList process names could not be compared" in out
    assert "PEB and ModuleList process names agree" not in out


def test_identity_name_agreement_ignores_case_only_differences():
    """Windows module and file names are case-insensitive, so a case
    difference alone must not be reported to an analyst as a conflict."""
    record = _identity_record(peb_name="Malware.exe", module_name="malware.exe",
                              match_state="resolved")
    out = _rendered_record(record, verbose=True)
    assert "[OK] PEB and ModuleList process names agree" in out


def test_identity_name_disagreement_shows_both_values():
    record = _identity_record(peb_name="malware.exe", module_name="svchost.exe",
                              match_state="resolved")
    out = _rendered_record(record, verbose=True)
    assert "[!!] PEB and ModuleList process names differ" in out
    assert "malware.exe" in out and "svchost.exe" in out


def test_identity_block_reports_an_ambiguous_name_candidate():
    record = _identity_record(peb_name="malware.exe", module_name=None,
                              match_state="unregistered", ambiguous=True)
    out = _rendered_record(record, verbose=True)
    assert "[!!] more than one module shares this process name" in out


def test_identity_block_reports_an_invalid_pe_header_with_its_reason():
    record = _identity_record(peb_name="malware.exe", module_name="malware.exe",
                              match_state="resolved",
                              main_image_pe={"checked": True, "valid": False,
                                             "reason": "no PE\0\0 signature at e_lfanew"})
    out = _rendered_record(record, verbose=True)
    assert "[!!] no valid PE header at the PEB image base" in out
    assert "e_lfanew" in out


def test_identity_block_reports_an_unchecked_pe_header_as_unavailable():
    record = _identity_record(peb_name="malware.exe", module_name="malware.exe",
                              match_state="resolved",
                              main_image_pe={"checked": False, "valid": None, "reason": None})
    out = _rendered_record(record, verbose=True)
    assert "[--] the PEB image base was not checked for a PE header" in out


# ── #98: every dump-derived verbose string is console-escaped ───────────

@pytest.mark.parametrize("hostile,escaped", [
    ("evil\n  [~] forged coverage reason", "\\x0a"),
    ("evil\x1b[2Jcleared", "\\x1b"),
    ("user\u202egnp.exe", "\\u202e"),
])
@pytest.mark.parametrize("field", ["peb_path", "peb_name", "module_path", "module_name",
                                   "pe_reason", "window_title", "dll_path", "dll", "symbol"])
def test_verbose_process_strings_cannot_drive_the_terminal(field, hostile, escaped):
    """Newline/ANSI/bidi regression coverage for every dump-derived
    string the verbose renderer prints -- the identity block's paths and
    names, the PE rejection reason, the Extended PEB window title and DLL
    path, and the import table's DLL/API names."""
    record = _hostile_verbose_record(field, hostile)
    out = _rendered_record(record, verbose=True)

    assert hostile not in out               # never verbatim
    assert escaped in out                   # rendered visibly instead
    assert not any(line.strip().startswith("[~] forged") for line in out.splitlines())


def test_verbose_console_renders_ordinal_and_unavailable_import_entries():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")

    import_dir_rva = 0x2000
    iat_dir_rva = 0x3000
    header = build_pe_header([TEXT_SECTION_RX], image_base=IMAGE_BASE, size_of_image=0x6000)
    header = _patch_data_directories(header, {1: (import_dir_rva, 40), 12: (iat_dir_rva, 8)})
    # OriginalFirstThunk == 0 -> import_by "unavailable": the loader has
    # already overwritten FirstThunk, so name/ordinal is unrecoverable.
    descr = _descriptor(0, 0, iat_dir_rva)
    memory = {
        IMAGE_BASE: header,
        IMAGE_BASE + import_dir_rva: descr + _TERMINATOR,
        IMAGE_BASE + iat_dir_rva: _thunk64(0x00007ffb00000001) + _thunk64(0),
    }
    mf = _mf(misc_info=misc, peb=peb, memory=memory)

    result = collect_process(mf, verbose=True)
    entry = result.records[0].iat.entries[0]
    assert entry.import_by == "unavailable"

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(result.records[0], result.coverage, verbose=True)
    assert "(unavailable)" in buf.getvalue()


def test_verbose_extended_peb_all_null_when_peb_absent():
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    mf = _mf(misc_info=misc)   # no PEB at all
    result = collect_process(mf, verbose=True)
    assert result.records[0].peb_extended == {
        "peb_address": None, "being_debugged": None, "window_title": None,
        "dll_path": None, "standard_input": None, "standard_output": None,
        "standard_error": None,
    }


def test_non_verbose_console_omits_verbose_only_sections():
    mf = _complete_mf()
    result = collect_process(mf, verbose=False)
    assert result.records[0].peb_extended is None
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(result.records[0], result.coverage, verbose=False)
    out = buf.getvalue()
    assert "Evidence Matrix" not in out
    assert "Extended PEB" not in out


def test_diagnostic_severity_prefixes_in_console():
    """PROCESS_MODULE_BASE_CONFLICT is severity=warning -> '[!]'."""
    misc = MiscInfo(process_id=4242, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\Samples\malware.exe", command_line=r"C:\Samples\malware.exe")
    other_base = 0x00007ff700000000
    mod = Module(other_base, 0x6000, r"C:\Windows\Temp\malware.exe")
    memory = _build_valid_image_no_imports()
    mf = _mf(misc_info=misc, peb=peb, modules=[mod], memory=memory)

    result = collect_process(mf)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        render_process_console(result.records[0], result.coverage)
    assert "[!]" in buf.getvalue()


# ── main image: read raises despite the segment table reporting bytes ───

def test_main_image_read_failed_when_reader_raises_mid_read():
    """va_range_captured_bytes() and the low-level buffered reader can, in
    principle, disagree (e.g. a corrupted reader state) -- collect_process
    must treat that as READ_FAILED, never propagate the exception."""
    misc = MiscInfo(process_id=100, process_create_time=1786670105)
    peb = Peb(IMAGE_BASE, r"C:\a.exe", command_line=r"C:\a.exe")
    mf = _mf(misc_info=misc, peb=peb, memory={IMAGE_BASE: b"MZ" + b"\x00" * 100})

    class _RaisingReader:
        def get_buffered_reader(self):
            raise Exception("boom")

    mf.get_reader = lambda: _RaisingReader()
    result = collect_process(mf)
    assert any(lim.code == LimitationCode.PROCESS_MAIN_IMAGE_READ_FAILED
               for lim in result.coverage.limitations)
