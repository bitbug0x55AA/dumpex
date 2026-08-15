"""Unit tests for dumpex.core.process_info -- issue #37 contract §3.2
(normalization), §3.3.3 (resolve_module_by_base), and §4.2
(walk_environment_block).

Every normalizer test asserts the SAME "structurally present but
rejected" pattern the contract requires: a rejected value must not be
silently promoted (a normalizer either returns the value untouched, or
None -- never a coerced/truncated substitute), and coverage-worthy
rejection is derived from the normalized result, not raw truthiness.
"""
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from tests.fixtures.fakes import (
    Module, FakeMF, SysInfo, Thread, Ctx, FakeStream, wire_environment_walk,
)

from dumpex.core.process_info import (
    normalize_pid, classify_process_create_time, normalize_windows_path,
    normalize_command_line, normalize_image_base, resolve_module_by_base,
    walk_environment_block, MAX_ENV_BYTES, MAX_ENV_ENTRIES,
)
import dumpex.core.process_info as process_info


# ── normalize_pid ────────────────────────────────────────────────────────

def test_normalize_pid_accepts_ordinary_value():
    assert normalize_pid(4242) == 4242


def test_normalize_pid_rejects_zero():
    # The library's unset value, not a dumpable process.
    assert normalize_pid(0) is None


def test_normalize_pid_rejects_negative():
    assert normalize_pid(-1) is None


def test_normalize_pid_rejects_out_of_uint32_range():
    assert normalize_pid(0x1_0000_0000) is None


def test_normalize_pid_accepts_uint32_max():
    assert normalize_pid(0xFFFFFFFF) == 0xFFFFFFFF


def test_normalize_pid_rejects_bool():
    # bool is a subclass of int -- a stray True/False must never
    # normalize to 1/0.
    assert normalize_pid(True) is None
    assert normalize_pid(False) is None


def test_normalize_pid_rejects_non_int():
    assert normalize_pid("4242") is None
    assert normalize_pid(None) is None
    assert normalize_pid(42.0) is None


# ── classify_process_create_time ─────────────────────────────────────────

def test_classify_process_create_time_ok():
    assert classify_process_create_time(1755130505) == "ok"


def test_classify_process_create_time_unset_is_zero():
    assert classify_process_create_time(0) == "unset"


def test_classify_process_create_time_invalid_out_of_uint32_range():
    assert classify_process_create_time(0x1_0000_0000) == "invalid"


def test_classify_process_create_time_invalid_negative():
    assert classify_process_create_time(-1) == "invalid"


def test_classify_process_create_time_invalid_non_int():
    assert classify_process_create_time("not-an-int") == "invalid"
    assert classify_process_create_time(None) == "invalid"


def test_classify_process_create_time_invalid_bool():
    assert classify_process_create_time(True) == "invalid"


# ── normalize_windows_path / normalize_command_line ─────────────────────

def test_normalize_windows_path_keeps_real_value():
    assert normalize_windows_path(r"C:\Samples\malware.exe") == r"C:\Samples\malware.exe"


def test_normalize_windows_path_strips_trailing_nuls_and_whitespace():
    assert normalize_windows_path(r"C:\Samples\malware.exe\x00".replace("\\x00", "\x00")) \
        == r"C:\Samples\malware.exe"
    assert normalize_windows_path("  C:\\a.exe  ") == "C:\\a.exe"


def test_normalize_windows_path_empty_or_whitespace_becomes_none():
    assert normalize_windows_path("") is None
    assert normalize_windows_path("   ") is None
    assert normalize_windows_path("\x00\x00") is None


def test_normalize_windows_path_non_string_becomes_none():
    assert normalize_windows_path(None) is None
    assert normalize_windows_path(1234) is None


def test_normalize_windows_path_never_lowercases_or_rewrites_separators():
    assert normalize_windows_path(r"C:\SAMPLES\Malware.EXE") == r"C:\SAMPLES\Malware.EXE"


def test_normalize_command_line_same_rules_as_path():
    assert normalize_command_line('"C:\\Samples\\malware.exe" -k') == '"C:\\Samples\\malware.exe" -k'
    assert normalize_command_line("") is None
    assert normalize_command_line("\x00") is None
    assert normalize_command_line(None) is None


# ── normalize_image_base ─────────────────────────────────────────────────

def test_normalize_image_base_accepts_aligned_value():
    assert normalize_image_base(0x00007ff600010000) == 0x00007ff600010000


def test_normalize_image_base_rejects_unaligned_value():
    assert normalize_image_base(0x00007ff600010abc) is None


def test_normalize_image_base_rejects_zero():
    assert normalize_image_base(0) is None


def test_normalize_image_base_rejects_negative():
    assert normalize_image_base(-0x1000) is None


def test_normalize_image_base_rejects_bool():
    assert normalize_image_base(True) is None


def test_normalize_image_base_rejects_non_int():
    assert normalize_image_base("0x1000") is None


def test_normalize_image_base_rejects_beyond_uint64():
    assert normalize_image_base(0x1_0000_0000_0000_0000) is None


# ── resolve_module_by_base ────────────────────────────────────────────────

def test_resolve_module_by_base_exact_match():
    modules = [Module(0x140000000, 0x1000, "a.dll"), Module(0x150000000, 0x2000, "malware.exe")]
    found = resolve_module_by_base(0x150000000, modules)
    assert found is not None
    assert found.name == "malware.exe"


def test_resolve_module_by_base_no_match_returns_none():
    modules = [Module(0x140000000, 0x1000, "a.dll")]
    assert resolve_module_by_base(0x150000000, modules) is None


def test_resolve_module_by_base_containment_is_not_a_match():
    # Deliberately NOT addr_to_module()'s containment semantics -- an
    # address INSIDE a module but not equal to its own base must not
    # resolve.
    modules = [Module(0x140000000, 0x10000, "a.dll")]
    assert resolve_module_by_base(0x140000500, modules) is None


def test_resolve_module_by_base_empty_list():
    assert resolve_module_by_base(0x140000000, []) is None


def test_resolve_module_by_base_rejects_non_int_base():
    modules = [Module(0x140000000, 0x1000, "a.dll")]
    assert resolve_module_by_base("0x140000000", modules) is None
    assert resolve_module_by_base(None, modules) is None


# ── walk_environment_block: fakes ─────────────────────────────────────────
# A minimal stand-in for MinidumpBufferedReader (minidump.minidumpreader),
# just enough of .move()/.read()/.current_segment/.current_position to
# exercise walk_environment_block()'s real pointer-chasing and read logic
# without a real .dmp file.

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
        raise Exception('Memory address 0x%08x is not in process memory space' % address)

    def read(self, size):
        end = self.current_position + size
        if end > self.current_segment.end_address:
            raise Exception('Would read over segment boundaries!')
        off = self.current_position - self.current_segment.start_address
        data = self.current_segment.data[off:off + size]
        self.current_position = end
        return data


class _FakeReader:
    def __init__(self, buffered):
        self._buffered = buffered

    def get_buffered_reader(self):
        return self._buffered


class _ShortReadBufferedReader(_FakeBufferedReader):
    """_FakeBufferedReader's own .read() -- like the real installed
    minidump.minidumpreader.MinidumpBufferedReader.read(size) -- always
    raises rather than returning fewer bytes than requested when a read
    would run past the segment boundary, so read_pointer()'s own `len(raw)
    < ptr_size` short-read branch (dumpex/core/process_info.py) is
    unreachable through that fake. This subclass instead truncates and
    returns whatever's left WITHOUT raising, purely to exercise dumpex's
    own defensive handling of a reader that legitimately can short-read --
    not a claim that today's installed library reader behaves this way."""
    def read(self, size):
        off = self.current_position - self.current_segment.start_address
        available = self.current_segment.end_address - self.current_position
        take = min(size, available)
        data = self.current_segment.data[off:off + take]
        self.current_position += take
        return data


class _Thread:
    def __init__(self, teb):
        self.Teb = teb


class _Threads:
    def __init__(self, *tebs):
        self.threads = [_Thread(teb) for teb in tebs]


class _SysInfo:
    def __init__(self, arch):
        self.ProcessorArchitecture = arch


class _MF:
    """Deliberately NOT tests.fixtures.fakes.FakeMF -- walk_environment_block
    reads mf.get_reader().get_buffered_reader(), and FakeMF's get_reader()
    already returns self._reader directly (no get_buffered_reader() layer),
    so a purpose-built minimal stand-in is clearer here than bending the
    shared fake's shape."""
    def __init__(self, *, sysinfo=None, threads=None, segments=None):
        self.sysinfo = sysinfo
        self.threads = threads
        self._reader = _FakeReader(_FakeBufferedReader(segments or {}))

    def get_reader(self):
        return self._reader


TEB_VA           = 0x7FF000000000
PEB_VA           = 0x7FF000001000
PROCESS_PARAMS_VA = 0x7FF000002000
ENV_VA           = 0x7FF000003000

_X64_OFFSETS = process_info.PEB_OFFSETS[1]


def _amd64_mf(env_segment_data: bytes, env_segment_len=None, *, teb=TEB_VA, peb=PEB_VA,
              process_params=PROCESS_PARAMS_VA, env_va=ENV_VA):
    """A ready-to-walk x64 MF: TEB -> PEB -> ProcessParameters -> Environment
    pointer chain fully wired, with `env_segment_data` as the ONLY bytes
    backing the environment block's own memory segment (so a walk that
    reads past its end naturally raises, exercising the "captured_segment"
    stop reason)."""
    segments = {
        teb + _X64_OFFSETS["peb"]: peb.to_bytes(8, "little"),
        peb + _X64_OFFSETS["process_parameters"]: process_params.to_bytes(8, "little"),
        process_params + _X64_OFFSETS["environment_variables"]: env_va.to_bytes(8, "little"),
        env_va: env_segment_data,
    }
    return _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(teb),
               segments=segments)


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


_X86_OFFSETS = process_info.PEB_OFFSETS[0]

# Separate, 32-bit-range VAs -- the x64 TEB_VA/PEB_VA/... constants above
# don't fit in a 4-byte x86 pointer.
TEB_VA_X86            = 0x00300000
PEB_VA_X86            = 0x00301000
PROCESS_PARAMS_VA_X86 = 0x00302000
ENV_VA_X86            = 0x00303000


def _intel_mf(env_segment_data: bytes, *, teb=TEB_VA_X86, peb=PEB_VA_X86,
              process_params=PROCESS_PARAMS_VA_X86, env_va=ENV_VA_X86):
    """x86 counterpart of _amd64_mf() -- 4-byte pointers, PEB_OFFSETS[0]."""
    segments = {
        teb + _X86_OFFSETS["peb"]: peb.to_bytes(4, "little"),
        peb + _X86_OFFSETS["process_parameters"]: process_params.to_bytes(4, "little"),
        process_params + _X86_OFFSETS["environment_variables"]: env_va.to_bytes(4, "little"),
        env_va: env_segment_data,
    }
    return _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.INTEL), threads=_Threads(teb),
               segments=segments)


# ── walk_environment_block: preconditions ────────────────────────────────

def test_walk_environment_block_unsupported_when_sysinfo_absent():
    mf = _MF(sysinfo=None, threads=_Threads(TEB_VA))
    assert walk_environment_block(mf) == ("unsupported", None, None)


def test_walk_environment_block_unsupported_when_threads_absent():
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=None)
    assert walk_environment_block(mf) == ("unsupported", None, None)


def test_walk_environment_block_unsupported_when_threads_list_empty():
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads())
    assert walk_environment_block(mf) == ("unsupported", None, None)


def test_walk_environment_block_architecture_unsupported_for_arm64():
    # The library still builds a non-None PEB for ARM64 (it silently
    # treats every non-INTEL architecture as x64) -- dumpex's own walk
    # must refuse rather than guess wrong offsets.
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AARCH64), threads=_Threads(TEB_VA))
    state, entries, detail = walk_environment_block(mf)
    assert state == "architecture_unsupported"
    assert entries is None


# ── walk_environment_block: pointer chasing failures ─────────────────────

def test_walk_environment_block_pointer_unreadable_teb_out_of_range():
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments={})
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert entries is None
    assert "TEB->PEB" in detail


def test_walk_environment_block_pointer_unreadable_null_peb_pointer():
    segments = {TEB_VA + _X64_OFFSETS["peb"]: (0).to_bytes(8, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "null pointer" in detail


def test_walk_environment_block_pointer_unreadable_short_read():
    # Only 4 of the 8 bytes an x64 pointer read needs are captured -- with
    # the default _FakeBufferedReader (matching the real installed
    # library's own MinidumpBufferedReader.read(), which always raises
    # rather than short-reading for a fixed size), this exercises
    # read_pointer()'s exception branch, not its `len(raw) < ptr_size`
    # branch -- see test_walk_environment_block_pointer_unreadable_short_
    # read_without_raising below for that one.
    segments = {TEB_VA + _X64_OFFSETS["peb"]: (0x1234).to_bytes(4, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"


def test_walk_environment_block_pointer_unreadable_short_read_without_raising():
    # Exercises read_pointer()'s OWN `len(raw) < ptr_size` defensive
    # branch specifically -- a reader whose .read() legitimately returns
    # fewer bytes than requested instead of raising (dumpex/core/
    # process_info.py's read_pointer() guards against this even though
    # today's installed library reader never actually does it for a fixed
    # size, per _ShortReadBufferedReader's own docstring).
    segments = {TEB_VA + _X64_OFFSETS["peb"]: (0x1234).to_bytes(4, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    mf._reader = _FakeReader(_ShortReadBufferedReader(dict(segments.items())))
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert detail.endswith("short read")


def test_walk_environment_block_pointer_unreadable_process_parameters_step():
    # PEB resolves; nothing beyond it does.
    segments = {TEB_VA + _X64_OFFSETS["peb"]: PEB_VA.to_bytes(8, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "ProcessParameters" in detail


class _RaisingGetReaderMF:
    """A minimal MF whose get_reader() raises exactly the way the real
    minidump.minidumpreader.MinidumpFileReader.__init__ does when
    minidumpfile.modules (or memory_segments_64/memory_segments) is None
    -- an unconditional `minidumpfile.modules.modules` attribute access,
    with no guard of its own. open_dump()'s own per-stream isolation can
    legitimately leave any of those None (an absent or FAILED stream),
    so mf.get_reader() itself -- not just the pointer reads that follow
    it -- is a real failure surface walk_environment_block() must
    survive, matching its own "-> (state, entries, detail). Never
    raises." docstring contract."""
    def __init__(self, sysinfo, threads):
        self.sysinfo = sysinfo
        self.threads = threads

    def get_reader(self):
        raise AttributeError("'NoneType' object has no attribute 'modules'")


def test_walk_environment_block_survives_reader_construction_failure():
    mf = _RaisingGetReaderMF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA))
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert entries is None
    assert "memory reader unavailable" in detail
    assert "modules" in detail


def test_walk_environment_block_null_environment_pointer():
    segments = {
        TEB_VA + _X64_OFFSETS["peb"]: PEB_VA.to_bytes(8, "little"),
        PEB_VA + _X64_OFFSETS["process_parameters"]: PROCESS_PARAMS_VA.to_bytes(8, "little"),
        PROCESS_PARAMS_VA + _X64_OFFSETS["environment_variables"]: (0).to_bytes(8, "little"),
    }
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "Environment" in detail
    assert "null pointer" in detail


def test_walk_environment_block_environment_base_unreadable():
    # All three pointers resolve to real, non-null values, but nothing
    # backs env_va itself -- reader.move(env_va) raises.
    segments = {
        TEB_VA + _X64_OFFSETS["peb"]: PEB_VA.to_bytes(8, "little"),
        PEB_VA + _X64_OFFSETS["process_parameters"]: PROCESS_PARAMS_VA.to_bytes(8, "little"),
        PROCESS_PARAMS_VA + _X64_OFFSETS["environment_variables"]: ENV_VA.to_bytes(8, "little"),
    }
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.AMD64), threads=_Threads(TEB_VA), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "Environment block base unreadable" in detail


# ── walk_environment_block: x86/INTEL architecture ────────────────────────

def test_walk_environment_block_intel_full_walk_succeeds():
    mf = _intel_mf(_utf16("A=1") + b"\x00\x00" + b"\x00\x00")
    state, entries, detail = walk_environment_block(mf)
    assert state == "present"
    assert entries == ["A=1"]


def test_walk_environment_block_intel_pointer_short_read():
    # Only 2 of the 4 bytes an x86 pointer read needs are captured -- see
    # the x64 short-read test above for why this exercises read_pointer()'s
    # exception branch, not its `len(raw) < ptr_size` branch.
    segments = {TEB_VA_X86 + _X86_OFFSETS["peb"]: (0x1234).to_bytes(2, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.INTEL), threads=_Threads(TEB_VA_X86), segments=segments)
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "TEB->PEB" in detail


def test_walk_environment_block_intel_pointer_short_read_without_raising():
    segments = {TEB_VA_X86 + _X86_OFFSETS["peb"]: (0x1234).to_bytes(2, "little")}
    mf = _MF(sysinfo=_SysInfo(PROCESSOR_ARCHITECTURE.INTEL), threads=_Threads(TEB_VA_X86), segments=segments)
    mf._reader = _FakeReader(_ShortReadBufferedReader(dict(segments.items())))
    state, entries, detail = walk_environment_block(mf)
    assert state == "pointer_unreadable"
    assert "TEB->PEB" in detail
    assert detail.endswith("short read")


# ── walk_environment_block: present_empty vs unparseable ─────────────────

def test_walk_environment_block_verified_empty_requires_four_captured_zero_bytes():
    mf = _amd64_mf(b"\x00\x00\x00\x00")
    assert walk_environment_block(mf) == ("present_empty", [], None)


def test_walk_environment_block_only_two_captured_zero_bytes_is_unparseable():
    # Truncated right after the first zero-length "entry" -- must NOT be
    # promoted into "the process had no environment" (issue #37 §4.3.2).
    mf = _amd64_mf(b"\x00\x00")
    state, entries, detail = walk_environment_block(mf)
    assert state == "unparseable"
    assert entries is None


def test_walk_environment_block_four_zero_bytes_but_more_after_is_still_present_empty():
    # present_empty is checked from the block start only -- what follows
    # the confirmed empty signature is irrelevant to THIS classification.
    mf = _amd64_mf(b"\x00\x00\x00\x00" + _utf16("A=1") + b"\x00\x00\x00\x00")
    assert walk_environment_block(mf) == ("present_empty", [], None)


# ── walk_environment_block: present ───────────────────────────────────────

def test_walk_environment_block_present_single_entry():
    data = _utf16("A=1") + b"\x00\x00" + b"\x00\x00"   # entry NUL + block NUL
    mf = _amd64_mf(data)
    assert walk_environment_block(mf) == ("present", ["A=1"], None)


def test_walk_environment_block_present_multiple_entries_preserve_order_and_duplicates():
    data = (_utf16("A=1") + b"\x00\x00" + _utf16("B=2") + b"\x00\x00"
            + _utf16("A=1") + b"\x00\x00" + b"\x00\x00")
    mf = _amd64_mf(data)
    assert walk_environment_block(mf) == ("present", ["A=1", "B=2", "A=1"], None)


def test_walk_environment_block_terminator_split_across_read_chunks_found_normally():
    data = _utf16("A=1") + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    original_chunk = process_info._ENV_READ_CHUNK
    process_info._ENV_READ_CHUNK = 4   # force many tiny chunk reads
    try:
        assert walk_environment_block(mf) == ("present", ["A=1"], None)
    finally:
        process_info._ENV_READ_CHUNK = original_chunk


def test_walk_environment_block_two_zero_bytes_at_odd_offset_not_treated_as_terminator():
    # "a" (0x61 0x00) + U+0100 (0x00 0x01) -- bytes[1:3] == b"\x00\x00" at
    # an ODD offset. A naive raw-byte scan for b"\x00\x00" would stop the
    # entry right there; the real entry continues past it to its own
    # (even-offset) terminator, and a second entry follows.
    entry = "a" + chr(0x0100)
    data = entry.encode("utf-16-le") + b"\x00\x00" + _utf16("B=2") + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    assert walk_environment_block(mf) == ("present", [entry, "B=2"], None)


# ── walk_environment_block: partial (budgets, segment end, decode) ───────

def test_walk_environment_block_partial_entries_budget():
    data = _utf16("A=1") + b"\x00\x00" + _utf16("B=2") + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    state, entries, detail = walk_environment_block(mf, max_entries=1)
    assert state == "partial"
    assert entries == ["A=1"]
    assert detail == "environment_entries"


def test_walk_environment_block_partial_bytes_budget():
    data = _utf16("A=1") + b"\x00\x00" + _utf16("BB=222") + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    # Budget covers the first entry's own terminator, but not the second entry.
    state, entries, detail = walk_environment_block(mf, max_bytes=8)
    assert state == "partial"
    assert entries == ["A=1"]
    assert detail == "environment_bytes"


def test_walk_environment_block_partial_captured_segment_ends_mid_entry():
    # The segment itself (not the byte budget) ends mid-entry: only 4 of
    # "BB=222"'s bytes are backed by real memory.
    data = _utf16("A=1") + b"\x00\x00" + _utf16("BB=2")   # truncated: no terminator, more budget available
    mf = _amd64_mf(data)
    state, entries, detail = walk_environment_block(mf, max_bytes=MAX_ENV_BYTES)
    assert state == "partial"
    assert entries == ["A=1"]
    assert detail == "captured_segment"


def test_walk_environment_block_partial_undecodable_entry_with_prior_entries():
    # An unpaired UTF-16 low surrogate can never decode -- utf-16-le
    # raises UnicodeDecodeError on it, regardless of what (if anything)
    # follows.
    bad = (0xDC00).to_bytes(2, "little")   # lone low surrogate code unit
    data = _utf16("A=1") + b"\x00\x00" + bad + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    state, entries, detail = walk_environment_block(mf)
    assert state == "partial"
    assert entries == ["A=1"]
    assert detail == "undecodable_entry"


def test_walk_environment_block_unparseable_undecodable_entry_with_no_prior_entries():
    bad = (0xDC00).to_bytes(2, "little")
    data = bad + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    state, entries, detail = walk_environment_block(mf)
    assert state == "unparseable"
    assert entries is None
    assert detail == "undecodable_entry"


# ── walk_environment_block: _env_read_capture()'s own bounded-read
# robustness (issue #41 P3) -- a mid-capture remaining_len()/read()
# failure must never escape as an exception, and must keep whatever was
# already captured, exactly like a genuine segment boundary already does
# (test_walk_environment_block_partial_captured_segment_ends_mid_entry
# above). All three use a >4096-byte segment (the module's own
# _ENV_READ_CHUNK) of 512 complete "A=1" entries (exactly 4096 bytes)
# followed by more data the fault must prevent ever being read, so the
# first read() call captures a full 4096-byte chunk before the SECOND
# call's fault fires -- proving entries found before the fault survive,
# not just that nothing raises. ──────────────────────────────────────────

_FAULT_ENV_ENTRIES = 512   # 512 * 8 bytes ("A=1\0") == 4096 == _ENV_READ_CHUNK exactly
_ONE_ENV_ENTRY = _utf16("A=1") + b"\x00\x00"
_FAULT_ENV_DATA = (_ONE_ENV_ENTRY * _FAULT_ENV_ENTRIES) + _utf16("B=2") + b"\x00\x00"


def _wire_fault_mf(fault_kind):
    mf = FakeMF()
    si = SysInfo()
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE.AMD64
    mf.sysinfo = si
    mf.threads = FakeStream([Thread(1, Ctx(0))], "threads")
    env_va = 0x7FF000003000
    wire_environment_walk(mf, _FAULT_ENV_DATA, env_va=env_va,
                           fault_at=env_va + 4096, fault_kind=fault_kind)
    return mf


def test_walk_environment_block_survives_remaining_len_raising_mid_capture():
    mf = _wire_fault_mf("remaining_len_raises")
    state, entries, detail = walk_environment_block(mf)   # must not raise
    assert state == "partial"
    assert entries == ["A=1"] * _FAULT_ENV_ENTRIES   # already-captured entries preserved
    assert detail == "captured_segment"


def test_walk_environment_block_survives_read_raising_mid_capture():
    mf = _wire_fault_mf("read_raises")
    state, entries, detail = walk_environment_block(mf)   # must not raise
    assert state == "partial"
    assert entries == ["A=1"] * _FAULT_ENV_ENTRIES
    assert detail == "captured_segment"


def test_walk_environment_block_survives_read_returning_empty_mid_capture():
    mf = _wire_fault_mf("read_empty")
    state, entries, detail = walk_environment_block(mf)   # must not raise
    assert state == "partial"
    assert entries == ["A=1"] * _FAULT_ENV_ENTRIES
    assert detail == "captured_segment"


# ── walk_environment_block: never raises, never mutates ─────────────────

def test_walk_environment_block_never_raises_when_only_one_byte_is_captured():
    # A successful move() to the block base followed by a single
    # capturable byte -- forced down to even alignment (0 usable bytes)
    # by _env_read_capture -- must still resolve cleanly to unparseable,
    # not raise.
    mf = _amd64_mf(b"\x00")
    state, entries, detail = walk_environment_block(mf)
    assert state == "unparseable"
    assert entries is None


def test_walk_environment_block_does_not_mutate_mf():
    data = _utf16("A=1") + b"\x00\x00" + b"\x00\x00"
    mf = _amd64_mf(data)
    walk_environment_block(mf)
    assert mf.sysinfo.ProcessorArchitecture == PROCESSOR_ARCHITECTURE.AMD64
    assert len(mf.threads.threads) == 1
