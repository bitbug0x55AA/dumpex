"""
Command-line behaviour baseline over real synthetic dump files.

Every scenario writes byte-level `.dmp` files (see
`tests.fixtures.minidump_bytes`) and runs the real `dumpex.cli.main()` on
them -- no `open_dump` stand-in -- so the loader, the captured-range
readers and every record/coverage projection a command uses sit on the
measured path. One run records:

* the exit code;
* stdout and stderr, line by line;
* the complete `--json` document, when the scenario writes one;
* the `--txt` transcript, when the scenario writes one;
* the size and SHA-256 of an `--output` byte artifact, when one is written.

Only values that genuinely vary between runs or machines are replaced, each
with a fixed placeholder: the scratch directory and repository paths
(separators normalised to "/"), the wall clock (frozen), installed version
strings, the size/digest of an output file whose bytes embed a scratch
path, and argparse's own usage block (its wrapping is the interpreter's).
CSV is not listed: no current command writes CSV.
"""
import contextlib
import datetime
import gc
import hashlib
import io
import json
import os
import re
import struct
import sys
from dataclasses import dataclass, field, replace

from tests.fixtures.decomposition_baseline import REPO_ROOT
from tests.fixtures.minidump_bytes import (
    MEM_IMAGE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE, DumpSpec, HandleSpec, ModuleSpec, RegionSpec, SegmentSpec,
    ThreadInfoSpec, ThreadSpec, build_minidump,
)

APP_BASE = 0x7FF6_0000_0000
NTDLL_BASE = 0x7FFE_0000_0000
TEB = 0x7FFD_E000
PEB = 0x7FFD_F000
PARAMS = 0x2000_0000
INJECTED = 0x3000_0000
SHORT_BACKED = 0x4000_0000
DUMP_FLAG_INVALID_CONTEXT = 0x10

_CODE = bytes.fromhex(
    "4883ec28"          # sub rsp, 0x28
    "488b05f90f0000"    # mov rax, [rip+0xff9]
    "ffd0"              # call rax
    "e8f0ffffff"        # call rel32
    "ff15e20f0000"      # call [rip+0xfe2]
    "4883c428"          # add rsp, 0x28
    "c3")               # ret


def _pe_header(size_of_image: int, image_base: int, text_size: int = 0x1000) -> bytes:
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    opt = bytearray(112 + 16 * 8)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)                # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, image_base)
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)        # Section/FileAlignment
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, 0x400)                 # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)                     # Subsystem: console
    struct.pack_into("<I", opt, 108, 16)                   # NumberOfRvaAndSizes
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0x5F5E1000, 0, 0, len(opt), 0x0022)
    section = bytearray(40)
    section[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", section, 8, text_size, 0x1000, text_size, 0x400)
    struct.pack_into("<I", section, 36, 0x60000020)
    return bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + bytes(section)


def _page(prefix: bytes, size: int = 0x1000, fill: bytes = b"\x00") -> bytes:
    return prefix + fill * (size - len(prefix))


def _unicode_string(buffer_va: int, text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<HHIQ", len(raw), len(raw) + 2, 0, buffer_va)


def _process_parameters() -> bytes:
    page = bytearray(0x1000)
    strings = {
        0x38: "D:\\Cases\\Work\\",
        0x50: r"C:\Windows\System32",
        0x60: r"C:\Program Files\Sample\app.exe",
        0x70: r'"C:\Program Files\Sample\app.exe" --serve --port 8443',
        0xB0: "Sample App",
    }
    cursor = 0x400
    for offset, text in strings.items():
        raw = text.encode("utf-16-le")
        page[offset:offset + 16] = _unicode_string(PARAMS + cursor, text)
        page[cursor:cursor + len(raw)] = raw
        cursor += len(raw) + 0x10
    struct.pack_into("<QQQ", page, 0x20, 0x4, 0x8, 0xC)    # standard handles
    struct.pack_into("<Q", page, 0x80, PARAMS + 0xC00)     # Environment
    env = "\0".join(["COMPUTERNAME=HOST-SYNTH", "USERNAME=analyst", r"PATH=C:\Windows",
                     "PROCESSOR_ARCHITECTURE=AMD64"]) + "\0\0"
    raw = env.encode("utf-16-le")
    page[0xC00:0xC00 + len(raw)] = raw
    return bytes(page)


def _injected_region() -> bytes:
    region = bytearray(_pe_header(0x2000, INJECTED))
    region += b"\x00" * (0x100 - len(region))
    region += _CODE
    region += b"\x00" * (0x400 - len(region))
    region += b"GET http://c2.example.test/beacon?id=7 HTTP/1.1\x00"
    region += b"\x00" * (0x480 - len(region))
    region += r"\\.\pipe\msagent_12".encode("utf-16-le") + b"\x00\x00"
    region += b"\x00" * (0x500 - len(region))
    region += b"User-Agent: Mozilla/5.0 (synthetic)\x00"
    return bytes(region) + b"\x00" * (0x2000 - len(region))


def primary_spec() -> DumpSpec:
    teb = bytearray(0x1000)
    struct.pack_into("<Q", teb, 0x60, PEB)
    peb = bytearray(0x1000)
    struct.pack_into("<Q", peb, 0x10, APP_BASE)
    struct.pack_into("<Q", peb, 0x20, PARAMS)
    text = _page(_CODE, fill=b"\xcc")
    segments = (
        SegmentSpec(TEB, bytes(teb)),
        SegmentSpec(PEB, bytes(peb)),
        SegmentSpec(PARAMS, _process_parameters()),
        SegmentSpec(INJECTED, _injected_region()),
        SegmentSpec(APP_BASE, _page(_pe_header(0x3000, APP_BASE))),
        SegmentSpec(APP_BASE + 0x1000, text),
        SegmentSpec(SHORT_BACKED, _page(b"short backed region needle-string", fill=b"S")),
    )
    regions = (
        RegionSpec(PARAMS, 0x1000),
        RegionSpec(INJECTED, 0x2000, protect=PAGE_EXECUTE_READWRITE),
        RegionSpec(SHORT_BACKED, 0x1000),
        RegionSpec(0x5000_0000, 0x10000, state=MEM_RESERVE, protect=PAGE_READWRITE),
        RegionSpec(TEB, 0x2000),
        RegionSpec(APP_BASE, 0x1000, protect=PAGE_READONLY, type=MEM_IMAGE),
        RegionSpec(APP_BASE + 0x1000, 0x1000, protect=PAGE_EXECUTE_READ, type=MEM_IMAGE,
                   allocation_base=APP_BASE),
        RegionSpec(APP_BASE + 0x2000, 0x1000, protect=PAGE_READWRITE, type=MEM_IMAGE,
                   allocation_base=APP_BASE),
        RegionSpec(NTDLL_BASE, 0x2000, protect=PAGE_EXECUTE_READ, type=MEM_IMAGE),
    )
    return DumpSpec(
        modules=(ModuleSpec(APP_BASE, 0x3000, r"C:\Program Files\Sample\app.exe",
                            checksum=0x1234, timestamp=0x5F5E1000),
                 ModuleSpec(NTDLL_BASE, 0x2000, r"C:\Windows\System32\ntdll.dll",
                            timestamp=0x5F000000)),
        threads=(ThreadSpec(0x100, ip=APP_BASE + 0x1010, teb=TEB),
                 ThreadSpec(0x104, ip=INJECTED + 0x100, teb=TEB + 0x2000),
                 ThreadSpec(0x108, ip=NTDLL_BASE + 0x500, teb=TEB + 0x4000),
                 ThreadSpec(0x10C, ip=APP_BASE + 0x1020, teb=TEB + 0x6000)),
        thread_infos=(ThreadInfoSpec(0x100, start_address=APP_BASE + 0x1000,
                                     create_time=132_000_000_000_000_000, kernel_time=1000,
                                     user_time=2000),
                      ThreadInfoSpec(0x104, start_address=INJECTED + 0x100),
                      ThreadInfoSpec(0x108, dump_flags=DUMP_FLAG_INVALID_CONTEXT,
                                     start_address=NTDLL_BASE + 0x400)),
        regions=regions,
        memory64=segments,
        handles=(HandleSpec(0x4, "File", r"\Device\HarddiskVolume3\Users\analyst\notes.txt",
                            granted_access=0x12019F),
                 HandleSpec(0x8, "Event", None, granted_access=0x1F0003),
                 HandleSpec(0xC, "File", r"\Device\NamedPipe\msagent_12", granted_access=0x12019F),
                 HandleSpec(0x10, "Key", r"\REGISTRY\MACHINE\SOFTWARE\Sample",
                            granted_access=0x20019),
                 HandleSpec(0x14, "Section", None, granted_access=0x4)),
        process_id=4242,
    )


def reference_spec() -> DumpSpec:
    """The --diff baseline: one module rebased, one thread gone and one new,
    and the injected region's protection different."""
    spec = primary_spec()
    modules = (spec.modules[0],
               replace(spec.modules[1], base=NTDLL_BASE + 0x100000))
    threads = (*spec.threads[:3], ThreadSpec(0x110, ip=APP_BASE + 0x1030, teb=TEB + 0x8000))
    regions = tuple(replace(r, protect=PAGE_EXECUTE_READ) if r.base == INJECTED else r
                    for r in spec.regions)
    return replace(spec, modules=modules, threads=threads, regions=regions)


STUB = 0x3100_0000

# A call/pop leaves this code's own address in rax; six single-step adds and
# one larger add derive the write address from it; a loop of in-place xor
# writes closes with a backward branch; control then leaves through a
# register. The address arithmetic makes the self-decoding-stub proof cite
# more instructions than a lead keeps as evidence.
_STUB_CODE = bytes.fromhex(
    "e800000000" "58" + "4883c001" * 6 + "4883c00a" "803041"
    + "".join(f"8070{i:02x}41" for i in range(1, 12))
    + "48ffc0" "4883e901" "75c8" "ffd0" "c3")


def leads_spec() -> DumpSpec:
    """The primary dump plus a private RWX region holding a self-decoding
    stub, for the report's static-analysis lead projection."""
    spec = primary_spec()
    return replace(
        spec,
        memory64=(*spec.memory64[:-1], SegmentSpec(STUB, _STUB_CODE.ljust(0x1000, b"\x90")),
                  spec.memory64[-1]),
        regions=(*spec.regions, RegionSpec(STUB, 0x1000, protect=PAGE_EXECUTE_READWRITE)))


def _truncated(spec: DumpSpec) -> DumpSpec:
    """`spec` with its last captured segment cut to 0x80 bytes."""
    full = len(build_minidump(spec))
    return replace(spec, truncate_to=full - 0x1000 + 0x80)


# ── Scenarios ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Scenario:
    name: str
    argv: tuple                 # "{dump}", "{ref}" and "{tmp}" are substituted
    dump: str = "primary"       # "primary" | "leads" | "missing" | "junk"
    json: bool = False
    txt: bool = False
    output: bool = False        # the argv already names "{tmp}/out.bin"
    needs_yara: bool = False    # yara-python is an optional ("full") dependency
    env: dict = field(default_factory=dict)


_J = dict(json=True)
SCENARIOS = (
    Scenario("list", ("--list",), **_J),
    Scenario("list_filter", ("--list", "--filter", "PAGE_EXECUTE_READWRITE"), **_J),
    Scenario("modules", ("--modules",), **_J),
    Scenario("modules_txt", ("--modules",), txt=True),
    Scenario("threads", ("--threads",), **_J),
    Scenario("extract", ("--extract", hex(INJECTED), "-s", "0x80", "-o", "{tmp}/out.bin"),
             output=True, **_J),
    Scenario("extract_short_read", ("--extract", hex(SHORT_BACKED), "-s", "0x100",
                                    "-o", "{tmp}/out.bin"), output=True, **_J),
    Scenario("extract_uncaptured", ("--extract", "0x60000000", "-s", "0x10",
                                    "-o", "{tmp}/out.bin"), **_J),
    Scenario("strings", ("--strings", hex(INJECTED), "-s", "0x800"), **_J),
    Scenario("strings_grep_ascii", ("--strings", hex(INJECTED), "-s", "0x800", "--grep", "c2",
                                    "--strings-encoding", "ascii", "--min-len", "8"), **_J),
    Scenario("process", ("--process",), **_J),
    Scenario("process_verbose_redacted", ("--process", "--verbose", "--redact-paths"), **_J),
    Scenario("handles", ("--handles",), **_J),
    Scenario("handles_verbose_txt", ("--handles", "--verbose"), txt=True),
    Scenario("profile", ("--profile",), **_J),
    Scenario("sysinfo", ("--sysinfo",), **_J),
    Scenario("sysinfo_verbose", ("--sysinfo", "--verbose")),
    Scenario("diff_all", ("--diff", "{ref}"), **_J),
    Scenario("diff_threads", ("--diff", "{ref}", "--diff-scope", "threads")),
    Scenario("report_tid_current", ("--report", "--report-tid", "0x100"), **_J),
    Scenario("report_tid_injected_verbose", ("--report", "--report-tid", "0x104", "--verbose"),
             **_J),
    Scenario("report_tid_conflict", ("--report", "--report-tid", "0x108"), **_J),
    Scenario("report_addr", ("--report", "--report-addr", hex(INJECTED + 0x400)), **_J),
    Scenario("report_string", ("--report", "--report-string", "needle-string"), **_J),
    Scenario("report_string_utf16", ("--report", "--report-string", "msagent_12")),
    Scenario("report_leads_txt", ("--report", "--report-addr", hex(STUB)), dump="leads",
             txt=True, **_J),
    Scenario("report_leads_verbose_txt", ("--report", "--report-addr", hex(STUB), "--verbose"),
             dump="leads", txt=True),
    Scenario("hunt_injection", ("--hunt", "injection"), **_J),
    Scenario("hunt_all", ("--hunt", "all"), needs_yara=True, **_J),
    Scenario("error_missing_dump", ("--modules",), dump="missing"),
    Scenario("error_not_a_minidump", ("--modules",), dump="junk"),
    Scenario("error_no_command", ()),
    Scenario("error_unknown_ttp", ("--hunt", "bogus")),
    Scenario("error_report_without_anchor", ("--report",)),
    Scenario("error_json_exists_without_force", ("--modules", "--json", "{tmp}/exists.json")),
)
SCENARIO_BY_NAME = {s.name: s for s in SCENARIOS}


# ── Runner ────────────────────────────────────────────────────────────────

_TIMEZONE = datetime.timezone
_TIMEDELTA = datetime.timedelta


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


class _FrozenDateTimeModule:
    datetime = _FixedDateTime
    timezone = _TIMEZONE
    timedelta = _TIMEDELTA


def _freeze(monkeypatch):
    import dumpex.cli as cli
    import dumpex.hunt.yara_hunt as yara_hunt_mod
    import dumpex.output.collector as collector_mod
    import dumpex.rules_pkg.loader as rules_loader
    import dumpex.ui.colors as colors
    import dumpex.ui.structured as structured_mod
    for mod in (cli, collector_mod, structured_mod):
        monkeypatch.setattr(mod, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(colors, "USE_COLOR", False)
    monkeypatch.setattr(rules_loader, "_RULES_CACHE", None)
    monkeypatch.setattr(rules_loader, "_EXPLICIT_RULES_PATH", None)
    monkeypatch.setattr(rules_loader, "_LAST_SOURCE_INFO", None)
    monkeypatch.setattr(yara_hunt_mod, "_LAST_YARA_PROVENANCE", None)
    monkeypatch.setenv("COLUMNS", "100")


def _write_inputs(scenario: Scenario, tmp: str) -> "tuple[str, str]":
    dump = os.path.join(tmp, "sample.dmp")
    ref = os.path.join(tmp, "reference.dmp")
    if scenario.dump in ("primary", "leads"):
        spec = leads_spec() if scenario.dump == "leads" else primary_spec()
        with open(dump, "wb") as fh:
            fh.write(build_minidump(_truncated(spec)))
        with open(ref, "wb") as fh:
            fh.write(build_minidump(_truncated(reference_spec())))
    elif scenario.dump == "junk":
        with open(dump, "wb") as fh:
            fh.write(b"this is not a minidump file")
    with open(os.path.join(tmp, "exists.json"), "wb") as fh:
        fh.write(b"{}\n")
    return dump, ref


class _Normalizer:
    def __init__(self, tmp: str):
        roots = [(os.path.realpath(tmp), "<TMP>"), (os.path.abspath(tmp), "<TMP>"),
                 (os.path.realpath(REPO_ROOT), "<REPO>"), (os.path.abspath(REPO_ROOT), "<REPO>")]
        roots = sorted(set(roots), key=lambda r: -len(r[0]))
        alternatives = "|".join(re.escape(root) for root, _ in roots)
        self._placeholders = dict(roots)
        self._re = re.compile(rf"({alternatives})([^\s\"'),]*)", re.IGNORECASE)
        self._lookup = {root.lower(): ph for root, ph in roots}

    def text(self, value: str) -> str:
        def sub(m):
            return self._lookup[m.group(1).lower()] + m.group(2).replace("\\", "/")
        return self._re.sub(sub, value)

    def data(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.data(v) for v in value]
        if isinstance(value, dict):
            return {k: self.data(v) for k, v in value.items()}
        return value


_WRITTEN_RE = re.compile(r"((?:JSON|TXT)\s+written \u2192 \S+\s+\()[^)]*(\))")
_VERSION_KEYS = ("python_version", "minidump_version", "yara_version", "pyyaml_version",
                 "capstone_version")


def _normalize_doc(doc: dict, norm: _Normalizer) -> dict:
    doc = norm.data(doc)
    meta = doc.get("meta", {})
    if "tool" in meta and "version" in meta["tool"]:
        meta["tool"]["version"] = "<VERSION>"
    runtime = meta.get("runtime")
    if isinstance(runtime, dict):
        meta["runtime"] = {k: "<VERSION>" for k in sorted(runtime)}
    return doc


def _lines(text: str) -> list:
    return text.replace("\r\n", "\n").split("\n")


_USAGE_RE = re.compile(r"^usage: .*?(?=^\S)", re.MULTILINE | re.DOTALL)


def _argparse_usage_elided(text: str) -> str:
    """argparse's usage block is wrapped by the interpreter's own formatter,
    whose layout differs between supported Python versions; the error line
    after it is dumpex's."""
    return _USAGE_RE.sub("usage: <argparse usage>\n", text)


def run_scenario(scenario: Scenario, monkeypatch, tmp: str) -> dict:
    """Run `scenario` in `tmp` (an empty directory) and return its
    normalized result. `monkeypatch` is a pytest MonkeyPatch the caller
    undoes afterwards."""
    import dumpex.cli as cli
    _freeze(monkeypatch)
    for key, value in scenario.env.items():
        monkeypatch.setenv(key, value)
    dump, ref = _write_inputs(scenario, tmp)
    if scenario.dump == "missing":
        dump = os.path.join(tmp, "absent.dmp")
    json_path = os.path.join(tmp, "out.json")
    txt_path = os.path.join(tmp, "out.txt")
    argv = [a.replace("{dump}", dump).replace("{ref}", ref).replace("{tmp}", tmp)
            for a in scenario.argv]
    argv = ["dumpex", dump, *argv]
    if scenario.json:
        argv += ["--json", json_path]
    if scenario.txt:
        argv += ["--txt", txt_path]
    monkeypatch.setattr(sys, "argv", argv)

    stdout, stderr = io.StringIO(), io.StringIO()
    exit_code, uncaught = 0, None
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code
        except Exception as exc:   # noqa: BLE001 -- an escaping exception IS an outcome
            # Recorded as text only: the traceback would keep the opened
            # dump (and its file handle) alive past this call.
            exit_code, uncaught = None, f"{type(exc).__name__}: {exc}"
    gc.collect()

    norm = _Normalizer(tmp)
    result = {
        "argv": norm.data(argv[1:]),
        "exit_code": exit_code,
        "stdout": _lines(_WRITTEN_RE.sub(r"\1<WRITTEN>\2", norm.text(stdout.getvalue()))),
        "stderr": _lines(_argparse_usage_elided(norm.text(stderr.getvalue()))),
    }
    if uncaught is not None:
        result["uncaught_exception"] = norm.text(uncaught)
    if scenario.json:
        if os.path.exists(json_path):
            with open(json_path, encoding="utf-8") as fh:
                result["json"] = _normalize_doc(json.load(fh), norm)
        else:
            result["json"] = None
    if scenario.txt:
        if os.path.exists(txt_path):
            with open(txt_path, "rb") as fh:
                result["txt"] = _lines(_WRITTEN_RE.sub(
                    r"\1<WRITTEN>\2", norm.text(fh.read().decode("utf-8"))))
        else:
            result["txt"] = None
    if scenario.output:
        out_path = os.path.join(tmp, "out.bin")
        if os.path.exists(out_path):
            with open(out_path, "rb") as fh:
                data = fh.read()
            result["output_file"] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        else:
            result["output_file"] = None
    return result


def yara_available() -> bool:
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    return True


def golden_name(scenario: Scenario) -> str:
    return f"cli/{scenario.name}.json"
