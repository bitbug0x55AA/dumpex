"""
Synthetic, deterministic `--hunt` scenarios shared by the v2.4 output
migration's compatibility-freeze test
(tests/integration/test_hunt_compat_freeze.py) and, going forward, PR2's
`HunterRecord`/`*Details` tests.

Every scenario builds its `MinidumpFile` stand-in from
`tests.fixtures.fakes` only — never from `tests/corpus/` (`.gitignore`d,
local-only, and may contain real process memory strings, host paths, and
file hashes from a real malware sample; see that directory's own
`.gitignore` entry and this repo's git history for why real-dump output
must never be committed here). Each builder is a deterministic function of
its own literal inputs — no wall clock, no real filesystem path outside a
caller-supplied `tmp_path` — so two runs on two machines produce
byte-identical hunter dicts and console text.

Every builder takes pytest's own `monkeypatch` fixture and uses
`monkeypatch.setattr()` for every module-attribute override
(`read_region`/`get_thread_contexts`), the same convention
tests/integration/test_report_compat_freeze.py already established for the
prior (`--report`) compatibility freeze. This is NOT the same pattern
tests/hunt/test_*.py's existing per-hunter unit tests use (those assign
`module.read_region = ...` directly and never restore it — see
tests/conftest.py's own `_reset_thread_context_monkeypatches` docstring for
the "a real bug hit during phase-two development" this caused for
`get_thread_contexts` specifically) — `monkeypatch` restores the original
attribute automatically at the end of the requesting test, so calling two
of these scenarios in the same test session can never leak state between
them regardless of execution order.

Each function returns `(findings: dict, console_text: str)` — `findings` is
today's raw v1.1 dict a hunter's own `_hunt_*()` function (or, for
cs-beacon/yara, `hunt.cmd_hunt()`'s per-hunter entry — see those two
functions' own docstrings for why) returns. The `meta` envelope is
deliberately NOT built here — `started_at`/`finished_at`/`sha256`/host
paths in that envelope are inherently non-reproducible across runs, exactly
the kind of dynamic field a frozen fixture must not pin; a full CLI-layer
(`meta`-inclusive) freeze lives separately in
tests/integration/test_hunt_cli_compat_freeze.py, which monkeypatches
`datetime.datetime.now()` the same way test_report_compat_freeze.py does.
`console_text` is everything the hunter printed, captured via
`contextlib.redirect_stdout` (so it is a plain, ANSI-free `str` regardless
of host codepage — `dumpex.ui.colors.USE_COLOR` is `sys.stdout.isatty()`,
False under both pytest and this redirect either way).

Every scenario here was run once against the current (pre-migration) hunter
code and its `findings` values spot-checked by hand before being written
into `tests/integration/test_hunt_compat_freeze.py` — this module only
builds the input; it asserts nothing itself.
"""
import base64
import contextlib
import io
from pathlib import Path

from tests.fixtures.fakes import (
    Region, Module, ThreadInfo, Ctx, Thread, Handle, Segment, FakeReader,
    FakeStream, FakeMF, Peb, build_pe_header, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, mem_reader, matching_module_and_ref, cs_beacon_config_bytes,
)

import dumpex.hunt as hunt
import dumpex.hunt.injection as injection
import dumpex.hunt.hollowing as hollowing
import dumpex.hunt.stomping as stomping
import dumpex.hunt.pipe as pipemod
import dumpex.hunt.encoding as encoding


def _capture(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn()
    return result, buf.getvalue()


# ── injection ────────────────────────────────────────────────────────────

def injection_detected_full_correlation(monkeypatch):
    """RWX + validated hidden PE + live RIP all in the same allocation ->
    score 3 (adapted from tests/hunt/test_injection.py::
    test_full_correlation_still_detects)."""
    alloc_base = 0x7ff700000000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x1000, "rawptr": 0x400,
          "rawsize": 0x1000, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    regions = [
        Region(alloc_base, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE"),
        Region(alloc_base + 0x2000, alloc_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE"),
    ]
    mods = [Module(0x7ffe00000000, 0x10000, r"C:\Windows\System32\ntdll.dll")]
    thread_infos = [ThreadInfo(0x1, alloc_base + 0x2000)]
    thread_list = [Thread(0x1, Ctx(alloc_base + 0x2000))]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        threads        = FakeStream(thread_list, "threads")
    monkeypatch.setattr(injection, "read_region", mem_reader({alloc_base + 0x2000: pe_bytes}))
    return _capture(lambda: injection._hunt_injection(MF(), verbose=False))


def injection_inconclusive_no_thread_context(monkeypatch):
    """No ThreadListStream at all -> RIP correlation can't run -> partial
    coverage, INCONCLUSIVE (tests/hunt/test_injection.py::
    test_no_thread_context_is_partial)."""
    dummy_regions = [Region(0x10000, 0x10000, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]
    mods = [Module(0x20000, 0x1000, r"C:\Windows\System32\ntdll.dll")]

    class MF(FakeMF):
        memory_info = FakeStream(dummy_regions, "infos")
        modules      = FakeStream(mods, "modules")
        thread_info   = FakeStream([], "infos")
        threads        = None
    monkeypatch.setattr(injection, "read_region", mem_reader({}))
    return _capture(lambda: injection._hunt_injection(MF(), verbose=False))


# ── hollowing ────────────────────────────────────────────────────────────

def hollowing_detected_mem_private_and_rwx(monkeypatch):
    """MEM_PRIVATE at image base + RWX protection (MZ header intact, module
    list agrees) -> the two-corroborator-minimum path, score 1."""
    image_base = 0x140000000
    module = Module(image_base, 0x5000, r"C:\Windows\System32\legit.exe")
    regions = [Region(image_base, image_base, 0x5000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        peb = Peb(image_base, r"C:\Windows\System32\legit.exe")
        modules = FakeStream([module], "modules")
        memory_info = FakeStream(regions, "infos")
    monkeypatch.setattr(hollowing, "read_region", mem_reader({image_base: b"MZ" + b"\x90" * 62}))
    return _capture(lambda: hollowing._hunt_hollowing(MF(), verbose=False))


def hollowing_not_evaluated(monkeypatch):
    """No PEB stream at all -> NOT_EVALUATED (tests/hunt/test_hollowing.py::
    test_no_peb_is_not_evaluated). Takes `monkeypatch` for signature
    consistency with every other builder even though it patches nothing --
    the PEB-less path never calls read_region at all."""
    class MF(FakeMF):
        peb = None
    return _capture(lambda: hollowing._hunt_hollowing(MF(), verbose=False))


# ── stomping ─────────────────────────────────────────────────────────────

def stomping_detected_tampered_content(monkeypatch, tmp_path: Path):
    """Same build identity (Machine/SizeOfImage/TimeDateStamp) as the
    on-disk reference, but the in-memory .text bytes are bit-flipped ->
    a genuine verified content diff, score 1 (no thread context -> no RIP
    corroboration, so not score 2)."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    tampered_text = bytes(b ^ 0xFF for b in mem_text)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: tampered_text}))
    (tmp_path / "legit.dll").write_bytes(ref_file)
    return _capture(lambda: stomping._hunt_stomping(MF(), verbose=False, ref_dir=str(tmp_path)))


def stomping_clean_matching_reference(monkeypatch, tmp_path: Path):
    """Identical memory vs. reference content -> NOT_DETECTED_IN_SCANNED_SCOPE,
    complete coverage (tests/hunt/test_stomping.py::test_normal_writecopy_is_clean)."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: mem_text}))
    (tmp_path / "legit.dll").write_bytes(ref_file)
    return _capture(lambda: stomping._hunt_stomping(MF(), verbose=False, ref_dir=str(tmp_path)))


def stomping_inconclusive_no_ref_dir(monkeypatch):
    """No --ref-dir at all -> the only scored check never ran -> partial
    coverage, INCONCLUSIVE, never a bare CLEAN (tests/hunt/test_stomping.py::
    test_no_ref_dir_is_inconclusive_partial)."""
    module_base = 0x7ff600000000
    header, mem_text, ref_file, section = matching_module_and_ref(module_base)
    mods = [Module(module_base, 0x5000, r"C:\Windows\System32\legit.dll")]
    regions = [Region(module_base + section["vaddr"], module_base, section["vsize"],
                       "MEM_COMMIT", "PAGE_EXECUTE_WRITECOPY", "MEM_IMAGE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream(mods, "modules")
    monkeypatch.setattr(stomping, "read_region", mem_reader(
        {module_base: header, module_base + section["vaddr"]: mem_text}))
    return _capture(lambda: stomping._hunt_stomping(MF(), verbose=False, ref_dir=None))


# ── pipe ─────────────────────────────────────────────────────────────────

def pipe_detected_full_corroboration(monkeypatch):
    """A framework-named (Cobalt Strike msagent_) handle corroborated by
    BOTH nearby C2-style string context AND live RIP -> score 3 (adapted
    from tests/hunt/test_pipe.py::test_framework_plus_full_corroboration_scores_3)."""
    region_base = 0x1230000
    pipe_name = b"\\\\.\\pipe\\msagent_1337"
    pipe_off = 0x100
    data = (b"A" * pipe_off + pipe_name + b"\x00"
            + b"http://198.51.100.7:8080/submit.php" + b"B" * 0x200)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READ", "MEM_PRIVATE")]
    handle_list = [Handle(0x88, "File", r"\Device\NamedPipe\msagent_1337")]
    thread_infos = [ThreadInfo(0x999, region_base + 0x10)]
    pipe_va = region_base + pipe_off

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
        thread_info   = FakeStream(thread_infos, "infos")
        handles        = FakeStream(handle_list, "handles")
    monkeypatch.setattr(pipemod, "read_region", mem_reader({region_base: data}))
    monkeypatch.setattr(pipemod, "get_thread_contexts", lambda mf: [
        {"ThreadId": 0x999, "ip": pipe_va + 5, "ip_reg": "RIP", "is_wow64": False}])
    return _capture(lambda: pipemod._hunt_pipe(MF(), verbose=False))


# ── cs-beacon ────────────────────────────────────────────────────────────

def cs_beacon_detected(monkeypatch):
    """A structurally-valid, XOR-encoded beacon config in an
    executable+private region -> context-corroborated, score 2 (adapted
    from tests/integration/test_hunt_dispatcher.py::
    test_cs_beacon_config_fields_survive_dispatcher). Goes through
    `hunt.cmd_hunt()`, not the bare `_hunt_cs_beacon()` aggregate, because
    the int-keyed-fields-dict -> str-keys + bytes -> hex sanitization this
    scenario's own field matrix entry documents happens at the DISPATCHER
    layer (`dumpex/hunt/__init__.py`), not inside the aggregate itself."""
    seg_va, seg_fo = 0x20000, 0x2000
    config = cs_beacon_config_bytes(0x69)
    data = b"\x00" * 0x100 + config + b"\x00" * 0x100
    seg = Segment(seg_va, seg_fo, len(data))
    regions = [Region(seg_va, seg_va, len(data), "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        memory_info          = FakeStream(regions, "infos")
        _reader                = FakeReader({seg_va: data})
    return _capture(lambda: hunt.cmd_hunt(MF(), "cs-beacon", verbose=False)["cs-beacon"])


# ── yara ─────────────────────────────────────────────────────────────────

def yara_not_evaluated(monkeypatch, tmp_path: Path):
    """No rules directory at all -> NOT_EVALUATED (tests/hunt/test_yara_hunt.py::
    test_no_rules_directory_is_not_evaluated). Goes through `hunt.cmd_hunt()`
    for the same reason `cs_beacon_detected()` does -- the dispatcher, not
    the aggregate, does the bytes -> hex sanitization on `matches`. Does NOT
    require yara-python: the "no rules directory" branch returns before
    ever importing it (`import yara` in `dumpex/hunt/yara_hunt/__init__.py`
    and `rules.py` is local to the functions that actually compile rules,
    not top-level) -- confirmed by grepping both files for a module-level
    `import yara`, so this scenario (unlike `yara_detected` below) is safe
    to run in an environment without the optional dependency installed.

    Uses a subdirectory of `tmp_path` that is asserted not to exist, rather
    than a hardcoded string -- a literal path like "/definitely_not_a_real_
    dir_xyz123" is not guaranteed absent on every platform (on Windows it
    resolves relative to the current drive, not a filesystem root) and
    doesn't honor this module's own "every path comes from tmp_path" rule
    (see module docstring)."""
    missing_dir = tmp_path / "missing-yara-dir"
    assert not missing_dir.exists()
    return _capture(lambda: hunt.cmd_hunt(
        FakeMF(), "yara", verbose=False, yara_dir=str(missing_dir))["yara"])


def yara_detected(tmp_path: Path):
    """One rule with a literal string match in a scanned segment -> score 1,
    DETECTED (adapted from tests/hunt/test_yara_hunt.py::test_matching_rule_is_detected).
    Requires yara-python — the calling test must `pytest.importorskip("yara")`
    itself before calling this, the same way tests/hunt/test_yara_hunt.py
    does; this function takes no `monkeypatch` because it patches no module
    attribute (yara rule compilation reads real files under `tmp_path`)."""
    seg_va, seg_fo = 0x50000, 0x5000
    data = b"A" * 0x100 + b"FINDME_MARKER" + b"B" * 0x100
    (tmp_path / "hit.yar").write_text(
        'rule HitRule { strings: $a = "FINDME_MARKER" condition: $a }')
    seg = Segment(seg_va, seg_fo, len(data))

    class MF(FakeMF):
        memory_segments_64 = FakeStream([seg], "memory_segments")
        _reader                = FakeReader({seg_va: data})
    return _capture(lambda: hunt.cmd_hunt(MF(), "yara", verbose=False, yara_dir=str(tmp_path))["yara"])


# ── obfuscation (encoding) ──────────────────────────────────────────────

def obfuscation_detected_validated_pe(monkeypatch):
    """A Base64-encoded, structurally-valid PE payload -> score 1, the only
    scored obfuscation signal besides sleep-mask (adapted from
    tests/hunt/test_encoding.py::test_validated_pe_still_scores)."""
    region_base = 0x300000
    pe_bytes = build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ}],
        size_of_image=0x2000, trailing_padding=0x300)
    b64_pe = base64.b64encode(pe_bytes)
    regions = [Region(region_base, region_base, 0x1000, "MEM_COMMIT", "PAGE_READWRITE", "MEM_PRIVATE")]

    class MF(FakeMF):
        memory_info = FakeStream(regions, "infos")
        modules      = FakeStream([], "modules")
    monkeypatch.setattr(encoding, "read_region", mem_reader({region_base: b64_pe.ljust(0x1000, b"\x00")}))
    return _capture(lambda: encoding._hunt_encoding(MF(), verbose=False))
