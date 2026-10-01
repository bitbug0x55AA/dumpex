"""
Compatibility-freeze suite for `--diff`, the two-dump counterpart to
tests/integration/test_compat_freeze.py's seven single-dump commands.

Every scenario runs the real `cli.main()` end to end (two FakeMF-backed
dumps opened via a PATH-AWARE `open_dump` fake -- unlike every other
integration test's path-ignoring lambda, since --diff opens two distinct
files) and asserts exit code, the full console text, and the JSON
document's kind/coverage/evidence shape. A representative subset also
schema validity against dumpex-output-v2.8.schema.json.

Two buckets:

  - TRUE_FREEZE: ordinary module, thread and memory comparisons whose
    sides are both readable.
  - NEW_BEHAVIOR: states that need a reason to read correctly -- anonymous
    modules colliding on one name key, an unknown start address, and
    absent or failed (SourceState.FAILED) sources. Each scenario's comment
    states the rule it pins.

Every scenario's console states inventory relations ("only in", "different
base address", "protection differs"), never history, and opens with the
comparison premise block (see _PREMISE_NOT_ESTABLISHED).

FAILED is genuinely reachable for --diff, same as it now is for
--sysinfo/--handles/--profile (unlike --list/--modules/--threads, which
never wrap their own single primary stream read in try/except -- see
dumpex.output.coverage.SourceState's own comment) because comparing two
independently-read dumps means one side's read can raise without the
other side being at fault at all.
"""
import datetime
import json
import os
import sys

import pytest

import dumpex.cli as cli
import dumpex.output.collector as collector_mod
from dumpex.output.envelope import SCHEMA_VERSION
from minidump.streams.SystemInfoStream import PROCESSOR_ARCHITECTURE

from tests.fixtures.fakes import (
    FakeMF, Module, ThreadInfo, Region, FakeStream, FakeHeader, MiscInfo, Peb, SysInfo,
    Segment, build_pe_header,
)
from tests.unit.test_process_cmd import _FakeBufferedReader, _FakeReader, _mf as _process_mf


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class _FrozenDateTimeModule:
    """See test_compat_freeze.py's identical helper for why the whole
    `datetime` module is replaced rather than patching `.now` in place --
    both cli.py and collector.py `import datetime` (the module)."""
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def _run(monkeypatch, tmp_path, argv, mf_baseline, mf_target):
    monkeypatch.setattr(cli, "datetime", _FrozenDateTimeModule)
    monkeypatch.setattr(collector_mod, "datetime", _FrozenDateTimeModule)
    baseline_path = str(tmp_path / "baseline.dmp")
    target_path = str(tmp_path / "target.dmp")
    for p in (baseline_path, target_path):
        with open(p, "wb") as fh:
            fh.write(b"synthetic dump content")
    mf_baseline.filename = baseline_path
    mf_target.filename = target_path
    mfs = {baseline_path: mf_baseline, target_path: mf_target}
    monkeypatch.setattr(cli, "open_dump", lambda path: mfs[path])
    out_json = str(tmp_path / "out.json")
    # CLI contract: the positional dump is the target under analysis;
    # --diff supplies its baseline/reference.
    monkeypatch.setattr(sys, "argv",
                         ["dumpex", target_path, "--diff", baseline_path, *argv,
                          "--json", out_json, "--force"])
    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    console = os.path.basename(target_path), os.path.basename(baseline_path)
    return exit_code, doc, console


# The premise block every scenario below renders: their FakeMFs carry no
# header, MiscInfo, SystemInfo, thread list or PEB, so every stream source
# is absent, the PEB was never reconstructed, and nothing can be located at
# a PEB image base.
_PREMISE_NOT_ESTABLISHED = (
    "\n═══ COMPARISON PREMISE ═══\n"
    "  Scope: inventory relations between two captures — "
    "not observed load, unload, rebase or protection events\n"
    "  Process instance: not established\n"
    "  Capture order: not established\n"
    "  Same: none\n"
    "  Differs: none\n"
    "  Not established:\n"
    "      source absent in both captures: capture time, process ID, process create time, "
    "host architecture, OS version\n"
    "      PEB image base unknown in both captures: image machine, module image path, "
    "module image size, module image timestamp\n"
    "      PEB not reconstructed (SystemInfo or thread list unavailable) in both captures: "
    "PEB image path\n"
    "  Within one capture: no identity disagreement\n"
)


def _wrap(label_a: str, label_b: str, body: str) -> str:
    return (f"\ndumpex diff: target {label_a} vs baseline {label_b}\n"
            + "─" * 60 + "\n" + _PREMISE_NOT_ESTABLISHED + body + "\n")


# ── scenario builders (fresh FakeMF pair per invocation) ──────────────────

def _mf_modules(mods):
    mf = FakeMF()
    mf.modules = FakeStream(mods, "modules")
    return mf


def _mf_threads(infos, modules=None):
    mf = FakeMF()
    mf.thread_info = FakeStream(infos, "infos")
    if modules is not None:
        mf.modules = FakeStream(modules, "modules")
    return mf


def _mf_memory(regions):
    mf = FakeMF()
    mf.memory_info = FakeStream(regions, "infos")
    return mf


class _ExplodingModulesMF(FakeMF):
    @property
    def modules(self):
        raise RuntimeError("modules boom")

    @modules.setter
    def modules(self, value):
        pass


class _ExplodingThreadInfoMF(FakeMF):
    @property
    def thread_info(self):
        raise RuntimeError("thread_info boom")

    @thread_info.setter
    def thread_info(self, value):
        pass


class _ExplodingMemoryInfoMF(FakeMF):
    @property
    def memory_info(self):
        raise RuntimeError("memory_info boom")

    @memory_info.setter
    def memory_info(self, value):
        pass


# ── TRUE_FREEZE: both sides readable ─────────────────────────────────────
# (name, diff_args, mf_baseline, mf_target, exit_code, console_body)

TRUE_FREEZE = [
    (
        "module_added_removed_rebased", ["--diff-scope", "modules"],
        _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll")]),
        _mf_modules([Module(0x9000, 0x1000, r"C:\a.dll"), Module(0x3000, 0x1000, r"C:\c.dll")]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 2 modules\n  target.dmp: 2 modules\n\n'
        '  [+] Only in target.dmp (1):\n      0x0000000000003000  C:\\c.dll\n\n'
        '  [-] Only in baseline.dmp (1):\n      0x0000000000002000  C:\\b.dll\n\n'
        '  [~] Different base address (1):\n      a.dll: baseline 0x1000, target 0x9000\n',
    ),
    (
        "module_rebased_cross_directory", ["--diff-mode", "modules"],
        _mf_modules([Module(0x1000, 0x1000, r"C:\Program Files\App\a.dll")]),
        _mf_modules([Module(0x9000, 0x1000, r"C:\Windows\System32\a.dll")]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 1 modules\n  target.dmp: 1 modules\n\n'
        '  [+] No modules only in target.dmp.\n\n  [-] No modules only in baseline.dmp.\n\n'
        '  [~] Different base address (1):\n      a.dll: baseline 0x1000, target 0x9000\n',
    ),
    (
        "module_anonymous_added", ["--diff-mode", "modules"],
        _mf_modules([]), _mf_modules([Module(0x1000, 0x1000, None)]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 0 modules\n  target.dmp: 1 modules\n\n'
        '  [+] Only in target.dmp (1):\n      0x0000000000001000  None\n\n'
        '  [-] No modules only in baseline.dmp.\n',
    ),
    (
        "module_anonymous_removed", ["--diff-mode", "modules"],
        _mf_modules([Module(0x1000, 0x1000, None)]), _mf_modules([]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 1 modules\n  target.dmp: 0 modules\n\n'
        '  [+] No modules only in target.dmp.\n\n'
        '  [-] Only in baseline.dmp (1):\n      0x0000000000001000  None\n',
    ),
    (
        "thread_added_resolved", ["--diff-mode", "threads"],
        _mf_threads([]),
        _mf_threads([ThreadInfo(2, 0x5000)], modules=[Module(0x5000, 0x1000, "legit.dll")]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] TIDs only in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: legit.dll\n\n'
        '  [-] No TIDs only in baseline.dmp.\n',
    ),
    (
        "thread_added_unregistered_known_address", ["--diff-mode", "threads"],
        _mf_threads([]),
        _mf_threads([ThreadInfo(2, 0x9999)], modules=[Module(0x1000, 0x1000, "legit.dll")]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] TIDs only in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x9999  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No TIDs only in baseline.dmp.\n',
    ),
    (
        "thread_removed", ["--diff-mode", "threads"],
        _mf_threads([ThreadInfo(1, 0x1000)]), _mf_threads([]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 1 threads\n  target.dmp: 0 threads\n\n'
        '  [+] No TIDs only in target.dmp.\n\n'
        '  [-] TIDs only in baseline.dmp (1):\n      TID=0x1  StartAddr=0x1000\n',
    ),
    (
        "memory_added_rwx", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n'
        '  [!] RWX regions only in target.dmp (1) — HIGH SUSPICION:\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READWRITE'
        '           ◄ RWX! [PRIVATE]\n\n  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_protection_changed_to_rwx", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [~] Protection differs at the same base (1):\n'
        '      0x0000000000001000  baseline PAGE_READWRITE, target PAGE_EXECUTE_READWRITE'
        ' ◄ RWX in target!\n',
    ),
    (
        "memory_no_changes", ["--diff-mode", "memory"],
        _mf_memory([]), _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 0 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_added_exec", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READ", "MEM_IMAGE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [+] Executable regions only in target.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READ                [EXEC]\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_added_notable_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_added_notable_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [+] Other notable regions only in target.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_READWRITE                   [PRIVATE]\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_added_noise_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [·] 1 routine regions only in target.dmp hidden '
        '(read-only, no-access and other non-executable protections).\n'
        '      Use --verbose to show all.\n\n  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_added_noise_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 1 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [+] Routine regions only in target.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_READONLY\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_removed_exec", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READ", "MEM_IMAGE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 1 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [-] Executable regions only in baseline.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READ                [EXEC]\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_removed_other_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 1 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [·] 1 non-executable regions only in baseline.dmp hidden. '
        'Use --verbose to show all.\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_removed_other_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 1 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [-] Other regions only in baseline.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_READWRITE\n\n'
        '  [~] No protection differences at shared bases.\n',
    ),
    (
        "memory_protection_changed_benign", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 1 regions\n'
        '  Base addresses in one capture only: 0 in target.dmp, 0 in baseline.dmp\n'
        '\n  [!] No RWX regions only in target.dmp.\n\n'
        '  [~] Protection differs at the same base (1):\n'
        '      0x0000000000001000  baseline PAGE_READONLY, target PAGE_READWRITE\n',
    ),
]


# ── NEW_BEHAVIOR: no old ground truth -- see this file's module docstring ─

NEW_BEHAVIOR = [
    (
        "module_anonymous_collision",
        # Old diff_modules keyed anonymous modules by module_name_only(m.name)
        # == "" for every one of them, so {"": m for m in ...} silently kept
        # only the LAST anonymous module and dropped the rest -- a real bug,
        # fixed at the domain layer by comparison.py's own
        # _module_match_key() (address-qualified fallback key). Both
        # anonymous modules must appear here; neither may be dropped.
        ["--diff-mode", "modules"],
        _mf_modules([]),
        _mf_modules([Module(0x1000, 0x1000, None), Module(0x2000, 0x1000, None)]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 0 modules\n  target.dmp: 2 modules\n\n'
        '  [+] Only in target.dmp (2):\n'
        '      0x0000000000001000  None\n      0x0000000000002000  None\n\n'
        '  [-] No modules only in baseline.dmp.\n',
    ),
    (
        "thread_added_target_modules_absent",
        # Old diff_threads called get_modules(mf_b) UNCONDITIONALLY (never
        # checked presence) and printed the identical "NOT IN ANY MODULE ⚠"
        # for this case as for a confirmed-unregistered thread -- the new
        # model still prints the same text (backing_module_context conflates
        # unregistered/unavailable/unknown-address in this renderer, a
        # deliberate design choice -- see diff.py's own docstring), but now
        # ALSO surfaces the fact structurally via a coverage reason line and
        # PARTIAL status, which old code had no way to express at all.
        ["--diff-mode", "threads"],
        _mf_threads([]),
        FakeMF(),   # thread_info set below (needs no modules stream at all)
        3,
        '\n═══ THREAD DIFF ═══\n'
        '  [~] target ModuleListStream not present; backing_module_after/'
        'backing_module_context unavailable\n'
        '  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] TIDs only in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No TIDs only in baseline.dmp.\n',
    ),
    (
        "thread_added_start_address_none",
        # Old diff_threads folded a None StartAddress to 0 (`sa = ti.
        # StartAddress or 0`) and fed that fabricated 0 into addr_to_module()
        # -- comparison.py's collect_thread_diff deliberately never does
        # this (see its own docstring: coercing to 0 could fabricate a
        # confirmed MODULE_CONTEXT_UNREGISTERED for an address that was
        # simply never known). start_address_after/backing_module_context
        # stay null; the console's own "0x0" fold happens only at RENDER
        # time (see diff.py's _int_or()), reproducing old's printed text
        # for this one line without reproducing old's data-model bug.
        ["--diff-mode", "threads"],
        _mf_threads([]),
        _mf_threads([ThreadInfo(2, None)], modules=[Module(0x1000, 0x1000, "legit.dll")]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] TIDs only in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x0  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No TIDs only in baseline.dmp.\n',
    ),
    (
        "module_target_read_failure",
        # SourceState.FAILED -- reserved since Phase 0, unreachable by any
        # command before this migration (see this file's module docstring).
        # A required side FAILED means the diff was never attempted at all:
        # its count shows N/A, and the section stops right there --
        # printing "No new modules."/"No removed modules." here would read
        # as "compared, found nothing," not "never compared" (this is the
        # exact bug _entity_not_evaluated()/_count_or_na() in diff.py fix).
        ["--diff-mode", "modules"],
        _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll")]),
        _ExplodingModulesMF(),
        3,
        '\n═══ MODULE DIFF ═══\n'
        '  [~] target ModuleListStream present but could not be read: modules boom\n'
        '  baseline.dmp: 1 modules\n  target.dmp: N/A modules\n\n'
        '  Comparison not evaluated.\n',
    ),
    (
        "thread_baseline_read_failure",
        ["--diff-mode", "threads"],
        _ExplodingThreadInfoMF(),
        _mf_threads([ThreadInfo(2, 0x5000)], modules=[Module(0x5000, 0x1000, "legit.dll")]),
        3,
        '\n═══ THREAD DIFF ═══\n'
        '  [~] baseline ThreadInfoListStream present but could not be read: '
        'thread_info boom\n'
        '  baseline.dmp: N/A threads\n  target.dmp: 1 threads\n\n'
        '  Comparison not evaluated.\n',
    ),
    (
        "memory_target_read_failure",
        ["--diff-mode", "memory"],
        _mf_memory([]),
        _ExplodingMemoryInfoMF(),
        3,
        '\n═══ MEMORY REGION DIFF ═══\n'
        '  [~] target MemoryInfoListStream present but could not be read: '
        'memory_info boom\n'
        '  baseline.dmp: 0 regions\n  target.dmp: N/A regions\n\n'
        '  Comparison not evaluated.\n',
    ),
    (
        "module_baseline_absent_target_present",
        # ABSENT (not just FAILED) is the other required-source-missing
        # state the same guard covers: baseline.modules is entirely
        # absent, target genuinely has one real module -- that module was
        # never actually compared against anything, so it must not be
        # silently paired with a false "No removed modules." into looking
        # like a completed, clean comparison. Exit code here is
        # not_evaluated (4), unlike the FAILED scenarios above (partial,
        # 3) -- a plain ABSENT required source is exactly what
        # NOT_EVALUATED already meant before this review round; only the
        # console's wording was wrong.
        ["--diff-mode", "modules"],
        FakeMF(),   # ModuleListStream absent entirely
        _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll")]),
        4,
        '\n═══ MODULE DIFF ═══\n'
        '  [~] baseline ModuleListStream not present in this dump\n'
        '  baseline.dmp: N/A modules\n  target.dmp: 1 modules\n\n'
        '  Comparison not evaluated.\n',
    ),
    (
        "thread_target_modules_failed_shows_reason_above_not_in_any_module",
        # target.modules is an OPTIONAL enrichment for thread diff (see
        # collect_thread_diff's own SourceRequirement(scope="thread",
        # unavailable_fields=(...))) -- a FAILED read there degrades
        # backing-module resolution rather than aborting the whole thread
        # diff, so the added thread record still renders with the SAME
        # "NOT IN ANY MODULE ⚠" text a confirmed-unregistered thread gets
        # (a deliberate, already-reviewed conflation -- see diff.py's own
        # docstring; not changed here). What WAS a real bug (fixed by this
        # scenario) is that the read-failure reason above it never
        # rendered at all: the limitation's scope was hardcoded to "dump"
        # instead of the requirement's own "thread", so render_thread_
        # diff's scope=="thread" filter silently dropped it. It must now
        # appear, so a reader is never left thinking "confirmed
        # unregistered" when the real fact is "couldn't check."
        ["--diff-mode", "threads"],
        _mf_threads([]),
        _ExplodingModulesMF(),   # thread_info patched in below, modules raises
        3,
        '\n═══ THREAD DIFF ═══\n'
        '  [~] target ModuleListStream present but could not be read: modules boom; '
        'backing_module_after/backing_module_context unavailable\n'
        '  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] TIDs only in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No TIDs only in baseline.dmp.\n',
    ),
]
# thread_added_target_modules_absent's target FakeMF needs thread_info set
# without also getting a `modules` attribute at all (ModuleListStream
# absent, not merely empty) -- can't express that via _mf_threads(modules=
# None) inline above without ALSO skipping thread_info, so it's patched
# in here.
NEW_BEHAVIOR[1][3].thread_info = FakeStream([ThreadInfo(2, 0x5000)], "infos")
# thread_target_modules_failed_shows_reason_above_not_in_any_module's
# target _ExplodingModulesMF needs thread_info set too -- constructing it
# with the keyword wouldn't work since `modules` is a raising @property,
# not a plain attribute FakeStream can populate via **kwargs.
NEW_BEHAVIOR[-1][3].thread_info = FakeStream([ThreadInfo(2, 0x5000)], "infos")


ALL_SCENARIOS = TRUE_FREEZE + NEW_BEHAVIOR


@pytest.mark.parametrize(
    "name,diff_args,mf_baseline,mf_target,exit_code,console_body",
    ALL_SCENARIOS, ids=[s[0] for s in ALL_SCENARIOS],
)
def test_diff_compat_freeze(monkeypatch, tmp_path, capsys, name, diff_args, mf_baseline,
                             mf_target, exit_code, console_body):
    actual_exit, doc, (label_a, label_b) = _run(
        monkeypatch, tmp_path, diff_args, mf_baseline, mf_target)
    actual_console = capsys.readouterr().out
    # Only the JSON write-confirmation line is stripped --
    # they embed the per-test tmp directory and, a content hash;
    # everything else is asserted verbatim, same discipline as
    # test_compat_freeze.py's own suite.
    write_lines_start = actual_console.find("  [\u00b7] JSON written")
    assert write_lines_start != -1, f"{name}: missing JSON write confirmation line"
    actual_body = actual_console[:write_lines_start]

    assert actual_exit == exit_code, f"{name}: exit code drifted"
    assert actual_body == _wrap(label_a, label_b, console_body), f"{name}: console drifted"

    assert doc["meta"]["schema_version"] == SCHEMA_VERSION
    assert [e["id"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
    assert [e["role"] for e in doc["meta"]["evidence"]] == ["baseline", "target"]
    assert [e["file_name"] for e in doc["meta"]["evidence"]] == [label_b, label_a]
    assert doc["result"]["kind"] == "comparison"
    expected_status = {0: "complete", 3: "partial", 4: "not_evaluated"}[exit_code]
    assert doc["result"]["coverage"]["status"] == expected_status, \
        f"{name}: coverage.status didn't match exit code"


# ── modules/threads/memory=="all" combined run + JSON Schema validation ───

def test_diff_mode_all_combines_three_entities_and_validates_against_schema(
        monkeypatch, tmp_path, capsys):
    jsonschema = pytest.importorskip("jsonschema")
    from dumpex.schemas import CURRENT_SCHEMA, schema_path

    mf_baseline = _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll")])
    mf_baseline.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_baseline.memory_info = FakeStream(
        [Region(0x2000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_READONLY", "MEM_PRIVATE")], "infos")

    mf_target = _mf_modules(
        [Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x3000, 0x1000, r"C:\c.dll")])
    mf_target.thread_info = FakeStream([ThreadInfo(1, 0x1000)], "infos")
    mf_target.memory_info = FakeStream(
        [Region(0x2000, 0x1000, 0x1000, "MEM_COMMIT", "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")],
        "infos")

    exit_code, doc, (label_a, label_b) = _run(
        monkeypatch, tmp_path, [], mf_baseline, mf_target)
    console = capsys.readouterr().out

    assert exit_code == 0
    assert doc["result"]["coverage"]["status"] == "complete"
    kinds = sorted({r["entity_type"] for r in doc["result"]["data"]["records"]})
    assert kinds == ["memory_region", "module"]   # thread has no add/remove here
    assert "═══ MODULE DIFF ═══" in console
    assert "═══ THREAD DIFF ═══" in console
    assert "═══ MEMORY REGION DIFF ═══" in console

    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(doc)



def test_diff_mode_all_shows_shared_target_modules_failure_in_both_sections(
        monkeypatch, tmp_path, capsys):
    # target.modules is read independently by BOTH module diff (its own
    # primary source) and thread diff (an optional enrichment source) --
    # when it FAILS, each collector derives its own CoverageLimitation
    # (scope="dump" for module diff, scope="thread"+unavailable_fields for
    # thread diff). These must stay two distinct facts, each printed under
    # its OWN section -- not collapsed into one by combine_coverage_
    # reports' dedup (which only removes byte-identical limitations), and
    # not cross-leaked into the wrong section (module's own filter
    # excludes scope=="thread"; thread's own filter requires it).
    mf_baseline = _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll")])
    mf_baseline.thread_info = FakeStream([], "infos")
    mf_target = _ExplodingModulesMF()
    mf_target.thread_info = FakeStream([ThreadInfo(2, 0x5000)], "infos")

    exit_code, doc, (label_a, label_b) = _run(
        monkeypatch, tmp_path, ["--diff-mode", "all"], mf_baseline, mf_target)
    console = capsys.readouterr().out

    assert exit_code == 3
    assert doc["result"]["coverage"]["status"] == "partial"
    failed = [l for l in doc["result"]["coverage"]["limitations"] if l["code"] == "SOURCE_FAILED"]
    assert len(failed) == 2, "module diff's and thread diff's own target.modules " \
        "failures must both survive as distinct facts, not be deduplicated"
    assert {l["scope"] for l in failed} == {"dump", "thread"}

    module_section, _, rest = console.partition("═══ THREAD DIFF ═══")
    thread_section, _, memory_section = rest.partition("═══ MEMORY REGION DIFF ═══")
    assert "target ModuleListStream present but could not be read: modules boom\n" \
        in module_section
    assert "target ModuleListStream present but could not be read: modules boom; " \
        "backing_module_after/backing_module_context unavailable" in thread_section
    # The module section's own (undifferentiated) reason must not also
    # leak into the thread section, and vice versa.
    assert "backing_module_after/backing_module_context unavailable" not in module_section
    assert module_section.count("target ModuleListStream present but could not be read") == 1
    assert thread_section.count("target ModuleListStream present but could not be read") == 1


# ── comparison premise: console and --json agree; nothing is rejected ─────

_IMAGE_BASE = 0x00007FF600010000
_TEXT_SECTION = {"name": b".text", "vaddr": 0x1000, "vsize": 0x100, "rawptr": 0x400,
                 "rawsize": 0x200, "chars": 0x60000020}


def _identified(*, capture, pid, build, peb_path, module_path=None, modules=()):
    """A capture establishing every premise fact, its main image header
    captured at the PEB image base."""
    main = Module(_IMAGE_BASE, 0x5000, module_path or peb_path)
    main.timestamp = 0x5F5E1000
    mf = _process_mf(misc_info=MiscInfo(process_id=pid, process_create_time=1_700_000_000),
                     peb=Peb(_IMAGE_BASE, peb_path), modules=[main, *modules],
                     memory={_IMAGE_BASE: build_pe_header([_TEXT_SECTION])})
    mf.header = FakeHeader(capture)
    mf.sysinfo = SysInfo(build_number=build, processor_architecture=PROCESSOR_ARCHITECTURE.AMD64)
    return mf


def _premise_block(console: str) -> str:
    return console.split("═══ COMPARISON PREMISE ═══\n", 1)[1].split("\n\n", 1)[0]


def test_unrelated_differing_build_comparison_keeps_its_records_and_exit_code(
        monkeypatch, tmp_path, capsys):
    jsonschema = pytest.importorskip("jsonschema")
    from dumpex.schemas import CURRENT_SCHEMA, schema_path

    baseline = _identified(capture=1_700_000_200, pid=100, build=19041,
                           peb_path="C:\\one\\one.exe",
                           modules=[Module(0x1000, 0x1000, "C:\\a.dll")])
    target = _identified(capture=1_700_000_100, pid=200, build=22631,
                         peb_path="C:\\two\\two.exe",
                         modules=[Module(0x2000, 0x1000, "C:\\a.dll")])
    exit_code, doc, _labels = _run(monkeypatch, tmp_path, ["--diff-scope", "modules"],
                                   baseline, target)
    console = capsys.readouterr().out

    assert exit_code == 0
    assert doc["result"]["coverage"]["status"] == "complete"
    assert doc["result"]["coverage"]["limitations"] == []
    assert {(r["change_type"], r["name"]) for r in doc["result"]["data"]["records"]} == {
        ("added", "two.exe"), ("removed", "one.exe"), ("rebased", "a.dll")}

    premise = doc["result"]["summary"]["premise"]
    assert premise["process_instance"] == "different"
    assert premise["capture_order"] == "target_first"
    assert premise["known_differences"] == [
        "capture_time", "process_id", "os_version", "peb_image_path", "module_image_path"]
    assert premise["unknown_premises"] == []
    assert premise["capture_diagnostics"] == []

    assert _premise_block(console) == (
        "  Scope: inventory relations between two captures — "
        "not observed load, unload, rebase or protection events\n"
        "  Process instance: different\n"
        "  Capture order: target captured first\n"
        "  Same: process create time, host architecture, image machine, module image size, "
        "module image timestamp\n"
        "  Differs:\n"
        "      capture time: 2023-11-14 22:16:40 UTC (baseline) / "
        "2023-11-14 22:15:00 UTC (target)\n"
        "      process ID: 100 (baseline) / 200 (target)\n"
        "      OS version: 10.0.19041 (baseline) / 10.0.22631 (target)\n"
        "      PEB image path: C:\\one\\one.exe (baseline) / C:\\two\\two.exe (target)\n"
        "      module image path: C:\\one\\one.exe (baseline) / C:\\two\\two.exe (target)\n"
        "  Not established: none\n"
        "  Within one capture: no identity disagreement")
    assert "  [~] Different base address (1):\n" \
           "      a.dll: baseline 0x1000, target 0x2000\n" in console

    with schema_path(CURRENT_SCHEMA) as path, open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft202012Validator(schema).validate(doc)


def test_same_instance_comparison_states_the_premise_it_rests_on(
        monkeypatch, tmp_path, capsys):
    baseline = _identified(capture=1_700_000_100, pid=4660, build=19041,
                           peb_path="C:\\app\\app.exe")
    target = _identified(capture=1_700_000_200, pid=4660, build=19041,
                         peb_path="C:\\app\\app.exe")
    target.modules.modules[0].timestamp = 0   # not set by the producer
    exit_code, doc, _labels = _run(monkeypatch, tmp_path, ["--diff-scope", "modules"],
                                   baseline, target)
    console = capsys.readouterr().out

    assert exit_code == 0
    premise = doc["result"]["summary"]["premise"]
    assert premise["process_instance"] == "same"
    assert premise["unknown_premises"] == ["module_image_timestamp"]
    block = _premise_block(console)
    assert ("  Process instance: same PID and creation time (PID 4660, created "
            "2023-11-14 22:13:20 UTC); host identity not established\n") in block
    assert "  Capture order: baseline captured first\n" in block
    assert block.endswith("  Not established:\n"
                          "      module image timestamp: 0x5f5e1000 (baseline) / "
                          "not set (target)\n"
                          "  Within one capture: no identity disagreement")


def test_peb_masquerade_is_disclosed_in_console_and_json(monkeypatch, tmp_path, capsys):
    baseline = _identified(capture=1_700_000_100, pid=4660, build=19041,
                           peb_path="C:\\Windows\\System32\\svchost.exe")
    target = _identified(capture=1_700_000_200, pid=4661, build=19041,
                         peb_path="C:\\Windows\\System32\\svchost.exe",
                         module_path="C:\\ProgramData\\Cache\\evil.exe")
    exit_code, doc, _labels = _run(monkeypatch, tmp_path, ["--diff-scope", "modules"],
                                   baseline, target)
    console = capsys.readouterr().out

    assert exit_code == 0
    premise = doc["result"]["summary"]["premise"]
    assert "module_image_path" in premise["known_differences"]
    assert "peb_image_path" not in premise["known_differences"]
    assert [(d["side"], d["code"]) for d in premise["capture_diagnostics"]] == [
        ("target", "PROCESS_MODULE_IDENTITY_MISMATCH")]
    block = _premise_block(console)
    assert ("      module image path: C:\\Windows\\System32\\svchost.exe (baseline) / "
            "C:\\ProgramData\\Cache\\evil.exe (target)\n") in block
    assert block.endswith(
        "  Within one capture:\n"
        "      target: PEB image path basename (svchost.exe) disagrees with the matched "
        "module's own name (evil.exe) [PROCESS_MODULE_IDENTITY_MISMATCH]")


def test_render_refuses_a_comparison_result_without_a_premise():
    from dumpex.commands.comparison import collect_comparison
    from dumpex.commands.diff import render_diff_console

    result = collect_comparison(_mf_modules([]), _mf_modules([]), mode="modules")
    del result.summary["premise"]
    with pytest.raises(ValueError, match="premise"):
        render_diff_console(result, "baseline.dmp", "target.dmp")


def test_console_wording_covers_every_fact_and_state():
    from dumpex.commands import diff
    from dumpex.output.records import COMPARISON_FACTS, COMPARISON_FACT_STATES

    assert list(diff._FACT_LABELS) == list(COMPARISON_FACTS)
    assert set(diff._STATE_TEXT) == set(COMPARISON_FACT_STATES) - {"recorded"}


def test_invalid_header_at_the_image_base_is_disclosed_not_unset(monkeypatch, tmp_path, capsys):
    baseline = _identified(capture=1_700_000_100, pid=4660, build=19041,
                           peb_path="C:\\app\\app.exe")
    target = _identified(capture=1_700_000_200, pid=4660, build=19041,
                         peb_path="C:\\app\\app.exe")
    zeros = b"\x00" * 0x400
    target.memory_segments_64 = FakeStream([Segment(_IMAGE_BASE, _IMAGE_BASE, len(zeros))],
                                           "memory_segments")
    target.get_reader = lambda: _FakeReader(_FakeBufferedReader({_IMAGE_BASE: zeros}))
    exit_code, doc, _labels = _run(monkeypatch, tmp_path, ["--diff-scope", "modules"],
                                   baseline, target)
    block = _premise_block(capsys.readouterr().out)

    assert exit_code == 0
    machine = doc["result"]["summary"]["premise"]["facts"][5]
    assert (machine["fact"], machine["target_state"]) == ("image_machine", "invalid")
    assert ("      image machine: AMD64 (baseline) / not a valid PE header (target)\n"
            in block)
    assert "not set" not in block
    assert block.split("  Within one capture:\n", 1)[1].startswith(
        "      target: the bytes captured at the PEB image base (0x00007ff600010000) are not "
        "a valid PE header: ")
    assert block.endswith("[PROCESS_MAIN_IMAGE_PE_INVALID]")


def test_missing_peb_does_not_call_the_module_list_absent(monkeypatch, tmp_path, capsys):
    baseline = _identified(capture=1_700_000_100, pid=4660, build=19041,
                           peb_path="C:\\app\\app.exe")
    target = _identified(capture=1_700_000_200, pid=4660, build=19041,
                         peb_path="C:\\app\\app.exe")
    target.peb = None   # its ModuleListStream is still present
    _run(monkeypatch, tmp_path, ["--diff-scope", "modules"], baseline, target)
    block = _premise_block(capsys.readouterr().out)

    assert "source absent" not in block
    assert ("      module image path: C:\\app\\app.exe (baseline) / "
            "PEB image base unknown (target)\n") in block
    assert ("      PEB image path: C:\\app\\app.exe (baseline) / "
            "PEB not reconstructed (SystemInfo or thread list unavailable) (target)\n") in block
