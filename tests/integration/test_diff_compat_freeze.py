"""
Compatibility-freeze suite for `--diff`, the two-dump counterpart to
tests/integration/test_compat_freeze.py's six single-dump commands.

Every scenario runs the real `cli.main()` end to end (two FakeMF-backed
dumps opened via a PATH-AWARE `open_dump` fake -- unlike every other
integration test's path-ignoring lambda, since --diff opens two distinct
files) and asserts exit code, the full console text, and the JSON
document's kind/coverage/evidence shape. A representative subset also
schema validity against dumpex-output-v2.8.schema.json.

Two buckets, per Phase D's plan:

  - TRUE_FREEZE: scenarios the original diff_modules/diff_threads/
    diff_memory console had a real, correct behavior for -- expected
    console text was captured by actually running that original code
    (see the scratchpad capture script referenced in the Phase D plan)
    before diff.py was rewritten, not hand-guessed.
  - NEW_BEHAVIOR: scenarios the original console either mishandled (two
    anonymous modules colliding on one dict key, silently dropping all
    but the last) or never had ground truth for at all (SourceState.FAILED
    -- reserved since Phase 0, never exercised by any command before this
    migration). Expected text here is freshly derived from the new,
    deliberately-changed behavior, not frozen from old output -- each
    scenario's comment says why.

FAILED is genuinely reachable for --diff (unlike the six single-dump
commands, which never wrap their stream reads in try/except -- see
test_compat_freeze.py's own module docstring) because comparing two
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
from tests.fixtures.fakes import FakeMF, Module, ThreadInfo, Region, FakeStream


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


def _wrap(label_a: str, label_b: str, body: str) -> str:
    return (f"\ndumpex diff: target {label_a} vs baseline {label_b}\n"
            + "─" * 60 + "\n" + body + "\n")


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


# ── TRUE_FREEZE: expected console text captured from the original
# diff_modules/diff_threads/diff_memory before diff.py's Phase D rewrite ──
# (name, diff_args, mf_baseline, mf_target, exit_code, console_body)

TRUE_FREEZE = [
    (
        "module_added_removed_rebased", ["--diff-scope", "modules"],
        _mf_modules([Module(0x1000, 0x1000, r"C:\a.dll"), Module(0x2000, 0x1000, r"C:\b.dll")]),
        _mf_modules([Module(0x9000, 0x1000, r"C:\a.dll"), Module(0x3000, 0x1000, r"C:\c.dll")]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 2 modules\n  target.dmp: 2 modules\n\n'
        '  [+] Added in target.dmp (1):\n      0x0000000000003000  C:\\c.dll\n\n'
        '  [-] Removed from baseline.dmp (1):\n      0x0000000000002000  C:\\b.dll\n\n'
        '  [~] Rebased (1):\n      a.dll: 0x1000 → 0x9000\n',
    ),
    (
        "module_rebased_cross_directory", ["--diff-mode", "modules"],
        _mf_modules([Module(0x1000, 0x1000, r"C:\Program Files\App\a.dll")]),
        _mf_modules([Module(0x9000, 0x1000, r"C:\Windows\System32\a.dll")]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 1 modules\n  target.dmp: 1 modules\n\n'
        '  [+] No new modules.\n\n  [-] No removed modules.\n\n'
        '  [~] Rebased (1):\n      a.dll: 0x1000 → 0x9000\n',
    ),
    (
        "module_anonymous_added", ["--diff-mode", "modules"],
        _mf_modules([]), _mf_modules([Module(0x1000, 0x1000, None)]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 0 modules\n  target.dmp: 1 modules\n\n'
        '  [+] Added in target.dmp (1):\n      0x0000000000001000  None\n\n'
        '  [-] No removed modules.\n',
    ),
    (
        "module_anonymous_removed", ["--diff-mode", "modules"],
        _mf_modules([Module(0x1000, 0x1000, None)]), _mf_modules([]),
        0,
        '\n═══ MODULE DIFF ═══\n  baseline.dmp: 1 modules\n  target.dmp: 0 modules\n\n'
        '  [+] No new modules.\n\n'
        '  [-] Removed from baseline.dmp (1):\n      0x0000000000001000  None\n',
    ),
    (
        "thread_added_resolved", ["--diff-mode", "threads"],
        _mf_threads([]),
        _mf_threads([ThreadInfo(2, 0x5000)], modules=[Module(0x5000, 0x1000, "legit.dll")]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] New threads in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: legit.dll\n\n'
        '  [-] No removed threads.\n',
    ),
    (
        "thread_added_unregistered_known_address", ["--diff-mode", "threads"],
        _mf_threads([]),
        _mf_threads([ThreadInfo(2, 0x9999)], modules=[Module(0x1000, 0x1000, "legit.dll")]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 0 threads\n  target.dmp: 1 threads\n\n'
        '  [+] New threads in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x9999  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No removed threads.\n',
    ),
    (
        "thread_removed", ["--diff-mode", "threads"],
        _mf_threads([ThreadInfo(1, 0x1000)]), _mf_threads([]),
        0,
        '\n═══ THREAD DIFF ═══\n  baseline.dmp: 1 threads\n  target.dmp: 0 threads\n\n'
        '  [+] No new threads.\n\n'
        '  [-] Threads gone from target.dmp (1):\n      TID=0x1  StartAddr=0x1000\n',
    ),
    (
        "memory_added_rwx", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n'
        '  [!] RWX regions in target.dmp (1) — HIGH SUSPICION:\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READWRITE'
        '           ◄ RWX! [PRIVATE]\n\n  [~] No protection changes.\n',
    ),
    (
        "memory_protection_changed_to_rwx", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 1 regions\n'
        '  Delta: +0 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [~] Protection changed (1):\n'
        '      0x0000000000001000  PAGE_READWRITE → PAGE_EXECUTE_READWRITE ← now RWX!\n',
    ),
    (
        "memory_no_changes", ["--diff-mode", "memory"],
        _mf_memory([]), _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 0 regions\n'
        '  Delta: +0 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_added_exec", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READ", "MEM_IMAGE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [+] New executable regions in target.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READ                [EXEC]\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_added_notable_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_added_notable_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [+] Other notable new regions (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_READWRITE                   [PRIVATE]\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_added_noise_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [·] 1 routine regions hidden (PAGE_READONLY/NOACCESS from new DLLs).\n'
        '      Use --verbose to show all.\n\n  [~] No protection changes.\n',
    ),
    (
        "memory_added_noise_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 0 regions\n  target.dmp: 1 regions\n'
        '  Delta: +1 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [+] Routine new regions (1) — likely from new DLLs:\n'
        '      0x0000000000001000  size=0x1000      PAGE_READONLY\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_removed_exec", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_EXECUTE_READ", "MEM_IMAGE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Delta: +0 / -1 regions\n\n  [!] No RWX regions added.\n\n'
        '  [-] Executable regions gone from target.dmp (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_EXECUTE_READ                [EXEC]\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_removed_other_nonverbose", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Delta: +0 / -1 regions\n\n  [!] No RWX regions added.\n\n'
        '  [·] 1 removed non-exec regions hidden. Use --verbose to show all.\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_removed_other_verbose", ["--diff-mode", "memory", "--verbose"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        _mf_memory([]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 0 regions\n'
        '  Delta: +0 / -1 regions\n\n  [!] No RWX regions added.\n\n'
        '  [-] Other removed regions (1):\n'
        '      0x0000000000001000  size=0x1000      PAGE_READWRITE\n\n'
        '  [~] No protection changes.\n',
    ),
    (
        "memory_protection_changed_benign", ["--diff-mode", "memory"],
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READONLY", "MEM_PRIVATE")]),
        _mf_memory([Region(0x1000, 0x1000, 0x1000, "MEM_COMMIT",
                            "PAGE_READWRITE", "MEM_PRIVATE")]),
        0,
        '\n═══ MEMORY REGION DIFF ═══\n  baseline.dmp: 1 regions\n  target.dmp: 1 regions\n'
        '  Delta: +0 / -0 regions\n\n  [!] No RWX regions added.\n\n'
        '  [~] Protection changed (1):\n'
        '      0x0000000000001000  PAGE_READONLY → PAGE_READWRITE\n',
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
        '  [+] Added in target.dmp (2):\n'
        '      0x0000000000001000  None\n      0x0000000000002000  None\n\n'
        '  [-] No removed modules.\n',
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
        '  [+] New threads in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No removed threads.\n',
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
        '  [+] New threads in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x0  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No removed threads.\n',
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
        '  [+] New threads in target.dmp (1):\n'
        '      TID=0x2  StartAddr=0x5000  Backed by: NOT IN ANY MODULE ⚠\n\n'
        '  [-] No removed threads.\n',
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

    assert doc["meta"]["schema_version"] == "2.9"
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
    from dumpex.schemas import schema_path

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

    with schema_path("dumpex-output-v2.9.schema.json") as path, open(path, encoding="utf-8") as fh:
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
