"""YARA memory scanner.

Score = number of *distinct rule names* that matched at least once, so
finding 50 instances of one rule still counts as 1.

Address semantics (consistent with the rest of Dumpex):
  VA (process)      — virtual address in the target process
  File offset (.dmp) — byte position inside the .dmp file
  Region base (VA)  — start of the enclosing memory region

Rules directory resolution (when rules_dir is None — pass --yara-dir
for an explicit, deliberate override instead of relying on this):
  1. sys._MEIPASS/rules/yara/         Compatibility with older
                                       PyInstaller builds
  2. dumpex.rules_pkg/data/yara/      Canonical package resource used
                                       by wheels and current PyInstaller
                                       builds (see rules.packaged_yara_rules_dir())

There is deliberately no automatic cwd/script-dir scan: a DFIR working
directory routinely contains untrusted case files, and that scan used
to sit AFTER the packaged-defaults check anyway — which always
succeeds now that YARA rules are bundled in the wheel — making it dead
code that could never actually run. --yara-dir is the explicit,
auditable way to point at a different rules directory.

This is a package, not a single file: rules.py resolves the packaged
rules directory and compiles rule files into a RuleBundle (rule_files +
compile_failed + reproducible provenance), never importing this facade;
context.py owns the PE_In_Private_Memory suppression/classification
policy; scanner.py runs the segment × rule-file match loop and applies
every whole-scan budget, collecting facts only — it never scores or
prints; aggregate.py is the ONE place score/status/coverage_status/
verdict_level get computed (yara_hunt deliberately still uses its own
"matches"/"rules_hit" shape, not the Finding model other phase-two/three
hunters use — this split does not change that); presentation.py is the
ONE place FINAL-RESULT console output gets rendered. This __init__.py is
the thin entry point: it resolves prerequisites (yara-python import,
rules directory, rule compilation, memory segments), prints the header
and in-progress scan announcements, and orchestrates scanner -> aggregate
-> presentation.

The stable contract is `_hunt_yara` and `get_yara_provenance` themselves
(both imported by dumpex/hunt/__init__.py and dumpex/ui/structured.py
respectively): same signatures, same fields, same score/status/coverage/
JSON shape as before this package split — this refactor only changes
internal structure. Tunable constants (YARA_MATCH_TIMEOUT, YARA_MAX_*,
YARA_SCAN_DEADLINE_SECONDS, YARA_MAX_TOTAL_BYTES_SCANNED) and `time` are
re-exported here and remain monkeypatchable (`yara_hunt.YARA_SCAN_DEADLINE_SECONDS
= -1` before calling `_hunt_yara()` still changes its behavior) because
they are threaded explicitly/looked up fresh at call time rather than
scanner.py importing its own separate copy — see
dumpex/hunt/yara_hunt/config.py and dumpex/hunt/_runtime.py.

`_load_yara_rules` is ALSO kept here (not just re-exported from rules.py)
as a thin wrapper: it calls rules.load_and_compile(), syncs the
compatibility `_LAST_YARA_PROVENANCE` global (read by get_yara_provenance()
— see its own docstring), and returns the same (rule_files, compile_failed)
2-tuple the single-file hunter always did, so `yara_hunt._load_yara_rules
= fake` (replacing the whole wrapper) remains exactly as monkeypatch-safe
as it always was. YARA_MAX_SEG_SCAN is this hunter's OWN segment-size
constant — it no longer imports CS Beacon's CS_MAX_SEG_SCAN (see
dumpex/hunt/yara_hunt/config.py). Private per-step helper functions
(`_context_unverified_reason`... now `context.context_unverified_reason`,
etc.) are NOT re-exported here and make no compatibility promise at all —
import them from their actual module (dumpex.hunt.yara_hunt.context/
.scanner/.rules/...) if you need them directly.
"""
import os
import sys
import time
from pathlib import Path
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import DIM, YELLOW
from dumpex.core.memory import get_modules, get_memory_regions
from dumpex.hunt._ui import _print_hunt_header, NOT_EVALUATED
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.yara_hunt.config import (YaraConfig,
    YARA_MATCH_TIMEOUT, YARA_MAX_STRINGS_PER_MATCH, YARA_MAX_TOTAL_HITS,
    YARA_SCAN_DEADLINE_SECONDS, YARA_MAX_TOTAL_BYTES_SCANNED, YARA_MAX_SEG_SCAN)
from dumpex.hunt.yara_hunt import rules
from dumpex.hunt.yara_hunt import scanner
from dumpex.hunt.yara_hunt import aggregate
from dumpex.hunt.yara_hunt import presentation

_LAST_YARA_PROVENANCE = None   # set by _load_yara_rules(); see get_yara_provenance()


def get_yara_provenance() -> "dict | None":
    """
    Reproducible content provenance for the YARA rule files actually used
    by the most recent _load_yara_rules() call: {"rules_dir": str,
    "files": [{"name", "sha256", "compiled", "error"}, ...] sorted by
    name, "aggregate_sha256": str, "compiled_ok": int, "compile_failed":
    int}. None if YARA scanning was never invoked this process (e.g.
    --hunt injection alone, which never calls _load_yara_rules).

    A --yara-dir path or directory name alone doesn't tell an analyst
    reviewing a report months later WHICH rules actually produced a
    verdict — rule files get edited in place routinely. The per-file and
    aggregate sha256 let a finding be tied to the exact rule content that
    generated it, the same way meta.rules already does for rules.yaml
    (see dumpex.rules_pkg.loader.get_rules_source_info).
    """
    return _LAST_YARA_PROVENANCE


def _load_yara_rules(rules_dir: str) -> tuple:
    """
    Compile every .yar/.yara file in rules_dir (via rules.load_and_compile,
    which never imports this facade) and sync the compatibility
    _LAST_YARA_PROVENANCE global from the result. Returns (loaded,
    compile_failed) — the same 2-tuple shape the single-file hunter always
    returned, so a test replacing this whole wrapper
    (`yara_hunt._load_yara_rules = lambda rules_dir: (...)`) needs no
    further changes downstream.
    """
    global _LAST_YARA_PROVENANCE
    bundle = rules.load_and_compile(rules_dir)
    _LAST_YARA_PROVENANCE = bundle.provenance
    return bundle.rule_files, bundle.compile_failed


def _hunt_yara(mf: MinidumpFile, rules_dir: str = None,
                verbose: bool = False) -> dict:
    """
    Scan all captured memory segments against every YARA rule in rules_dir.

    For each match reports:
      - Rule name, file, tags, description, MITRE ATT&CK ID
      - Every matched string: VA (process), file offset in .dmp, hex preview
      - Per-region context (protection, memory type, backing module)

    See package docstring for the rules-directory resolution order and
    the score/coverage model.
    """
    _print_hunt_header("YARA Memory Scan")

    # get_yara_provenance() is a module-level global, only ever SET by
    # _load_yara_rules() — never cleared. Without resetting it here, a
    # run that returns NOT_EVALUATED before ever reaching
    # _load_yara_rules() (no rules directory found, yara-python missing,
    # ...) would leave meta.yara_rules reporting a PRIOR successful
    # scan's rule file hashes from earlier in the same process, silently
    # implying rules were used for this run when they weren't.
    global _LAST_YARA_PROVENANCE
    _LAST_YARA_PROVENANCE = None

    # ── Locate and import yara-python ─────────────────────────────────
    try:
        import yara
    except ImportError:
        report = aggregate.build_not_evaluated_report("yara-python not installed")
        return presentation.render_yara_not_installed(report)

    # ── Resolve rules directory ───────────────────────────────────────
    if rules_dir is None:
        # sys.argv[0] and cwd are dev-environment assumptions — a pip-
        # installed dumpex has no rules/ next to whatever invoked it.
        # Current PyInstaller builds collect dumpex.rules_pkg's package data
        # in its canonical layout; the _MEIPASS/rules path below is retained
        # only for compatibility with older frozen builds.
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass and (Path(meipass) / "rules" / "yara").is_dir():
            rules_dir = str(Path(meipass) / "rules" / "yara")
        else:
            rules_dir = rules.packaged_yara_rules_dir()

    if rules_dir is None or not os.path.isdir(rules_dir):
        report = aggregate.build_not_evaluated_report("no YARA rules directory found")
        return presentation.render_no_rules_dir(report)

    # ── Load rule files ───────────────────────────────────────────────
    # Looked up HERE by its bare name (this module's own re-exported,
    # still-monkeypatchable global) so a test replacing the whole
    # `_load_yara_rules` wrapper is honored exactly as it was pre-split.
    rule_files, compile_failed = _load_yara_rules(rules_dir)
    if not rule_files:
        reason = (f"all {compile_failed} rule file(s) in {rules_dir} failed to compile"
                   if compile_failed else f"no .yar/.yara files in {rules_dir}")
        report = aggregate.build_not_evaluated_report(reason)
        return presentation.render_no_rule_files(report, rules_dir, compile_failed)

    print(DIM(f"  [*] Loaded {len(rule_files)} rule file(s) from {rules_dir}"))
    if compile_failed:
        print(YELLOW(f"  [~] {compile_failed} rule file(s) failed to compile — "
                      f"scan coverage is reduced, not just a warning\n"))

    # ── Collect memory segments ───────────────────────────────────────
    segs = scanner.select_segments(mf)
    if not segs:
        report = aggregate.build_not_evaluated_report("Memory64ListStream missing from this dump")
        return presentation.render_no_segments(report)

    # Two independent context sources used to judge whether a
    # PE_In_Private_Memory hit is really in private memory or just a
    # legitimately loaded module: ModuleList (name/base/size per module) and
    # MemoryInfo (per-region Type/Protect/State, including MEM_IMAGE vs
    # MEM_PRIVATE). Either one alone lets us classify a hit; only when BOTH
    # are absent from this dump can the address not be judged at all.
    modules_available  = bool(mf.modules and mf.modules.modules)
    mem_info_available = bool(mf.memory_info and mf.memory_info.infos)
    modules = get_modules(mf)
    regions = get_memory_regions(mf)

    print(DIM(f"  [*] Scanning {len(segs)} segment(s) …\n"))

    # config bundles every yara_hunt.* tunable, read from THIS module's own
    # (re-exported, and therefore still monkeypatchable) globals -- see
    # dumpex/hunt/yara_hunt/config.py for why scanner.py can't just read
    # its own separate copy of these constants directly.
    config = YaraConfig(
        match_timeout=YARA_MATCH_TIMEOUT, max_strings_per_match=YARA_MAX_STRINGS_PER_MATCH,
        max_total_hits=YARA_MAX_TOTAL_HITS, scan_deadline_seconds=YARA_SCAN_DEADLINE_SECONDS,
        max_total_bytes_scanned=YARA_MAX_TOTAL_BYTES_SCANNED, max_seg_scan=YARA_MAX_SEG_SCAN,
    )
    # `time.monotonic` is looked up HERE (this module's own re-exported
    # `time` module) rather than imported separately inside scanner.py --
    # see dumpex/hunt/_runtime.py.
    runtime = HunterRuntime(monotonic=time.monotonic)

    outcome = scanner.scan_segments(mf, segs, rule_files, modules, regions,
                                     modules_available, mem_info_available,
                                     config, runtime.monotonic)

    scan_note = scanner.format_scan_note(outcome, config)
    print(DIM(f"  [*] Scan complete — {outcome.scanned} segment(s) scanned{scan_note}."))
    if outcome.suppressed_module_pe:
        print(DIM(f"  [·] {outcome.suppressed_module_pe} PE_In_Private_Memory match(es) suppressed — "
                  f"MZ/PE header belonged to a known, legitimately loaded module.\n"))

    report = aggregate.build_report(outcome, compile_failed)

    return presentation.render_result(report, modules, verbose)
