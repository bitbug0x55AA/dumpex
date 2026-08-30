"""Budgeted YARA scanning over captured minidump memory.

Score counts distinct matching rule names, not match instances. Process VAs and
dump-file offsets remain distinct. Packaged rules are the default and
--yara-dir is the explicit override, avoiding implicit searches through
untrusted case working directories.

Rule compilation, segment scanning, context resolution, and retained evidence
are bounded and represented in coverage. YARA intentionally does not use the
shared Finding model.
"""
import os
import copy
import sys
import time
from pathlib import Path
from minidump.minidumpfile import MinidumpFile
from dumpex.core.memory import get_modules, get_memory_regions
from dumpex.hunt._runtime import HunterRuntime

from dumpex.hunt.yara_hunt.config import (YaraConfig,
    YARA_MATCH_TIMEOUT, YARA_MAX_STRINGS_PER_MATCH, YARA_MAX_TOTAL_HITS,
    YARA_SCAN_DEADLINE_SECONDS, YARA_MAX_TOTAL_BYTES_SCANNED, YARA_MAX_SEG_SCAN)
from dumpex.hunt.yara_hunt import rules
from dumpex.hunt.yara_hunt import scanner
from dumpex.hunt.yara_hunt import aggregate
from dumpex.hunt.yara_hunt import report_console
from dumpex.hunt.yara_hunt import report_legacy
from dumpex.hunt.yara_hunt.domain import RulesDiagnostics

_LAST_YARA_PROVENANCE = None   # set by _build_yara_report()'s own _finish(); see get_yara_provenance()


def get_yara_provenance() -> "dict | None":
    """
    Reproducible content provenance for the YARA rule files actually used
    by the most recently COMPLETED `_build_yara_report()` call: {"rules_dir":
    str, "files": [{"name", "sha256", "compiled", "error"}, ...] sorted by
    name, "aggregate_sha256": str, "compiled_ok": int, "compile_failed":
    int}. None if YARA scanning was never invoked this process (e.g.
    --hunt injection alone, which never builds a YaraReport).

    This is a COMPATIBILITY ADAPTER, not the canonical provenance source --
    it is a process-wide "last completed build" cache (issue #11's own
    "keep get_yara_provenance() only as a compatibility adapter... must not
    be the canonical source" requirement), correct for this codebase's
    actual usage (one Report built, then its metadata read, per `--hunt`
    invocation), but it necessarily reflects only the SINGLE most recent
    `_build_yara_report()` call in this process. A caller that builds more
    than one `domain.YaraReport` before consuming provenance (e.g. scanning
    two separate dumps in one long-lived process) MUST read
    `report.coverage.rules.provenance` directly off its own Report instead
    of relying on this global to still describe the right one.

    Returns a FRESH dict on every call (never the same object twice, and
    never a view into `_LAST_YARA_PROVENANCE`'s own nested structures) --
    a caller mutating what it gets back can never corrupt this module's own
    state or a later, unrelated caller's read of it.

    A --yara-dir path or directory name alone doesn't tell an analyst
    reviewing a report months later WHICH rules actually produced a
    verdict — rule files get edited in place routinely. The per-file and
    aggregate sha256 let a finding be tied to the exact rule content that
    generated it, the same way meta.rules already does for rules.yaml
    (see dumpex.rules_pkg.loader.get_rules_source_info).
    """
    if _LAST_YARA_PROVENANCE is None:
        return None
    return copy.deepcopy(_LAST_YARA_PROVENANCE)


def _load_yara_rules(rules_dir: str) -> tuple:
    """
    Compile every .yar/.yara file in rules_dir via `rules.load_and_compile`
    (which never imports this facade). Returns `(loaded, provenance)` --
    the compiled rule_files list and the frozen `models.RulesProvenance`
    describing every candidate file considered. Kept as its own thin,
    still-monkeypatchable module-level function (rather than inlined into
    `_build_yara_report()`) purely so a test can replace the whole loading
    step: `yara_hunt._load_yara_rules = lambda rules_dir: (fake_rule_files,
    fake_provenance)`.

    Deliberately does NOT touch `_LAST_YARA_PROVENANCE` -- see
    `_build_yara_report()`'s own `_finish()` helper for where and why that
    compatibility global is written.
    """
    return rules.load_and_compile(rules_dir)


def _yara_config() -> YaraConfig:
    """Every `yara_hunt.*` tunable at its full-scope value, bundled for
    scanner.py. Read from THIS module's own re-exported (and therefore still
    monkeypatchable) globals -- see dumpex/hunt/yara_hunt/config.py for why
    scanner.py can't just read its own separate copy of these constants
    directly. Shared with the targeted adapter so a full-scope override of
    `dumpex.hunt.yara_hunt.<CONST>` moves both modes together."""
    return YaraConfig(
        match_timeout=YARA_MATCH_TIMEOUT, max_strings_per_match=YARA_MAX_STRINGS_PER_MATCH,
        max_total_hits=YARA_MAX_TOTAL_HITS, scan_deadline_seconds=YARA_SCAN_DEADLINE_SECONDS,
        max_total_bytes_scanned=YARA_MAX_TOTAL_BYTES_SCANNED, max_seg_scan=YARA_MAX_SEG_SCAN,
    )


def _resolve_rule_files(rules_dir: str = None) -> tuple:
    """The three prerequisites every YARA scan shares -- yara-python is
    importable, a rules directory resolves, and at least one file in it
    compiles -- as `(rule_files, RulesDiagnostics)`.

    `rule_files` is empty for each prerequisite failure and the diagnostics say
    which one fired, so a caller decides what a missing prerequisite means for
    its own output shape (a not-evaluated `YaraReport` for the full-scope
    builder below, a not-evaluated closure for the targeted adapter in
    `dumpex.hunt.yara_hunt.targeted`) without either restating the chain.

    `rules_dir=None` resolves the packaged rules the same way `--yara-dir`'s
    absence always has; the returned diagnostics carry the directory actually
    used, so provenance names real rule content rather than the caller's
    argument."""
    try:
        import yara
    except ImportError:
        return (), RulesDiagnostics(yara_available=False)

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
        return (), RulesDiagnostics(yara_available=True)

    # Looked up HERE by its bare name (this module's own re-exported,
    # still-monkeypatchable global) so a test replacing the whole
    # `_load_yara_rules` wrapper is honored.
    rule_files, provenance = _load_yara_rules(rules_dir)
    return rule_files, RulesDiagnostics(
        yara_available=True, rules_dir=rules_dir, attempted=True,
        compiled_ok=provenance.compiled_ok, compile_failed=provenance.compile_failed,
        provenance=provenance)


def _build_yara_report(mf: MinidumpFile, rules_dir: str = None):
    """Run the prerequisite checks / scan / aggregate pipeline and return
    the domain.YaraReport -- the ONE place this pipeline is assembled,
    shared by `_hunt_yara()` (console path, below) and
    `collect_yara_record()` (the HunterRecord-producing path). Prints
    nothing at all -- which of the four "prerequisite missing" cases
    applies (if any) is fully recoverable from the returned Report's own
    `coverage.rules` (see domain.RulesDiagnostics), so nothing here needs
    to remember or signal which branch fired.

    Scan all captured memory segments against every YARA rule in
    rules_dir. See package docstring for the rules-directory resolution
    order and the score/coverage model.
    """
    def _finish(report):
        """The ONE place `_LAST_YARA_PROVENANCE` is written -- always a
        snapshot COPY of the just-built, already-immutable `report`'s own
        `coverage.rules.provenance` (itself `None` for every branch that
        returns before a rules directory was ever loaded/compiled), never
        the other way around. Nothing anywhere in this pipeline reads the
        global back INTO a Report -- a Report's own provenance comes
        exclusively from the `RulesDiagnostics` built from THIS call's own
        `_load_yara_rules()` return value, so an interleaved/concurrent
        scan touching this same global in another thread/re-entrant call
        can never leak into a different run's result (issue #11's own
        "must not... leak stale state across runs" requirement)."""
        global _LAST_YARA_PROVENANCE
        provenance = report.coverage.rules.provenance
        _LAST_YARA_PROVENANCE = provenance.to_dict() if provenance is not None else None
        return report

    # ── yara-python, rules directory, compiled rule files ─────────────
    rule_files, rules_diag = _resolve_rule_files(rules_dir)
    if not rule_files:
        return _finish(aggregate.build_not_evaluated_report(rules_diag))

    # ── Collect memory segments ───────────────────────────────────────
    segs = scanner.select_segments(mf)
    if not segs:
        return _finish(aggregate.build_not_evaluated_report(rules_diag))

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

    config = _yara_config()
    # `time.monotonic` is looked up HERE (this module's own re-exported
    # `time` module) rather than imported separately inside scanner.py --
    # see dumpex/hunt/_runtime.py.
    runtime = HunterRuntime(monotonic=time.monotonic)

    scan_result = scanner.scan_segments(mf, segs, rule_files, modules, regions,
                                         modules_available, mem_info_available,
                                         config, runtime.monotonic)

    return _finish(aggregate.build_report(scan_result, rules_diag))


def _hunt_yara(mf: MinidumpFile, rules_dir: str = None, verbose: bool = False) -> dict:
    """Scan all captured memory segments against every YARA rule in
    rules_dir -- see `_build_yara_report()`'s own docstring for the
    algorithm and rules-directory resolution order.

    All console output happens via `_render_yara_console()`, AFTER the
    fully silent `_build_yara_report()` returns."""
    report = _build_yara_report(mf, rules_dir=rules_dir)
    return _render_yara_console(report, verbose)


def _render_yara_console(report, verbose: bool = False) -> dict:
    """Print the console report for an ALREADY-BUILT `domain.YaraReport`
    and return the same v1.1-shaped findings dict `_hunt_yara()` always
    has -- extracted so `dumpex.hunt.collect_hunt()`'s console+JSON
    orchestrator can call `_build_yara_report()` once and feed the SAME
    Report to this function AND `report_record.project_hunter_record()`,
    instead of calling `_hunt_yara()` (which would build its own second
    Report and scan again)."""
    report_console.print_console(report, verbose)
    return report_legacy.project_legacy_dict(report)
