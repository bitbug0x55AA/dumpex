"""Hunt command dispatcher."""
import os
import sys
from dataclasses import dataclass, field
from minidump.minidumpfile import MinidumpFile
from dumpex.ui.colors import RED
from dumpex.core.memory import va_to_file_offset, prot_str, get_memory_regions
from dumpex.hunt._ui import NOT_EVALUATED

from dumpex.hunt.injection  import _build_injection_report, _render_injection_console
from dumpex.hunt.hollowing  import _build_hollowing_report, _render_hollowing_console
from dumpex.hunt.stomping   import _build_stomping_report, _render_stomping_console
from dumpex.hunt.pipe       import _build_pipe_report, _render_pipe_console
from dumpex.hunt.cs_beacon  import _build_cs_beacon_report, _render_cs_beacon_console
from dumpex.hunt.yara_hunt  import _build_yara_report, _render_yara_console
from dumpex.hunt.encoding   import _build_encoding_report, _render_encoding_console

from dumpex.hunt.injection.collect import _record_from_injection_report
from dumpex.hunt.hollowing.collect import _record_from_hollowing_report
from dumpex.hunt.stomping.collect  import _record_from_stomping_report
from dumpex.hunt.pipe.collect      import _record_from_pipe_report
from dumpex.hunt.cs_beacon.collect import _record_from_cs_beacon_report
from dumpex.hunt.yara_hunt.collect import _record_from_yara_report
from dumpex.hunt.encoding.collect  import _record_from_encoding_report

from dumpex.hunt.summary import build_hunt_summary
from dumpex.hunt import summary_presentation
from dumpex.hunt.region_correlation import build_region_correlations
from dumpex.hunt._investigation import build_investigation_queue
from dumpex.hunt._deep_triage import run_deep_triage
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport
from dumpex.output.records import HUNTERS

# Imported last, after every facade builder/renderer/collect import above:
# _registry.py's own top-level registration code resolves each
# dispatcher-facing name (e.g. `_build_injection_report`) off this module,
# so those names must already exist as attributes here first (see
# _registry.py's own module docstring and
# docs/hunt_analyzer_registry_contract.md §6's "Module layout and import
# timing"). Those per-analyzer imports stay -- even after #72's cutover
# below -- because they are not merely how THIS module used to call each
# builder/renderer/projector directly: they are the second binding
# `_registry.py`'s own `_late_bound()` resolves off `sys.modules
# ["dumpex.hunt"]` on every call (contract §8), which is also what keeps
# `monkeypatch.setattr(dumpex.hunt, "_build_injection_report", fake)`
# working. #71 registered AnalyzerRegistry here; #72 (this cutover) routes
# `_execute_full_scope()` -- and therefore both `collect_hunt()` and
# `cmd_hunt()` -- through `_registry.REGISTRY.select()` instead of the old
# hard-coded `if _wanted(hunter):`/`if run_<hunter>:` branches, which are
# removed below.
from dumpex.hunt import _registry


def _option_view(ref_dir: "str | None", yara_dir: "str | None") -> dict:
    """The ONE, real mapping from `_execute_full_scope()`'s own public
    keyword parameters to the internal option names `AnalyzerSpec.
    option_names` values are drawn from -- `_execute_full_scope()` below
    and the import-time drift guard immediately below THIS function both
    call this same function, rather than each maintaining its own
    hand-written `{"ref_dir": ..., "rules_dir": ...}` literal.

    Finding, #73: an earlier version of this guard compared TWO
    independently hand-maintained frozensets (a local `_OPTION_NAMES`
    constant here against `_registry.KNOWN_OPTION_NAMES`) -- neither one
    was actually derived from the real dict `_execute_full_scope()`
    builds, so a future edit could keep both constants in lockstep and
    still leave THIS dict's own keys out of sync with them, reopening the
    exact bare-`KeyError`-after-six-real-builders regression this whole
    guard exists to close (reproduced directly: `KNOWN_OPTION_NAMES` and
    the old `_OPTION_NAMES` both updated to add a name, `_execute_full_
    scope()`'s own dict literal left untouched -- the import-time guard
    passed, and `collect_hunt("all")` still crashed with a bare
    `KeyError` after every other selected builder had already run).
    Making this function the one place either an import-time OR a
    per-call check reads means there is no second literal left to drift."""
    return {"ref_dir": ref_dir, "rules_dir": yara_dir}


def _check_option_names_in_sync(local_names: frozenset, registry_names: frozenset) -> None:
    """A real function (never a bare module-level `if`/`raise` alone),
    independently unit-testable against synthetic frozensets without
    needing to reload this module -- the same "extract into a named,
    directly-testable function" pattern `_registry.py`'s own
    `_validate_scoped_sources()` already establishes for its own
    import-time invariants. Raises `_registry.InvalidAnalyzerSpec` --
    the same named exception family every other §7.1 construction-time
    failure raises -- never a bare `AssertionError`, so a caller (or a
    test) can catch exactly this gate rather than pattern-matching
    message text (the same rule `_registry.py`'s own module docstring
    states for its own exceptions)."""
    if local_names != registry_names:
        raise _registry.InvalidAnalyzerSpec(
            "dumpex.hunt._execute_full_scope()'s own options view has drifted "
            "from _registry.KNOWN_OPTION_NAMES -- update both together")


# Checked once, right here, at IMPORT time -- matching every other §7.1
# construction-time invariant's whole-CLI blast radius (`dumpex.cli`
# imports `dumpex.hunt` at module scope, so a mismatch here fails import,
# not merely the first `--hunt` invocation that happens to reach it).
# `_option_view(None, None)`'s own KEYS are what matter here, not the
# `None` values passed to build them -- no request context exists yet at
# import time.
_check_option_names_in_sync(frozenset(_option_view(None, None)), _registry.KNOWN_OPTION_NAMES)


def full_scope_hunters() -> tuple:
    """The exact, capability-filtered identity set `--hunt all` actually
    selects, in `HUNTERS` order (contract §6's own `AnalyzerRegistry.
    select("all")`) -- what `dumpex.hunt.summary.build_hunt_summary
    (selected="all")`'s own `full_scope_hunters` keyword must be told, so
    its internal roster check matches what `_execute_full_scope()` (below)
    actually built `records` from, rather than the unfiltered `HUNTERS`
    tuple it silently assumed before (finding, #73 -- see
    `build_hunt_summary`'s own docstring for the full finding). Public
    (no leading underscore) so `dumpex/cli.py`'s own second, redundant
    `build_hunt_summary()` call -- which attaches `investigation_actions`
    to the summary `cmd_hunt()` already computed once internally, rather
    than importing `_registry` directly -- can pass the identical value
    `cmd_hunt()` itself used for the same invocation."""
    return tuple(spec.identity for spec in _registry.REGISTRY.select("all"))


def _hunt_coverage_report(records: "list", summary: dict) -> CoverageReport:
    """The single, document-level `CommandResult.coverage` for `--hunt`
    -- required to be ONE CoverageReport instance, unlike the real
    per-hunter coverage detail (which already lives, in full, on each
    HunterRecord.coverage produced by collect_hunt() below). NOT derived
    from `summary` alone: `status` (DETECTED/INCONCLUSIVE/NOT_EVALUATED/
    NOT_DETECTED_IN_SCANNED_SCOPE) and `coverage.status` (complete/
    partial/not_evaluated) are independent dimensions on every
    HunterRecord -- a hunter can be DETECTED from a config/finding in one
    region while ANOTHER region failed to read or a required context
    source was missing, which is `status=DETECTED` with
    `coverage.status=partial` at the same time. `summary`'s own
    detected_count/inconclusive_count/not_evaluated_count are derived
    from `status` only (see build_hunt_summary()), so a DETECTED-with-
    partial-coverage record contributes to NONE of them -- deriving this
    document-level coverage from `summary` counts alone would silently
    report "complete" for a run that genuinely has an evidence gap. Every
    record's own `coverage.status` must be checked directly instead; this
    document-level rollup only needs to say whether anything was
    evaluated at all (not_evaluated), and whether EVERY selected hunter's
    own coverage was fully conclusive (complete) or not (partial) --
    never combining the individual CoverageReports themselves via
    dumpex.output.coverage.combine_coverage_reports(), since their source
    names (e.g. "memory_info") are not namespaced per hunter and
    legitimately disagree in meaning between hunters (pipe's own
    "memory_info" completeness rule is not cs-beacon's).

    `not_evaluated` here is exactly `summary["overall_status"] ==
    "NOT_EVALUATED"` -- the one relationship
    dumpex-output-v2.12.schema.json's own kind=="hunt" branch enforces as
    a biconditional between `coverage.status` and `summary.overall_status`.
    """
    if summary["overall_status"] == "NOT_EVALUATED":
        return CoverageReport(status="not_evaluated")
    if any(record.coverage.status != "complete" for record in records):
        return CoverageReport(status="partial")
    return CoverageReport(status="complete")


def _investigation_actions_json(records: "list", selected: str, mf: MinidumpFile) -> list:
    """`result.summary.investigation_actions` -- the default, metadata-
    only skipped-target queue (issue #19), computed only for `--hunt all`
    (`selected == "all"`); `[]` for a single-hunter run, so the JSON field
    stays present and simply empty rather than conditionally omitted (see
    dumpex.hunt._investigation's own module docstring). `get_memory_regions
    (mf)` reads the dump's already-parsed MemoryInfoListStream -- not a
    re-scan, same as `build_region_correlations()`'s own use of it above."""
    if selected != "all":
        return []
    actions = build_investigation_queue(records, get_memory_regions(mf))
    return [a.to_dict() for a in actions]


@dataclass
class _FullScopeExecution:
    """The result of one `_execute_full_scope()` call -- everything
    `collect_hunt()`/`cmd_hunt()` need, computed exactly once (issue #72).
    `records`/`provenance` are keyed/ordered the same way regardless of
    `render`; `results` stays `{}` when `render=False` (`collect_hunt()`'s
    own silence guarantee -- see `_execute_full_scope()`'s own docstring
    on why `render=False` never calls a spec's `renderer` at all, not
    merely "discards its return value")."""
    records: list
    results: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)


def _execute_full_scope(mf: MinidumpFile, selected: str, *, ref_dir: str = None,
                         yara_dir: str = None, verbose: bool = False,
                         render: bool = False) -> _FullScopeExecution:
    """The one internal full-scope executor issue #72 routes both
    `collect_hunt()` and `cmd_hunt()` through -- replacing the two
    separate hard-coded `if _wanted(hunter):`/`if run_<hunter>:` selection
    chains those functions used to maintain independently.

    Selects `AnalyzerSpec`s via `_registry.REGISTRY.select(selected)`,
    which returns them in fixed `HUNTERS` order (`_registry.py`'s own
    `AnalyzerRegistry.select()` docstring) -- the same order the old
    per-hunter `if` chains already produced, so `records`/`results` here
    come out in exactly the order every existing golden fixture and
    call-count test already expects. `selected` is passed through
    unchanged; the caller is responsible for its own "all" vs. one-of-
    `HUNTERS` validation BEFORE calling this (see `collect_hunt()`/
    `cmd_hunt()` below) -- `select()` would raise its own
    `UnknownAnalyzerIdentity` for a bad value, but that exception's
    message text does not match either caller's own long-frozen
    error text (contract §7.2 failure #9), so neither caller may let an
    invalid `selected` reach this function in the first place.

    Each selected spec's own `builder` is called exactly once, with only
    the option keyword(s) that spec actually declares (`spec.option_names`
    -- e.g. only `ref_dir` reaches `stomping`'s builder, only `rules_dir`
    reaches `yara`'s), never the full `{ref_dir, rules_dir}` normalized
    option view unfiltered -- a builder with a closed option set (contract
    §7.1 failure #7) would raise `TypeError` on an unexpected keyword
    otherwise. `rules_dir` is `cmd_hunt()`/`cli.py`'s own `yara_dir`
    parameter renamed at this boundary (contract §9's own `HuntRequest`
    row makes the same rename) -- both this function's own `yara_dir`
    parameter and `cmd_hunt()`'s/`collect_hunt()`'s public `yara_dir`
    keyword keep that external name unchanged; only the internal option
    key handed to `spec.builder` is `rules_dir`.

    The one already-built `Report` instance feeds every consumer for that
    spec: `spec.record_projector(report)` always (both callers need a
    `HunterRecord`), `spec.renderer(report, verbose)` only when
    `render=True` (`collect_hunt()`'s own console-silence guarantee --
    contract §8's "`collect_hunt()` never calls `renderer`" -- passes
    `render=False`, `cmd_hunt()` passes `render=True`), and
    `spec.provenance_hook(report)` whenever that spec declares one
    (`yara` today; contract §5 field 8) -- collected into `provenance` by
    identity rather than a `yara`-name conditional, so a caller that wants
    a given identity's own invocation-specific metadata (YARA rule
    provenance today, a future analyzer's own hook tomorrow) reads
    `execution.provenance.get(identity)` instead of a growing set of
    per-analyzer `if identity == "yara":` branches."""
    options = _option_view(ref_dir, yara_dir)
    specs = _registry.REGISTRY.select(selected)

    # `options`' own keys are checked against `_registry.KNOWN_OPTION_
    # NAMES` once already, at IMPORT time (this module's own top-level
    # `_check_option_names_in_sync(...)` call, above `_option_view()`) --
    # that guard alone catches a genuine SOURCE-level drift (an edit that
    # leaves `_option_view()` and `KNOWN_OPTION_NAMES` disagreeing) the
    # moment `dumpex.cli` next imports `dumpex.hunt`, before any `--hunt`
    # invocation ever runs. It cannot, by construction, catch a mismatch
    # introduced AFTER this process already imported `dumpex.hunt` (a
    # test monkeypatching `_registry.KNOWN_OPTION_NAMES` mid-session, for
    # instance) -- import-time validation is a boot-time invariant, not a
    # continuously-re-checked one. This second, PER-CALL preflight closes
    # that residual gap unconditionally, for every invocation regardless
    # of what happened to global state in between: every selected spec's
    # `option_names` is validated against THIS call's own real `options`
    # dict, for every spec, BEFORE the loop below calls a single builder
    # -- not discovered one `KeyError` at a time, mid-loop, after
    # whichever earlier-selected analyzers' builders already ran.
    known = frozenset(options)
    for spec in specs:
        if not spec.option_names <= known:
            raise _registry.InvalidAnalyzerSpec(
                f"{spec.identity}: option_names "
                f"{sorted(spec.option_names - known)} are not in this call's own "
                f"options view {sorted(known)} -- _option_view() and "
                f"_registry.KNOWN_OPTION_NAMES have drifted apart")

    records = []
    results = {}
    provenance = {}
    for spec in specs:
        kwargs = {name: options[name] for name in spec.option_names}
        report = spec.builder(mf, **kwargs)
        records.append(spec.record_projector(report))
        if render:
            results[spec.identity] = spec.renderer(report, verbose)
        if spec.provenance_hook is not None:
            provenance[spec.identity] = spec.provenance_hook(report)
    return _FullScopeExecution(records=records, results=results, provenance=provenance)


def collect_hunt(mf: MinidumpFile, selected: str, *, yara_dir: str = None,
                  ref_dir: str = None) -> CommandResult:
    """
    The v2.4 migration's `CommandResult`-producing entry point for
    `--hunt` (PR4) -- builds each SELECTED hunter's `Report` exactly
    ONCE, via that hunter's own `_build_*_report()`, and converts it
    straight to a `HunterRecord` via `_record_from_*_report()`. Never
    calls `_hunt_*()` or `collect_*_record()` -- both are thin compat
    wrappers that each build their OWN fresh Report, so calling either
    of them here (in addition to this function's own builder calls)
    would scan every selected hunter twice for one `--hunt` invocation.
    See each hunter's own `_build_*_report()`/`_record_from_*_report()`
    docstring pair for why a single Report safely feeds both a console
    consumer and this JSON-record consumer.

    `selected` is the `--hunt` argument: `"all"` or one of `HUNTERS`
    (the same contract `dumpex.hunt.summary.build_hunt_summary()`
    documents). Console rendering (the printed `--hunt` summary/detail)
    remains `cmd_hunt()`'s own separate concern in this module -- this
    function produces only the v2.4 JSON/CSV side and prints nothing.

    Routed through `_execute_full_scope(..., render=False)` (issue #72),
    which selects specs via `_registry.REGISTRY.select(selected)` in fixed
    `HUNTERS` order rather than this function's own hard-coded
    `if _wanted(hunter):` chain -- see that function's own docstring for
    why `render=False` is what keeps this function's own console-silence
    guarantee (`tests/integration/test_collect_hunt_is_silent.py`) intact:
    no selected spec's `renderer` is ever called, not merely "its return
    value is discarded."
    """
    valid = set(HUNTERS) | {"all"}
    if selected not in valid:
        raise ValueError(
            f"collect_hunt() got unknown selected={selected!r} -- must be 'all' or "
            f"one of {HUNTERS}")

    execution = _execute_full_scope(mf, selected, ref_dir=ref_dir, yara_dir=yara_dir)
    records = execution.records

    summary = build_hunt_summary(records, selected=selected, full_scope_hunters=full_scope_hunters())
    summary["investigation_actions"] = _investigation_actions_json(records, selected, mf)
    return CommandResult(kind="hunt", records=records,
                          coverage=_hunt_coverage_report(records, summary), summary=summary)

def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False, yara_dir: str = None,
             ref_dir: str = None, collect_records: bool = False, triage_skipped: bool = False):
    """Run TTP-specific detection playbooks, printing the console report
    exactly as always.

    `collect_records=True` (used by cli.py's `--hunt` branch, PR4) makes
    this function ALSO build the v2.4 `HunterRecord` for every selected
    hunter and return `(results, records, investigation_actions,
    diagnostics, yara_provenance)` -- a 5-tuple, always, since issue #11's
    own P1 review fix added `yara_provenance` alongside issue #19 Phase
    2's earlier `--triage-skipped` addition -- instead of the bare
    `results` dict every existing caller already gets back unchanged.
    `investigation_actions` is `list[InvestigationAction]` and
    `diagnostics` is `list[Diagnostic]` (both `[]` for a single-hunter
    `ttp`, and `diagnostics` is also `[]` whenever `triage_skipped` is
    False). `yara_provenance` is THIS call's own
    `domain.RulesProvenance.to_dict()` (or `None` when `ttp` never
    selects "yara"/"all", or the yara-python/rules-directory/rule-
    compilation prerequisites weren't met) -- cli.py threads it straight
    into `V2Output.set_yara_provenance()` so `meta.yara_rules` reflects
    THIS run's own YARA scan, never `dumpex.hunt.yara_hunt.
    get_yara_provenance()`'s process-wide "last build" global (which
    remains available only as a compatibility adapter for
    `dumpex.ui.structured.StructuredOutput`, the legacy v1.1 output
    path). Each selected hunter's own `_build_*_report()` is still called
    EXACTLY ONCE either way -- this function has always called it
    directly (never through the `_hunt_*()`/`collect_*_record()` compat
    wrappers, which would each build their own separate Report), feeding
    that one Report to both this hunter's console-render function and,
    when `collect_records` is set, `_record_from_*_report()` too. See
    `collect_hunt()` above for the equivalent silent, JSON-only path used
    by any caller that doesn't want console output at all (that path
    stays metadata-only -- it has no `triage_skipped` parameter, since
    nothing in the CLI wires it to `--triage-skipped`; only THIS
    function, the real `--hunt` CLI entry point, needs that capability).

    `triage_skipped=True` (only meaningful when `ttp == "all"` -- a
    single-hunter run never has an investigation queue to begin with)
    runs `dumpex.hunt._deep_triage.run_deep_triage()` on the metadata
    queue `build_investigation_queue()` already computed below, EXACTLY
    ONCE -- the resulting `investigation_actions`/diagnostics feed BOTH
    this function's own console rendering AND (via the 4-tuple above)
    `--json`, so a real, budgeted content read is never performed twice
    for one invocation. See `_deep_triage`'s own module docstring for the
    budget model.

    The `--hunt all` console summary card's own "Overall: ..." line is
    derived from the exact same `dumpex.hunt.summary.build_hunt_summary()`
    reduction the JSON/CSV side uses (via the `summary` this function
    always computes internally, from the same `records` -- see that
    module's own docstring) -- not a second, independently-maintained
    any_hit/any_not_evaluated/any_inconclusive reduction, which could
    silently disagree with `result.summary.overall_status` if only one
    side's rule were ever updated. Per-hunter DISPLAY formatting (name/
    verdict color/score suffix/lead count) still reads from `results`,
    since that's each hunter's own presentation choice, not a
    cross-hunter reduction.

    Routed through `_execute_full_scope(..., render=True)` (issue #72),
    which selects specs via `_registry.REGISTRY.select(ttp)` in fixed
    `HUNTERS` order rather than this function's own former hard-coded
    `run_injection`/`run_hollowing`/... flags and `if run_<hunter>:`
    chain -- --hunt all always runs the full memory scan for every
    selected analyzer this way (in particular cs-beacon: skipping it
    when prior TTPs scored 0 used to mean a beacon could be present in a
    dump with no injection/hollowing/stomping/pipe indicators and
    --hunt all would still report "No TTP indicators found" without ever
    having looked -- the registry-driven executor has no such
    short-circuit to begin with, for any analyzer). `yara_provenance` is
    now `execution.provenance.get("yara")` -- `_registry.py`'s own
    `_yara_provenance_hook` performs the exact `RulesProvenance.to_dict()`
    conversion this function used to hand-roll inline, reading
    `report.coverage.rules.provenance` off the same `Report` instance."""
    # Derived from HUNTERS (already imported above for the record order)
    # rather than repeated as a second literal: a hunter added to /
    # renamed in HUNTERS but forgotten here used to be accepted-or-
    # rejected purely by whichever copy the caller happened to hit.
    valid = set(HUNTERS) | {"all"}
    if ttp not in valid:
        print(RED(f"[!] Unknown TTP '{ttp}'. Choose from: {', '.join(sorted(valid))}"))
        sys.exit(1)

    # Built unconditionally (not gated by collect_records): the console
    # "--hunt all" summary card below needs the real HunterRecords too --
    # see this function's own docstring update on why the Overall line is
    # now derived from dumpex.hunt.summary.build_hunt_summary() rather
    # than a second, independently-computed reduction over `results`.
    # Each spec.record_projector() call is a pure, cheap conversion of a
    # Report already built above (never a re-scan), so computing this
    # even for a caller that ignores the second return value costs
    # nothing worth gating.
    # §7.2 failure #11 (contract §10 item 4, option (a)) -- `ttp` is a
    # real `HUNTERS` member but its own spec is `full_scope_capable=False`
    # (targeted-scan only, unreachable this release since all seven real
    # specs are `full_scope_capable=True`, but a real, named exception
    # `_registry.REGISTRY.select()` already raises for it, contract §6).
    # Caught here and translated into the same clear-message-then-exit(1)
    # shape the unknown-TTP branch above already uses, rather than
    # letting it propagate as a bare traceback out of `cli.main()`.
    try:
        execution = _execute_full_scope(mf, ttp, ref_dir=ref_dir, yara_dir=yara_dir,
                                         verbose=verbose, render=True)
    except _registry.UnsupportedFullScopeRequest:
        print(RED(f"[!] '{ttp}' is a targeted-scan-only analyzer and cannot be run via "
                   f"full-scope --hunt (neither directly, nor as part of --hunt all)."))
        sys.exit(1)
    results = execution.results
    records = execution.records
    yara_provenance = execution.provenance.get("yara")   # this call's own YARA rule
                              # provenance, if ttp selected "yara" -- see this
                              # function's own docstring on why this is threaded
                              # through explicitly rather than read back from
                              # dumpex.hunt.yara_hunt.get_yara_provenance()'s global

    # The single cross-hunter reducer JSON (dumpex.hunt.cmd_hunt(...,
    # collect_records=True) -> cli.py), CSV, and this function's own
    # console summary card below all derive their overall
    # detected/inconclusive/not_evaluated classification from -- see
    # dumpex.hunt.summary.build_hunt_summary()'s own docstring. Computed
    # unconditionally (cheap: pure aggregation over already-built
    # records, no re-scan) even for a single-TTP run that never reads it.
    summary = build_hunt_summary(records, selected=ttp, full_scope_hunters=full_scope_hunters())

    # Rule provenance (path + sha256 of the rules.yaml that actually
    # produced these verdicts) is surfaced once, in --json meta.rules
    # (dumpex.ui.structured.StructuredOutput._rules_meta()) — not
    # duplicated here inside the hunt results themselves.

    # Both cs-beacon's and YARA's `report_legacy.project_legacy_dict()`
    # already return JSON-safe dicts (bytes fields hex-encoded in the
    # projector itself), so `results` needs no post-render sanitization pass.

    # Summary card for --hunt all
    if ttp == "all" and "yara" not in results:
        results["yara"] = {"matches": [], "score": 0, "rules_hit": [], "status": NOT_EVALUATED}
    if ttp == "all" and "obfuscation" not in results:
        results["obfuscation"] = {"score": 0, "status": NOT_EVALUATED}

    investigation_actions = []
    deep_diagnostics = []
    if ttp == "all":
        # The single cross-hunter renderer (Step 1.5, console presentation
        # patch) -- reads ONLY `records`/`summary`/the document-level
        # coverage status, never `results` (this function's own legacy
        # per-hunter console dicts, used above only for the function's
        # return value). See dumpex.hunt.summary_presentation's own module
        # docstring for the REVIEW FIRST/NEEDS ATTENTION/OTHER HUNTERS/NEXT INVESTIGATION
        # section breakdown this replaces the old flat per-hunter list
        # with, and tests/integration/test_hunt_all_summary_source.py for
        # the proof that a poisoned `results` value cannot leak into it.
        doc_coverage = _hunt_coverage_report(records, summary)
        # get_memory_regions(mf) reads the dump's ALREADY-PARSED
        # MemoryInfoListStream (see dumpex.core.memory's own docstring) --
        # this is not a re-scan. Fetched exactly ONCE here and reused for
        # both build_region_correlations() and build_investigation_queue()
        # -- each reads only these already-parsed regions plus the
        # already-built `records`, never `mf` again beyond this one call.
        memory_regions = get_memory_regions(mf)
        region_correlations = build_region_correlations(records, memory_regions)
        investigation_actions = build_investigation_queue(records, memory_regions)
        # --triage-skipped (issue #19 Phase 2): run the real, budgeted
        # content read EXACTLY ONCE here, over the metadata queue just
        # built above -- both this call's own console rendering below AND
        # the (investigation_actions, deep_diagnostics) this function
        # returns to collect_records=True callers consume the SAME
        # already-deep-triaged list, never a second independent pass (see
        # this function's own docstring and dumpex.hunt._deep_triage's
        # module docstring for why re-running it would silently double
        # the read budget).
        if triage_skipped and investigation_actions:
            investigation_actions, deep_diagnostics = run_deep_triage(mf, investigation_actions)
        summary_presentation.render_hunt_summary(
            records, summary, doc_coverage.status.value,
            region_correlations=region_correlations,
            investigation_actions=investigation_actions,
            deep_triage_diagnostics=deep_diagnostics, verbose=verbose)

    if collect_records:
        return results, records, investigation_actions, deep_diagnostics, yara_provenance
    return results

