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


def _run_targeted_obfuscation(context):
    """The dispatcher-facing name `_registry.py` resolves `obfuscation`'s
    `targeted_adapter` through (contract §8): given one targeted
    `HuntExecutionContext`, run the entropy, sleep-mask, and decode layers
    over the single requested virtual-address range and return an
    `ObservationResult` with one independent closure per layer.

    The real implementation lives in `dumpex.hunt.encoding.targeted` and is
    imported lazily -- `_registry`'s import-time resolution of this name (via
    `_resolve_and_validate_targeted_adapter`) only needs the callable to
    exist, and the executor's own observation-layer imports must not be
    pulled in while `dumpex.hunt` is still assembling."""
    from dumpex.hunt.encoding.targeted import run_targeted_encoding
    return run_targeted_encoding(context)


def _run_targeted_yara(context):
    """The dispatcher-facing name `_registry.py` resolves `yara`'s
    `targeted_adapter` through (contract §8): given one targeted
    `HuntExecutionContext`, match every compiled rule against the single
    requested virtual-address range and return an `ObservationResult` with one
    `segment_scan` closure.

    The real implementation lives in `dumpex.hunt.yara_hunt.targeted` and is
    imported lazily, for the same reason `_run_targeted_obfuscation` above
    imports its own."""
    from dumpex.hunt.yara_hunt.targeted import run_targeted_yara
    return run_targeted_yara(context)


def _run_targeted_cs_beacon(context):
    """The dispatcher-facing name `_registry.py` resolves `cs-beacon`'s
    `targeted_adapter` through (contract §8): given one targeted
    `HuntExecutionContext`, search the single requested virtual-address range
    for beacon configurations and return an `ObservationResult` with one
    `segment_scan` closure.

    The real implementation lives in `dumpex.hunt.cs_beacon.targeted` and is
    imported lazily, for the same reason `_run_targeted_obfuscation` above
    imports its own."""
    from dumpex.hunt.cs_beacon.targeted import run_targeted_cs_beacon
    return run_targeted_cs_beacon(context)


def _run_targeted_pipe(context):
    """The dispatcher-facing name `_registry.py` resolves `pipe`'s
    `targeted_adapter` through (contract §8): given one targeted
    `HuntExecutionContext`, collect pipe names and the C2 context around them
    over the single requested virtual-address range and return an
    `ObservationResult` with one independent `pipe_name` closure and one
    `c2_context` closure.

    The real implementation lives in `dumpex.hunt.pipe.targeted` and is
    imported lazily, for the same reason `_run_targeted_obfuscation` above
    imports its own."""
    from dumpex.hunt.pipe.targeted import run_targeted_pipe
    return run_targeted_pipe(context)


def _run_targeted_stomping(context):
    """The dispatcher-facing name `_registry.py` resolves `stomping`'s
    `targeted_adapter` through (contract §8): given one targeted
    `HuntExecutionContext`, run the unscored IOC-string scan over the single
    requested virtual-address range and return an `ObservationResult` with one
    `ioc_string_scan` closure. Stomping's module-header, reference-file,
    executable-section, relocation, and content-diff sources are not evaluated
    by it.

    The real implementation lives in `dumpex.hunt.stomping.targeted` and is
    imported lazily, for the same reason `_run_targeted_obfuscation` above
    imports its own."""
    from dumpex.hunt.stomping.targeted import run_targeted_stomping
    return run_targeted_stomping(context)


# ── Targeted report projectors (contract §8's own late-bound seam) ──────
# Each name below is what `_registry.py` resolves an analyzer's
# `targeted_report_projector` through: given the invocation's
# `HuntExecutionContext` and its adapter's own `ObservationResult`, return
# that analyzer's canonical `Report` built from the rescan's evidence by the
# SAME `aggregate.build_report()` full scope uses. Scoring, verdict tiers,
# check construction, and detail projection therefore have one authority per
# analyzer, and a targeted rescan cannot drift into a parallel scoring rule.
# The record's own coverage is rebuilt from the observation's closures
# afterwards (`dumpex.hunt._targeted_record`), never from these reports'
# full-scope-shaped coverage snapshots.


def _project_targeted_obfuscation(context, result):
    """`obfuscation`'s targeted report projector. Lazily imported for the
    same reason `_run_targeted_obfuscation` above imports its own."""
    from dumpex.hunt.encoding.targeted import project_targeted_report
    return project_targeted_report(context, result)


def _project_targeted_yara(context, result):
    """`yara`'s targeted report projector."""
    from dumpex.hunt.yara_hunt.targeted import project_targeted_report
    return project_targeted_report(context, result)


def _project_targeted_cs_beacon(context, result):
    """`cs-beacon`'s targeted report projector."""
    from dumpex.hunt.cs_beacon.targeted import project_targeted_report
    return project_targeted_report(context, result)


def _project_targeted_pipe(context, result):
    """`pipe`'s targeted report projector."""
    from dumpex.hunt.pipe.targeted import project_targeted_report
    return project_targeted_report(context, result)


def _project_targeted_stomping(context, result):
    """`stomping`'s targeted report projector."""
    from dumpex.hunt.stomping.targeted import project_targeted_report
    return project_targeted_report(context, result)


from dumpex.hunt.summary import build_hunt_summary
from dumpex.hunt import summary_presentation
from dumpex.hunt.region_correlation import build_region_correlations
from dumpex.hunt._investigation import build_investigation_queue
from dumpex.output.command_result import CommandResult
from dumpex.output.coverage import CoverageReport
from dumpex.output.records import HUNTERS

# Imported last, after every facade builder/renderer/collect import above:
# _registry.py's own top-level registration code resolves each
# dispatcher-facing name (e.g. `_build_injection_report`) off this module,
# so those names must already exist as attributes here first (see
# _registry.py's own module docstring and
# docs/developer/hunt_analyzer_registry_contract.md §6's "Module layout and import
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
from dumpex.hunt._request import HuntOptions, HuntRequest
from dumpex.hunt._execution import build_execution_context
from dumpex.hunt._targeted_console import print_targeted_console
from dumpex.hunt._targeted_record import build_targeted_record
from dumpex.output.records import hex_address


def _option_view(ref_dir: "str | None", yara_dir: "str | None") -> dict:
    """The ONE mapping from `_execute_full_scope()`'s public keyword
    parameters to the internal option names `AnalyzerSpec.option_names`
    values are drawn from. Built from `HuntOptions` so its key set is the
    same one `_execute_full_scope()` reads off `request.options` at
    execution time -- there is no second literal to drift from
    `_registry.KNOWN_OPTION_NAMES`. Called by the import-time drift guard
    immediately below; the executor reads `request.options.as_option_view()`
    directly."""
    return HuntOptions(ref_dir=ref_dir, rules_dir=yara_dir).as_option_view()


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
    # The one `HuntExecutionContext` this invocation built. Carried out so a
    # caller can read `context.observations.counts()` / `.event_overflow` --
    # the fact that an expensive observation was produced, reused,
    # unavailable, failed, or budget-exhausted is reachable, not dropped with
    # the context.
    context: object = None


def _execute_full_scope(mf: MinidumpFile, selected: str, *, ref_dir: str = None,
                         yara_dir: str = None, verbose: bool = False,
                         render: bool = False) -> _FullScopeExecution:
    """Build and project each selected full-scope analyzer exactly once.

    Registry selection preserves HUNTERS order. Each builder receives only its
    declared options; the resulting report feeds the record projector, optional
    renderer, and optional provenance hook. Collection mode never invokes console
    rendering. Callers validate the selected identity before this boundary so
    their public error contracts remain unchanged.

    One `HuntRequest` and one `HuntExecutionContext` are built per invocation --
    the request/observation/budget boundary every analyzer shares. The
    full-scope builders still read the dump handle directly; a builder opting
    into `context.observations` / `context.budgets` is a separate migration.
    """
    request = HuntRequest.full(selected, ref_dir=ref_dir, rules_dir=yara_dir)
    context = build_execution_context(mf, request)
    options = request.options.as_option_view()
    specs = _registry.REGISTRY.select(request.selected)

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
                f"options view {sorted(known)} -- HuntOptions and "
                f"_registry.KNOWN_OPTION_NAMES have drifted apart")

    records = []
    results = {}
    provenance = {}
    for spec in specs:
        kwargs = {name: options[name] for name in spec.option_names}
        builder_input = context if spec.builder_arg == "context" else context.mf
        report = spec.builder(builder_input, **kwargs)
        records.append(spec.record_projector(report))
        if render:
            results[spec.identity] = spec.renderer(report, verbose)
        if spec.provenance_hook is not None:
            provenance[spec.identity] = spec.provenance_hook(report)
    return _FullScopeExecution(records=records, results=results, provenance=provenance,
                               context=context)


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


def _rescan_dump_path(mf: MinidumpFile, redact_paths: bool) -> "str | None":
    """The dump path a skipped-target entry renders its `--hunt-addr` follow-up
    command for, or `None` for a MinidumpFile that never came from
    `open_dump()`. Under `--redact-paths` it is reduced to a basename, the same
    rule `dumpex.output.envelope` applies to every path it records: the console
    and `--txt` transcript are as shareable as the structured document, and the
    command still runs from the directory holding the dump."""
    path = getattr(mf, "filename", None)
    if not isinstance(path, str) or not path:
        return None
    return os.path.basename(path.rstrip("/\\")) if redact_paths else path


def cmd_hunt(mf: MinidumpFile, ttp: str, verbose: bool = False, yara_dir: str = None,
             ref_dir: str = None, collect_records: bool = False,
             redact_paths: bool = False):
    """Run selected hunters, render reports, and return their results.

    With collect_records false, return the legacy results dictionary. With it
    true, return results, typed records, investigation actions, and this
    invocation's YARA provenance. Each selected report is built once and shared
    by console and record projections.

    For hunt-all, the same metadata-only actions and summary feed console and
    structured output. Registry selection preserves fixed order and never skips
    an analyzer because an earlier analyzer scored zero. Its skipped-target
    section renders each eligible entry's targeted rescan for this dump's own
    path; `redact_paths` reduces that path to a basename, matching what
    `--redact-paths` does to every path in the structured document.
    """
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
        summary_presentation.render_hunt_summary(
            records, summary, doc_coverage.status.value,
            region_correlations=region_correlations,
            investigation_actions=investigation_actions,
            # The path this invocation was given, so a queue entry can render
            # the targeted rescan an analyst copies verbatim. The section
            # renders without commands rather than inventing one when the path
            # is unknown.
            dump_path=_rescan_dump_path(mf, redact_paths), verbose=verbose)

    if collect_records:
        return results, records, investigation_actions, yara_provenance
    return results



# ── Targeted (`--hunt-addr`) execution ─────────────────────────────────
# One invocation names one analyzer and one virtual-address range. Selection,
# capability, and the request ceiling are all resolved through the analyzer
# registry -- there is no second hunter/capability allowlist anywhere in the
# tree, and a command surface asks these functions rather than keeping its own.

class TargetedSelectionError(Exception):
    """`--hunt <ttp> --hunt-addr` names something no targeted rescan can run:
    an unknown analyzer, the `all` selection mode, an analyzer with no declared
    targeted capability, or one whose capability has no registered executor.
    Carries the finished user-facing sentence, so every command surface reports
    the same refusal for the same cause."""


@dataclass(frozen=True)
class TargetedSelection:
    """What a validated `--hunt <ttp> --hunt-addr` selection resolves to: the
    analyzer, the one coverage source that invocation runs, the full granted
    scope set for it (empty for an unscoped source), the analyzer's own frozen
    request-size ceiling in bytes, and the hunt options this targeted
    invocation actually reads.

    `consumed_options` is the registry's own answer, carried here so a command
    surface can refuse an option that would have no effect without keeping its
    own table of which analyzer reads what."""
    identity: str
    source: str
    scopes: frozenset
    request_ceiling: int
    consumed_options: frozenset


def targeted_hunters() -> tuple:
    """Every hunter a targeted rescan can name, in `HUNTERS` order -- the
    registry's own capability-and-executor filter (see
    `_registry.AnalyzerRegistry.targeted_identities`). Public so a command
    surface can render the supported set in help and error text without
    restating it."""
    return _registry.REGISTRY.targeted_identities()


def resolve_targeted_selection(ttp: str) -> TargetedSelection:
    """Resolve `ttp` to the targeted rescan it names, or raise
    `TargetedSelectionError`.

    Every refusal happens here, before a dump is opened and therefore before
    any scan work: `all` is a selection mode rather than an analyzer, an
    unknown name is unknown, and a real hunter without a registered targeted
    executor (`injection`/`hollowing` today) cannot run one. The registry's own
    typed failures are translated into one user-facing sentence each -- the
    supported set in that sentence is read from the registry, never listed
    here.
    """
    supported = ", ".join(targeted_hunters())
    if ttp == "all":
        raise TargetedSelectionError(
            f"--hunt-addr targets exactly one analyzer; 'all' is a selection mode, not an "
            f"analyzer. Choose one of: {supported}")
    try:
        source = _registry.REGISTRY.targeted_source(ttp)
        spec = _registry.REGISTRY.select_targeted_scopes(
            ttp, source, _registry.REGISTRY.granted_scopes(ttp, source))
    except _registry.UnknownAnalyzerIdentity:
        raise TargetedSelectionError(
            f"Unknown TTP '{ttp}'. --hunt-addr supports: {supported}") from None
    except (_registry.UnsupportedTargetedCapability,
            _registry.UnpopulatedTargetedGrant,
            _registry.UnsupportedTargetedSource,
            _registry.UnsupportedTargetedScope) as exc:
        raise TargetedSelectionError(
            f"'{ttp}' has no targeted-scan capability and cannot be run with --hunt-addr "
            f"({exc}). --hunt-addr supports: {supported}") from None
    except _registry.InvalidAnalyzerSpec as exc:
        # A registration-time invariant reaching a command means a registry was
        # assembled around a spec that bypassed `AnalyzerSpec` construction.
        # It still leaves through the ordinary user-facing Hunt error path
        # rather than as a traceback out of the CLI.
        raise TargetedSelectionError(
            f"'{ttp}' has a malformed targeted-scan capability and cannot be run with "
            f"--hunt-addr ({exc}). --hunt-addr supports: {supported}") from None
    if spec.targeted_adapter is None or spec.targeted_report_projector is None:
        raise TargetedSelectionError(
            f"'{ttp}' declares a targeted-scan capability but has no registered executor "
            f"for it. --hunt-addr supports: {supported}")
    return TargetedSelection(
        identity=spec.identity, source=source,
        scopes=_registry.REGISTRY.granted_scopes(ttp, source),
        request_ceiling=spec.targeted_capability.request_ceiling,
        consumed_options=spec.targeted_capability.consumed_options)


def targeted_scan_scope(request, result) -> dict:
    """The `targeted` variant of `summary.scan_scope` -- the normalized range
    and the capability it ran under, so a consumer can match a result back to
    the invocation that produced it without parsing a command line.

    `scopes` comes from the observation's ACTUAL closure scopes, not from the
    request's granted scope set. The two agree for obfuscation, whose grant IS
    its three layers, but pipe's grant is unscoped while its invocation closes
    `pipe_name` and `c2_context` independently -- and #66's reconciliation is
    keyed on `hunter + source + scope + base_address + size`, so a consumer
    reading `scan_scope` alone must not conclude the run was unscoped. This
    keeps `scan_scope.scopes` and `details.targeted_scope`'s own scopes in
    agreement by construction.
    """
    return {
        "kind": "targeted",
        "hunter": request.selected,
        "source": request.targeted_source,
        "scopes": sorted({closure.scope for closure in result.closures
                          if closure.scope is not None}),
        "base_address": hex_address(request.target_range.base_address),
        "size": request.target_range.size,
    }


@dataclass
class _TargetedExecution:
    """One targeted invocation's finished output: the `CommandResult` a command
    surface routes to console exit codes and `--json`, and this invocation's
    own YARA rule provenance (`None` for every other analyzer), threaded out
    the same way `_FullScopeExecution` carries it rather than read back from a
    process-wide global."""
    result: CommandResult
    yara_provenance: "dict | None" = None
    context: object = None


def execute_targeted(mf: MinidumpFile, request, *, verbose: bool = False,
                     render: bool = False) -> _TargetedExecution:
    """Run one already-validated targeted `HuntRequest` and project it exactly
    once.

    The request is built and validated by the caller (`HuntRequest.targeted()`
    resolves the grant and the request ceiling through the registry), so this
    function opens no second capability decision: it builds the invocation's
    execution context, resolves the registered adapter, runs it once, and
    projects the single `ObservationResult` into a record, a summary, and the
    document-level coverage the exit code derives from.

    `render=False` prints nothing at all -- the same silence guarantee
    `_execute_full_scope(render=False)` gives `collect_hunt()`.
    """
    context = build_execution_context(mf, request)
    spec, adapter = _registry.REGISTRY.resolve_targeted_adapter(
        request.selected, request.targeted_source, request.targeted_scopes)
    # Retained in the invocation's own observation registry under the key the
    # adapter built, so `context.observations.counts()` reports what actually
    # happened rather than staying empty. One targeted command calls one
    # adapter once, so this is instrumentation rather than deduplication --
    # the registry cannot gate the call itself without knowing the key before
    # it runs.
    observation = context.observations.record(adapter(context))
    projection = build_targeted_record(spec, context, observation)
    record = projection.record

    if render:
        print_targeted_console(record, observation, request, verbose)

    summary = build_hunt_summary([record], selected=request.selected,
                                  full_scope_hunters=full_scope_hunters(),
                                  scan_scope=targeted_scan_scope(request, observation))
    # A targeted rescan never builds the skipped-target queue: that queue is
    # `--hunt all`'s cross-hunter view of a whole dump, and one range's result
    # is not the evidence for it. The key stays present and empty so the
    # summary shape does not change with scope.
    summary["investigation_actions"] = []
    yara_provenance = (spec.provenance_hook(projection.report)
                       if spec.provenance_hook is not None else None)
    return _TargetedExecution(
        result=CommandResult(kind="hunt", records=[record],
                             coverage=_hunt_coverage_report([record], summary),
                             summary=summary),
        yara_provenance=yara_provenance, context=context)


def cmd_hunt_targeted(mf: MinidumpFile, request, verbose: bool = False) -> _TargetedExecution:
    """The console entry point for a targeted rescan -- renders the one card
    and returns the same `_TargetedExecution` `execute_targeted()` builds, so
    console and structured output come from ONE projection of ONE scan."""
    return execute_targeted(mf, request, verbose=verbose, render=True)
