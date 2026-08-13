"""Architecture contract for the hunt output-source migration.

These tests describe the target boundary for the ongoing migration:

* aggregate returns a frozen, deeply immutable domain Report;
* a Report stores Findings once, rather than keeping parallel console and
  JSON representations that can drift;
* aggregate consumes collected evidence, not the dump object or a console
  projection flag; and
* presentation consumes only the Report plus its projection choice.

Known gaps are marked ``xfail`` (strict) so this test-only commit does not
make the existing CI permanently red while the larger refactor is in
progress -- as soon as an implementation change satisfies one contract,
pytest reports XPASS as a failure until that case's marker is removed. Once
a boundary is actually satisfied, its marker is deleted in the SAME commit
that satisfies it (not left around as a permanently-skipped assertion) --
Finding.print()'s `level` contract and injection's aggregate/renderer
boundaries were the first three to convert; obfuscation's renderer boundary
converted incidentally when its unused `mf`/`susp_prots`/`modules`
parameters were dropped; injection's Report/parallel-findings/mutable-
collection boundaries converted with the Injection 2C cutover (production
now builds `dumpex.hunt.injection.domain.InjectionReport`, and the old
dict-`Report` module `dumpex.hunt.injection.aggregate.Report` no longer
exists); obfuscation's Report/parallel-findings/mutable-collection/
aggregate boundaries converted with the Encoding pilot (issue #5) --
production now builds `dumpex.hunt.encoding.domain.EncodingReport`, and
the old dict-`EncodingReport` in `dumpex.hunt.encoding.aggregate` and
`dumpex.hunt.encoding.presentation` no longer exist; stomping's
Report/parallel-findings/mutable-collection/aggregate boundaries converted
with the Stomping migration (issue #8) -- production now builds
`dumpex.hunt.stomping.domain.StompingReport`, and the old mutable
`dumpex.hunt.stomping.aggregate.Report` and
`dumpex.hunt.stomping.presentation` no longer exist; pipe's
Report/parallel-findings/mutable-collection/aggregate boundaries converted
with the Pipe migration (issue #7) -- production now builds
`dumpex.hunt.pipe.domain.PipeReport`, and the old mutable
`dumpex.hunt.pipe.aggregate.Report` and `dumpex.hunt.pipe.presentation` no
longer exist; hollowing's Report/parallel-findings/mutable-collection/
aggregate/renderer boundaries converted with the Hollowing migration
(issue #10) -- production now builds
`dumpex.hunt.hollowing.domain.HollowingReport`, the old mutable
`dumpex.hunt.hollowing.Report` (and the single-file module that held it) no
longer exists, and `_render_hollowing_console` no longer takes `mf`;
cs-beacon's Report/parallel-findings/mutable-collection/aggregate/renderer
boundaries converted with the CS Beacon migration (issue #9) -- production
now builds `dumpex.hunt.cs_beacon.domain.CSBeaconReport`, and the old
mutable `dumpex.hunt.cs_beacon.aggregate.Report` and
`dumpex.hunt.cs_beacon.presentation` no longer exist. To use the file as a
red/green implementation checklist, run it with
``pytest --runxfail tests/hunt/test_output_source_architecture.py``.
"""
import dataclasses
import enum
import inspect

import pytest

from dumpex.hunt import _finding
from dumpex.hunt.cs_beacon import aggregate as cs_beacon_aggregate
from dumpex.hunt.cs_beacon import domain as cs_beacon_domain
from dumpex.hunt.cs_beacon import report_console as cs_beacon_render
from dumpex.hunt.encoding import aggregate as encoding_aggregate
from dumpex.hunt.encoding import domain as encoding_domain
from dumpex.hunt.encoding import _render_encoding_console as encoding_render
from dumpex.hunt.hollowing import aggregate as hollowing_aggregate
from dumpex.hunt.hollowing import domain as hollowing_domain
from dumpex.hunt.hollowing import _render_hollowing_console as hollowing_render
from dumpex.hunt.injection import aggregate as injection_aggregate
from dumpex.hunt.injection import _render_injection_console as injection_render
from dumpex.hunt.injection import domain as injection_domain
from dumpex.hunt.pipe import aggregate as pipe_aggregate
from dumpex.hunt.pipe import domain as pipe_domain
from dumpex.hunt.pipe import _render_pipe_console as pipe_render
from dumpex.hunt.stomping import aggregate as stomping_aggregate
from dumpex.hunt.stomping import domain as stomping_domain
from dumpex.hunt.stomping import _render_stomping_console as stomping_render
from dumpex.hunt.yara_hunt import aggregate as yara_aggregate
from dumpex.hunt.yara_hunt import presentation as yara_presentation


_PENDING = pytest.mark.xfail(
    strict=True,
    reason="output-source architecture migration not implemented yet",
)


REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing_domain.HollowingReport, id="hollowing"),
    pytest.param(stomping_domain.StompingReport, id="stomping"),
    pytest.param(pipe_domain.PipeReport, id="pipe"),
    pytest.param(cs_beacon_domain.CSBeaconReport, id="cs-beacon"),
    pytest.param(encoding_domain.EncodingReport, id="obfuscation"),
    pytest.param(yara_aggregate.Report, id="yara", marks=_PENDING),
]


@pytest.mark.parametrize("report_type", REPORT_TYPES)
def test_domain_report_is_a_frozen_dataclass(report_type):
    """Top-level Report attributes must not change after aggregation."""
    assert dataclasses.is_dataclass(report_type)
    assert report_type.__dataclass_params__.frozen is True


PARALLEL_FINDING_REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing_domain.HollowingReport, id="hollowing"),
    pytest.param(stomping_domain.StompingReport, id="stomping"),
    pytest.param(pipe_domain.PipeReport, id="pipe"),
    pytest.param(cs_beacon_domain.CSBeaconReport, id="cs-beacon"),
    pytest.param(encoding_domain.EncodingReport, id="obfuscation"),
]


@pytest.mark.parametrize("report_type", PARALLEL_FINDING_REPORT_TYPES)
def test_report_does_not_store_parallel_findings_representations(report_type):
    """Console and structured output must not read separate stored copies."""
    field_names = {field.name for field in dataclasses.fields(report_type)}
    assert not {"findings", "findings_list"}.issubset(field_names), (
        f"{report_type.__module__}.{report_type.__name__} stores both the "
        "structured findings payload and a second Finding list"
    )


MUTABLE_COLLECTION_REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing_domain.HollowingReport, id="hollowing"),
    pytest.param(stomping_domain.StompingReport, id="stomping"),
    pytest.param(pipe_domain.PipeReport, id="pipe"),
    pytest.param(cs_beacon_domain.CSBeaconReport, id="cs-beacon"),
    pytest.param(encoding_domain.EncodingReport, id="obfuscation"),
]

# Per-(report_type, required-field-name) construction overrides, consulted
# before the generic {}/[]/None guesses below -- needed for a Report type
# whose required fields are ordinary validated scalars/value-objects (not
# the old dict-`Report`'s own `findings`/`findings_list` collections),
# which legitimately reject `None` at construction. `InjectionReport`/
# `EncodingReport`/`StompingReport`/`PipeReport`/`HollowingReport` all need
# one: their required fields are `score` (an int) and `coverage` (a
# `CoverageSnapshot`), both of which validate their input.
_REQUIRED_FIELD_OVERRIDES = {
    (injection_domain.InjectionReport, "score"): 0,
    (injection_domain.InjectionReport, "coverage"): injection_domain.CoverageSnapshot(
        memory_info_stream=False, thread_info_stream=False,
        module_list_stream=False, thread_list_stream=False),
    (encoding_domain.EncodingReport, "score"): 0,
    (encoding_domain.EncodingReport, "coverage"): encoding_domain.CoverageSnapshot(
        memory_info_stream=False),
    (stomping_domain.StompingReport, "score"): 0,
    (stomping_domain.StompingReport, "coverage"): stomping_domain.CoverageSnapshot(
        memory_info_stream=False, module_list_stream=False),
    (pipe_domain.PipeReport, "score"): 0,
    (pipe_domain.PipeReport, "coverage"): pipe_domain.CoverageSnapshot(
        memory_info_stream=False, handle_data_stream=False),
    (hollowing_domain.HollowingReport, "score"): 0,
    # peb_present=False is also what pins `context` to its own None default:
    # HollowingReport refuses a Report that claims the run evaluated while
    # carrying no resolved image base (see its own __post_init__).
    (hollowing_domain.HollowingReport, "coverage"): hollowing_domain.CoverageSnapshot(
        peb_present=False),
    (cs_beacon_domain.CSBeaconReport, "score"): 0,
    (cs_beacon_domain.CSBeaconReport, "coverage"): cs_beacon_domain.CoverageSnapshot(
        scan=cs_beacon_domain.ScanDiagnostics(segment_count=0)),
}


@pytest.mark.parametrize("report_type", MUTABLE_COLLECTION_REPORT_TYPES)
def test_report_does_not_retain_mutable_collection_state(report_type):
    """Frozen must be deep: lists/dicts/sets cannot remain mutable inside."""
    required_values = {}
    for field in dataclasses.fields(report_type):
        if (
            field.default is dataclasses.MISSING
            and field.default_factory is dataclasses.MISSING
        ):
            override_key = (report_type, field.name)
            required_values[field.name] = (
                _REQUIRED_FIELD_OVERRIDES[override_key] if override_key in _REQUIRED_FIELD_OVERRIDES
                else {} if field.name == "findings"
                else [] if field.name == "findings_list"
                else None
            )

    report = report_type(**required_values)
    mutable_fields = {
        field.name
        for field in dataclasses.fields(report)
        if isinstance(getattr(report, field.name), (dict, list, set))
    }
    assert not mutable_fields, (
        f"{report_type.__module__}.{report_type.__name__} retains mutable "
        f"collection field(s): {sorted(mutable_fields)}"
    )


def test_finding_detail_level_replaces_string_projection_modes():
    """Finding projection is a typed two-level policy, not string switches."""
    detail_level = getattr(_finding, "DetailLevel", None)
    assert inspect.isclass(detail_level) and issubclass(detail_level, enum.Enum)
    assert {"NORMAL", "VERBOSE"}.issubset(detail_level.__members__)

    parameter_names = set(inspect.signature(_finding.Finding.print).parameters)
    assert "level" in parameter_names
    assert not parameter_names & {"facts_mode", "verbose"}


AGGREGATORS_WITH_PENDING_BOUNDARY_FIXES = [
    pytest.param(injection_aggregate.build_report, id="injection"),
    # Converted (marker removed) with the Pipe migration: its new
    # signature takes typed evidence tuples plus int/bool/str scalars only
    # -- no `mf`, no `verbose`, and no live CoverageTracker/ScanBudget
    # (only the scalars those resolved to).
    pytest.param(pipe_aggregate.build_report, id="pipe"),
    pytest.param(encoding_aggregate.build_report, id="obfuscation"),
    # Added (never _PENDING) with the Stomping migration: its new
    # signature takes typed evidence tuples plus int/bool scalars only --
    # no `mf`, no `verbose`, and no `ref_dir` PATH (only a
    # `ref_dir_supplied` bool), so it satisfies this contract on arrival.
    pytest.param(stomping_aggregate.build_report, id="stomping"),
    # Added (never _PENDING) with the Hollowing migration: its new
    # signature takes typed evidence tuples plus an already-resolved
    # `ImageBaseContext` and bool scalars only -- no `mf`, no `verbose`, no
    # raw regions/modules lists, and no `peb` object.
    pytest.param(hollowing_aggregate.build_report, id="hollowing"),
    # Added (never _PENDING) with the CS Beacon migration: its new
    # signature takes typed evidence tuples (hits/corroborations) plus an
    # already-resolved `ScanDiagnostics` and bool/int scalars only -- no
    # `mf`, no `verbose`, and no live `CoverageTracker`/`ScanOutcome`.
    pytest.param(cs_beacon_aggregate.build_report, id="cs-beacon"),
]


@pytest.mark.parametrize("build_report", AGGREGATORS_WITH_PENDING_BOUNDARY_FIXES)
def test_aggregate_accepts_evidence_not_dump_or_projection_state(build_report):
    """Dump access belongs to scan/enrichment; verbosity belongs to render."""
    parameter_names = set(inspect.signature(build_report).parameters)
    forbidden = parameter_names & {"mf", "verbose", "detail_level", "level"}
    assert not forbidden, (
        f"{build_report.__module__}.{build_report.__name__} still accepts "
        f"non-evidence concern(s): {sorted(forbidden)}"
    )


def test_injection_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above: `mf`/`verbose` are not
    the only way a raw dump reference can cross into aggregate.py -- a
    keyword-only `all_regions`/`thread_info_entries`/`module_list` (a raw
    minidump Region/ThreadInfo/Module list, passed straight from
    `_build_injection_report()`) crossed that same boundary without ever
    matching that blacklist. This is a whitelist instead: every parameter
    `build_report()` accepts must be one of the typed Evidence/Correlation/
    HiddenPeScan objects it's built from, or a plain bool/int scalar --
    counts derived from a raw list (`region_count`/`thread_info_count`/
    `module_count`) are the scan layer's job to compute; aggregate only
    ever sees the resulting int."""
    allowed = {
        "rwx", "hidden_pe_scan", "validated_pe_hits", "mz_only_hits",
        "start_threads", "thread_contexts", "correlation",
        "memory_info_stream", "thread_info_stream", "module_list_stream",
        "thread_list_stream", "threads_total", "contexts_parsed",
        "region_count", "thread_info_count", "module_count",
    }
    parameter_names = set(inspect.signature(injection_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.injection.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


def test_cs_beacon_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. Every parameter
    `build_report()` accepts must be one of the typed evidence
    tuples/objects it's built from, or a plain bool/int scalar."""
    allowed = {
        "hits", "corroborations", "scan", "mem_info_available",
        "thread_list_stream_available", "threads_total", "contexts_parsed",
    }
    parameter_names = set(inspect.signature(cs_beacon_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.cs_beacon.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


RENDERERS = [
    pytest.param(injection_render, id="injection"),
    pytest.param(hollowing_render, id="hollowing"),
    pytest.param(stomping_render, id="stomping"),
    pytest.param(pipe_render, id="pipe"),
    pytest.param(cs_beacon_render.print_console, id="cs-beacon"),
    pytest.param(encoding_render, id="obfuscation"),
    pytest.param(yara_presentation.render_result, id="yara", marks=_PENDING),
]


@pytest.mark.parametrize("render", RENDERERS)
def test_console_renderer_only_accepts_report_and_projection_choice(render):
    """Rendering must not require the dump, modules, rules, or raw scans."""
    parameter_names = set(inspect.signature(render).parameters)
    unexpected = parameter_names - {"report", "verbose", "level"}
    assert not unexpected, (
        f"{render.__module__}.{render.__name__} still accepts external "
        f"evidence source(s): {sorted(unexpected)}"
    )
