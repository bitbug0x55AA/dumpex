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
exists). To use the file as a red/green implementation checklist, run it
with ``pytest --runxfail tests/hunt/test_output_source_architecture.py``.
"""
import dataclasses
import enum
import inspect

import pytest

from dumpex.hunt import _finding, hollowing
from dumpex.hunt.cs_beacon import aggregate as cs_beacon_aggregate
from dumpex.hunt.cs_beacon import presentation as cs_beacon_presentation
from dumpex.hunt.encoding import aggregate as encoding_aggregate
from dumpex.hunt.encoding import presentation as encoding_presentation
from dumpex.hunt.injection import aggregate as injection_aggregate
from dumpex.hunt.injection import _render_injection_console as injection_render
from dumpex.hunt.injection import domain as injection_domain
from dumpex.hunt.pipe import aggregate as pipe_aggregate
from dumpex.hunt.pipe import presentation as pipe_presentation
from dumpex.hunt.stomping import aggregate as stomping_aggregate
from dumpex.hunt.stomping import presentation as stomping_presentation
from dumpex.hunt.yara_hunt import aggregate as yara_aggregate
from dumpex.hunt.yara_hunt import presentation as yara_presentation


_PENDING = pytest.mark.xfail(
    strict=True,
    reason="output-source architecture migration not implemented yet",
)


REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing.Report, id="hollowing", marks=_PENDING),
    pytest.param(stomping_aggregate.Report, id="stomping", marks=_PENDING),
    pytest.param(pipe_aggregate.Report, id="pipe", marks=_PENDING),
    pytest.param(cs_beacon_aggregate.Report, id="cs-beacon", marks=_PENDING),
    pytest.param(encoding_aggregate.EncodingReport, id="obfuscation", marks=_PENDING),
    pytest.param(yara_aggregate.Report, id="yara", marks=_PENDING),
]


@pytest.mark.parametrize("report_type", REPORT_TYPES)
def test_domain_report_is_a_frozen_dataclass(report_type):
    """Top-level Report attributes must not change after aggregation."""
    assert dataclasses.is_dataclass(report_type)
    assert report_type.__dataclass_params__.frozen is True


PARALLEL_FINDING_REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing.Report, id="hollowing", marks=_PENDING),
    pytest.param(stomping_aggregate.Report, id="stomping", marks=_PENDING),
    pytest.param(pipe_aggregate.Report, id="pipe", marks=_PENDING),
    pytest.param(cs_beacon_aggregate.Report, id="cs-beacon", marks=_PENDING),
    pytest.param(encoding_aggregate.EncodingReport, id="obfuscation", marks=_PENDING),
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
    pytest.param(stomping_aggregate.Report, id="stomping", marks=_PENDING),
    pytest.param(pipe_aggregate.Report, id="pipe", marks=_PENDING),
    pytest.param(cs_beacon_aggregate.Report, id="cs-beacon", marks=_PENDING),
    pytest.param(encoding_aggregate.EncodingReport, id="obfuscation", marks=_PENDING),
]

# Per-(report_type, required-field-name) construction overrides, consulted
# before the generic {}/[]/None guesses below -- needed for a Report type
# whose required fields are ordinary validated scalars/value-objects (not
# the old dict-`Report`'s own `findings`/`findings_list` collections),
# which legitimately reject `None` at construction. `InjectionReport` is
# the first (and, while the migration is in progress, only) type that
# needs one: its required fields are `score` (an int) and `coverage` (a
# `CoverageSnapshot`), both of which validate their input.
_REQUIRED_FIELD_OVERRIDES = {
    (injection_domain.InjectionReport, "score"): 0,
    (injection_domain.InjectionReport, "coverage"): injection_domain.CoverageSnapshot(
        memory_info_stream=False, thread_info_stream=False,
        module_list_stream=False, thread_list_stream=False),
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
    pytest.param(pipe_aggregate.build_report, id="pipe", marks=_PENDING),
    pytest.param(encoding_aggregate.build_report, id="obfuscation", marks=_PENDING),
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


RENDERERS = [
    pytest.param(injection_render, id="injection"),
    pytest.param(hollowing._render_hollowing_console, id="hollowing", marks=_PENDING),
    pytest.param(stomping_presentation.render, id="stomping"),
    pytest.param(pipe_presentation.render, id="pipe"),
    pytest.param(cs_beacon_presentation.render, id="cs-beacon"),
    pytest.param(encoding_presentation.render, id="obfuscation"),
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
