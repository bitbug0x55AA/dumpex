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
parameters were dropped. To use the file as a red/green implementation
checklist, run it with
``pytest --runxfail tests/hunt/test_output_source_architecture.py``.
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
from dumpex.hunt.injection import presentation as injection_presentation
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
    pytest.param(injection_aggregate.Report, id="injection", marks=_PENDING),
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
    pytest.param(injection_aggregate.Report, id="injection", marks=_PENDING),
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
    pytest.param(injection_aggregate.Report, id="injection", marks=_PENDING),
    pytest.param(stomping_aggregate.Report, id="stomping", marks=_PENDING),
    pytest.param(pipe_aggregate.Report, id="pipe", marks=_PENDING),
    pytest.param(cs_beacon_aggregate.Report, id="cs-beacon", marks=_PENDING),
    pytest.param(encoding_aggregate.EncodingReport, id="obfuscation", marks=_PENDING),
]


@pytest.mark.parametrize("report_type", MUTABLE_COLLECTION_REPORT_TYPES)
def test_report_does_not_retain_mutable_collection_state(report_type):
    """Frozen must be deep: lists/dicts/sets cannot remain mutable inside."""
    required_values = {}
    for field in dataclasses.fields(report_type):
        if (
            field.default is dataclasses.MISSING
            and field.default_factory is dataclasses.MISSING
        ):
            required_values[field.name] = (
                {} if field.name == "findings"
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


RENDERERS = [
    pytest.param(injection_presentation.render, id="injection"),
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
