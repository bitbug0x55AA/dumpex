"""Architecture contract for the hunt output-source migration.

Every hunter in this migration series (injection, encoding, stomping,
pipe, hollowing, cs-beacon, yara) now satisfies every contract below; no
`xfail`/`_PENDING` marker remains anywhere in this file. This is a plain
assertion suite, exercised directly against each hunter's real
`aggregate.build_report()`/domain `Report` type/console renderer:

* aggregate returns a frozen, deeply immutable domain Report;
* a Report stores Findings once, rather than keeping parallel console and
  JSON representations that can drift;
* aggregate consumes collected evidence, not the dump object or a console
  projection flag; and
* presentation consumes only the Report plus its projection choice.

Historical note, kept for provenance: while this migration was in
progress, unconverted contracts were marked `xfail(strict)` so the
in-progress suite didn't turn CI permanently red, and each marker was
deleted in the same commit that satisfied its contract (Finding.print()'s
`level` contract and injection's aggregate/renderer boundaries were the
first three to convert; obfuscation's renderer boundary converted
incidentally when its unused `mf`/`susp_prots`/`modules` parameters were
dropped; injection's Report/parallel-findings/mutable-collection
boundaries converted with the Injection 2C cutover; obfuscation's
Report/parallel-findings/mutable-collection/aggregate boundaries converted
with the Encoding pilot (issue #5); stomping's with the Stomping migration
(issue #8); pipe's with the Pipe migration (issue #7); hollowing's
Report/parallel-findings/mutable-collection/aggregate/renderer boundaries
with the Hollowing migration (issue #10), which also dropped `mf` from
`_render_hollowing_console`; cs-beacon's with the CS Beacon migration
(issue #9); and yara's Report/aggregate/renderer boundaries with the YARA
migration (issue #11) -- yara deliberately does not build a
`findings`/`findings_list` pair at all (see domain.py's own docstring on
why it stays off the shared Finding model), so it was never added to
`PARALLEL_FINDING_REPORT_TYPES` in the first place.
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
from dumpex.hunt.injection import models as injection_models
from dumpex.hunt.pipe import aggregate as pipe_aggregate
from dumpex.hunt.pipe import domain as pipe_domain
from dumpex.hunt.pipe import _render_pipe_console as pipe_render
from dumpex.hunt.stomping import aggregate as stomping_aggregate
from dumpex.hunt.stomping import domain as stomping_domain
from dumpex.hunt.stomping import _render_stomping_console as stomping_render
from dumpex.hunt.yara_hunt import aggregate as yara_aggregate
from dumpex.hunt.yara_hunt import domain as yara_domain
from dumpex.hunt.yara_hunt import report_console as yara_render
from dumpex.hunt.yara_hunt import scanner as yara_scanner


REPORT_TYPES = [
    pytest.param(injection_domain.InjectionReport, id="injection"),
    pytest.param(hollowing_domain.HollowingReport, id="hollowing"),
    pytest.param(stomping_domain.StompingReport, id="stomping"),
    pytest.param(pipe_domain.PipeReport, id="pipe"),
    pytest.param(cs_beacon_domain.CSBeaconReport, id="cs-beacon"),
    pytest.param(encoding_domain.EncodingReport, id="obfuscation"),
    pytest.param(yara_domain.YaraReport, id="yara"),
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


# One explicit "nothing observed" builder per hunter, each calling that
# hunter's own real `aggregate.build_report()` -- the same production entry
# point `_hunt_<name>()` calls -- rather than guessing a Report's required
# fields generically from `dataclasses.fields()`. This makes each hunter's
# minimal shape self-documenting instead of relying on a shared guesser
# patched with per-field overrides.

def _minimal_injection_report():
    return injection_aggregate.build_report(
        rwx=(), hidden_pe_scan=injection_models.HiddenPeScan(
            hits=(), read_failed=0, short_reads=0, scan_truncated=0),
        validated_pe_hits=(), mz_only_hits=(),
        start_threads=(), thread_contexts=(),
        correlation=injection_models.Correlation(),
        memory_info_stream=False, thread_info_stream=False,
        module_list_stream=False, thread_list_stream=False,
        threads_total=0, contexts_parsed=0,
    )


def _minimal_hollowing_report():
    return hollowing_aggregate.build_report()


def _minimal_stomping_report():
    return stomping_aggregate.build_report()


def _minimal_pipe_report():
    return pipe_aggregate.build_report()


def _minimal_cs_beacon_report():
    return cs_beacon_aggregate.build_report(
        scan=cs_beacon_domain.ScanDiagnostics(segment_count=0))


def _minimal_encoding_report():
    return encoding_aggregate.build_report(
        (), (), (), (), (),
        memory_info_stream=False, region_count=0, any_region_scanned=False,
    )


def _minimal_yara_report():
    return yara_aggregate.build_report(
        scan_result=yara_scanner.ScanResult(
            matches=(), diagnostics=yara_domain.ScanDiagnostics()),
        rules=yara_domain.RulesDiagnostics(),
    )


MINIMAL_REPORT_BUILDERS = [
    pytest.param(_minimal_injection_report, id="injection"),
    pytest.param(_minimal_hollowing_report, id="hollowing"),
    pytest.param(_minimal_stomping_report, id="stomping"),
    pytest.param(_minimal_pipe_report, id="pipe"),
    pytest.param(_minimal_cs_beacon_report, id="cs-beacon"),
    pytest.param(_minimal_encoding_report, id="obfuscation"),
    pytest.param(_minimal_yara_report, id="yara"),
]


@pytest.mark.parametrize("build_minimal_report", MINIMAL_REPORT_BUILDERS)
def test_report_does_not_retain_mutable_collection_state(build_minimal_report):
    """Frozen must be deep: lists/dicts/sets cannot remain mutable inside."""
    report = build_minimal_report()
    mutable_fields = {
        field.name
        for field in dataclasses.fields(report)
        if isinstance(getattr(report, field.name), (dict, list, set))
    }
    assert not mutable_fields, (
        f"{type(report).__module__}.{type(report).__name__} retains mutable "
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


# Every hunter's `aggregate.build_report()` signature, checked below against
# the blacklist of non-evidence concerns (`mf`/`verbose`/`detail_level`/
# `level`) that dump access and verbosity/projection state would otherwise
# leak across. See the narrower per-hunter whitelist tests further down for
# hunters where the full allowed-parameter set is pinned explicitly.
AGGREGATOR_BUILD_REPORT_SIGNATURES = [
    pytest.param(injection_aggregate.build_report, id="injection"),
    pytest.param(pipe_aggregate.build_report, id="pipe"),
    pytest.param(encoding_aggregate.build_report, id="obfuscation"),
    pytest.param(stomping_aggregate.build_report, id="stomping"),
    pytest.param(hollowing_aggregate.build_report, id="hollowing"),
    pytest.param(cs_beacon_aggregate.build_report, id="cs-beacon"),
    pytest.param(yara_aggregate.build_report, id="yara"),
]


@pytest.mark.parametrize("build_report", AGGREGATOR_BUILD_REPORT_SIGNATURES)
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


def test_yara_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. `build_report()`
    accepts exactly the typed `scanner.ScanResult` (evidence tuple +
    ScanDiagnostics) and `domain.RulesDiagnostics` it is built from --
    never `mf`, raw `modules`/`regions`, or a mutable `ScanOutcome`."""
    allowed = {"scan_result", "rules"}
    parameter_names = set(inspect.signature(yara_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.yara_hunt.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


def test_pipe_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. Every parameter
    `build_report()` accepts must be one of the typed evidence
    tuples/objects it's built from, or a plain bool/int/str scalar."""
    allowed = {
        "handle_pipes", "string_leads", "corroborated_handles",
        "start_address_leads", "c2_context", "framework_string_hits",
        "unbacked_threads", "memory_info_stream", "handle_data_stream",
        "skipped_oversize", "read_failed", "read_failed_targets",
        "short_reads", "short_read_targets", "c2_budget_exhausted",
        "c2_budget_reason", "pipe_name_budget_exhausted",
        "pipe_name_budget_reason", "image_pipe_refs", "image_pipe_modules",
        # the ledger's two directions, scalar counts
        "rule_version", "unaccounted", "over_accounted", "ledger_imbalance",
    }
    parameter_names = set(inspect.signature(pipe_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.pipe.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


def test_encoding_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. Every parameter
    `build_report()` accepts must be one of the typed evidence
    tuples it's built from, or a plain bool/int scalar."""
    allowed = {
        "sleep_mask_hits", "entropy_hits", "base64_hits", "xor_hits",
        "compressed_hits", "memory_info_stream", "region_count",
        "any_region_scanned", "sleep_mask_oversized", "entropy_oversized",
        "decode_oversized", "sleep_mask_read_failed", "entropy_read_failed",
        "decode_read_failed", "sleep_mask_short_read", "entropy_short_read",
        "decode_short_read", "budget_exhausted", "exhausted_reason",
        # the ledger's two directions, per scan layer
        "sleep_mask_unaccounted", "entropy_unaccounted", "decode_unaccounted",
        "sleep_mask_over_accounted", "entropy_over_accounted", "decode_over_accounted",
        "sleep_mask_imbalance", "entropy_imbalance", "decode_imbalance",
    }
    parameter_names = set(inspect.signature(encoding_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.encoding.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


def test_stomping_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. Every parameter
    `build_report()` accepts must be one of the typed evidence
    tuples it's built from, or a plain bool/int scalar."""
    allowed = {
        "protection_leads", "rip_correlated_leads", "verified_changes",
        "identity_mismatches", "parse_failures", "ioc_hits",
        "memory_info_stream", "module_list_stream", "ref_dir_supplied",
        "modules_total", "headers_parsed", "sections_total",
        "sections_compared", "reference_missing", "reference_mismatch",
        "reference_read_failed", "memory_read_failed", "short_reads",
        "relocation_failed", "header_read_failed", "header_parse_failed",
        "ioc_oversized", "ioc_read_failed", "ioc_read_failed_targets",
        "ioc_short_reads", "ioc_short_read_targets",
        "ioc_whitelisted_modules",
        "ioc_unaccounted", "ioc_over_accounted",   # the ledger's two directions
        "ioc_ledger_imbalance",
    }
    parameter_names = set(inspect.signature(stomping_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.stomping.aggregate.build_report accepts unexpected "
        f"parameter(s) {sorted(unexpected)} -- confirm any new parameter is "
        f"typed evidence or a scalar count, never a raw dump-derived list"
    )


def test_hollowing_aggregate_receives_only_typed_evidence_and_scalars():
    """Narrower than the name-blacklist check above -- see
    `test_injection_aggregate_receives_only_typed_evidence_and_scalars`'s
    own docstring for why a whitelist is needed at all. Every parameter
    `build_report()` accepts must be one of the typed evidence tuples/
    context object it's built from, or a plain bool scalar."""
    allowed = {
        "mem_private", "wiped_headers", "rwx", "name_mismatches",
        "correlations", "context", "peb_present", "image_base_region_found",
        "mz_read_failed", "modules_available",
    }
    parameter_names = set(inspect.signature(hollowing_aggregate.build_report).parameters)
    unexpected = parameter_names - allowed
    assert not unexpected, (
        f"dumpex.hunt.hollowing.aggregate.build_report accepts unexpected "
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
    pytest.param(yara_render.print_console, id="yara"),
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
