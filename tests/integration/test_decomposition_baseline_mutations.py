"""
Mutation controls for the decomposition baseline: each test applies one
representative perturbation of the kind a relocation could introduce and
asserts the baseline notices it. A baseline that stays green under these
would be proving nothing.

The last section runs the opposite controls: structural moves -- a pure
re-export facade, definitions re-executed in a different owner module --
that the baseline must accept without any difference.

Every perturbation is applied with `monkeypatch` and undone after the test.
All `dumpex` modules are imported before any perturbation: a consumer
module imported for the first time while a legacy name is patched would
bind the patched object for the rest of the process.
"""
import dataclasses
import importlib
import importlib.util
import pkgutil
import sys
import types

import pytest

import dumpex
import dumpex.core.memory as memory
import dumpex.output.coverage as cov
import dumpex.output.records as records
from tests.fixtures.decomposition_baseline import TARGET_MODULES, capture, seams
from tests.fixtures.decomposition_baseline.cli_matrix import SCENARIO_BY_NAME, golden_name, run_scenario
from tests.fixtures.decomposition_baseline.coverage_corpus import (
    capture_coverage_corpus, unaccounted_vocabularies)
from tests.fixtures.decomposition_baseline.record_corpus import capture_record_corpus
from tests.fixtures.decomposition_baseline.stable import (
    diff, dumps, golden_path, load_golden, roundtrip)
from tests.fixtures.decomposition_baseline.relocation import (
    FUNCTIONS, INTERNALS, split_relocation)
from tests.fixtures.decomposition_baseline.surface import (
    capture_contract, capture_structure, duplicate_definitions, duplicate_source_definitions)
from tests.unit import test_memory_baseline_characterization as characterization
from tests.unit import test_memory_patch_seams as seam_tests

for _module in pkgutil.walk_packages(dumpex.__path__, "dumpex."):
    if _module.name != "dumpex.__main__":   # importing it runs the CLI
        importlib.import_module(_module.name)


def _contract_diff():
    contract, _ = capture.committed_surfaces()
    return diff(load_golden(capture.SURFACE_CONTRACT), roundtrip(contract))


def _corpus_diff(name, captured):
    return diff(load_golden(name), roundtrip(captured))


def _cli_diff(name, monkeypatch, tmp_path):
    scenario = SCENARIO_BY_NAME[name]
    return diff(load_golden(golden_name(scenario)),
                roundtrip(run_scenario(scenario, monkeypatch, str(tmp_path))))


def _any_mentions(differences, *fragments):
    return any(all(f in d for f in fragments) for d in differences)


def test_unperturbed_baseline_is_clean(monkeypatch, tmp_path):
    assert _contract_diff() == []
    assert _corpus_diff(capture.RECORD_CORPUS, capture_record_corpus()) == []
    assert _corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus()) == []
    assert _cli_diff("threads", monkeypatch, tmp_path) == []


# ── Lost export ───────────────────────────────────────────────────────────


def test_lost_export_is_detected(monkeypatch):
    monkeypatch.delattr(records, "hex_address")
    assert _any_mentions(_contract_diff(), "dumpex.output.records", "hex_address", "missing")


def test_lost_private_compatibility_name_is_detected(monkeypatch):
    monkeypatch.delattr(memory, "_resolve_size")
    assert _any_mentions(_contract_diff(), "dumpex.core.memory", "_resolve_size", "missing")


# ── Validator, default and order drift ────────────────────────────────────


def test_dropped_validator_is_detected(monkeypatch):
    monkeypatch.setattr(records.ThreadRecord, "__post_init__", lambda self: None)
    differences = _corpus_diff(capture.RECORD_CORPUS, capture_record_corpus())
    assert _any_mentions(differences, "ThreadRecord", "probes")


def _replace_everywhere(monkeypatch, target, name, replacement):
    """Replace `target.name` in every loaded dumpex namespace that binds the
    same object: the legacy path and each owner module whose validators
    resolve it at call time."""
    real = getattr(target, name)
    for module in list(sys.modules.values()):
        if (getattr(module, "__name__", "").split(".")[0] == "dumpex"
                and vars(module).get(name) is real):
            monkeypatch.setattr(module, name, replacement)


def test_changed_validation_message_is_detected(monkeypatch):
    real = records._require_nonneg_int

    def reworded(value, field_name):
        try:
            real(value, field_name)
        except ValueError:
            raise ValueError(f"{field_name} is invalid") from None

    _replace_everywhere(monkeypatch, records, "_require_nonneg_int", reworded)
    differences = _corpus_diff(capture.RECORD_CORPUS, capture_record_corpus())
    assert _any_mentions(differences, "probes")


def test_changed_field_default_is_detected(monkeypatch):
    field = records.ThreadRecord.__dataclass_fields__["ip_context_conflict"]
    monkeypatch.setattr(field, "default", None)
    assert _any_mentions(_contract_diff(), "ThreadRecord")


def test_reordered_vocabulary_is_detected(monkeypatch):
    monkeypatch.setattr(records, "HUNTERS", tuple(reversed(records.HUNTERS)))
    assert _any_mentions(_contract_diff(), "HUNTERS")


def test_reordered_code_registry_is_detected(monkeypatch):
    monkeypatch.setattr(cov, "_CODE_SPECS", dict(reversed(list(cov._CODE_SPECS.items()))))
    differences = _corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus())
    assert _any_mentions(differences, "code_specs")


# ── Changed text ──────────────────────────────────────────────────────────


def test_changed_limitation_text_is_detected(monkeypatch):
    code = cov.LimitationCode.SOURCE_ABSENT
    monkeypatch.setitem(cov._CODE_SPECS, code,
                        dataclasses.replace(cov._CODE_SPECS[code], render=lambda lim: "changed"))
    differences = _corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus())
    assert _any_mentions(differences, "render", "changed")


def test_changed_console_and_json_text_is_detected(monkeypatch, tmp_path):
    monkeypatch.setitem(cov._SOURCE_DISPLAY_NAMES, "thread_info", "ThreadInfoStream")
    differences = _cli_diff("threads", monkeypatch, tmp_path)
    assert _any_mentions(differences, "$.stdout")
    assert _any_mentions(differences, "$.json.result.coverage")


# ── Skipped patch seam ────────────────────────────────────────────────────


def test_relocated_function_that_skips_the_legacy_seam_is_detected(monkeypatch):
    """`enriched_thread_contexts` defined in a module of its own resolves
    its readers in that module's namespace, so a patch applied to
    `dumpex.core.memory.get_thread_contexts` does not reach it."""
    relocated = types.FunctionType(memory.enriched_thread_contexts.__code__,
                                   dict(vars(memory)), "enriched_thread_contexts")
    monkeypatch.setattr(memory, "enriched_thread_contexts", relocated)
    inner = pytest.MonkeyPatch()
    try:
        with pytest.raises(AssertionError, match="get_thread_contexts"):
            seams.check_thread_readers_reach_enriched_contexts(inner)
    finally:
        inner.undo()


# ── Hole read as complete ─────────────────────────────────────────────────


def test_hole_reported_as_captured_is_detected(monkeypatch, tmp_path):
    monkeypatch.setattr(memory, "va_range_captured_bytes",
                        lambda mf, va, size: max(size, 0) if va else 0)
    mf = characterization._open(tmp_path, characterization._gapped_spec())
    try:
        with pytest.raises(AssertionError):
            characterization.test_va_range_captured_bytes(mf, 0x10000, 0x3000, 0x2000)
    finally:
        mf.file_handle.close()


def test_hole_zero_filled_by_a_read_is_detected(monkeypatch, tmp_path):
    real = memory.read_region_spanning
    monkeypatch.setattr(memory, "read_region_spanning",
                        lambda mf, va, size: real(mf, va, size).ljust(max(size, 0), b"\x00"))
    mf = characterization._open(tmp_path, characterization._gapped_spec())
    try:
        with pytest.raises(AssertionError):
            characterization.test_read_primitives(mf, *characterization.READ_CASES["inside_hole"])
    finally:
        mf.file_handle.close()


@pytest.mark.parametrize("case", ["into_adjacent_segment", "whole_adjacent_run"])
def test_corrupted_middle_of_a_spanning_read_is_detected(monkeypatch, tmp_path, case):
    """A read that returns the right length and the right first and last
    bytes, with everything between replaced by zeros."""
    real = memory.read_region_spanning

    def corrupted(mf, va, size):
        data = real(mf, va, size)
        return data[:1] + b"\x00" * (len(data) - 2) + data[-1:] if len(data) > 2 else data

    monkeypatch.setattr(memory, "read_region_spanning", corrupted)
    mf = characterization._open(tmp_path, characterization._gapped_spec())
    try:
        with pytest.raises(AssertionError):
            characterization.test_read_primitives(mf, *characterization.READ_CASES[case])
    finally:
        mf.file_handle.close()


def test_segments_spliced_at_the_wrong_offset_are_detected(monkeypatch, tmp_path):
    """A spanning read that joins the right segments but starts the second
    one at the wrong offset."""
    real = memory.read_region_spanning

    def misspliced(mf, va, size):
        data = real(mf, va, size)
        return data[:0x10] + real(mf, va + 0x18, size - 0x10) if size > 0x10 else data

    monkeypatch.setattr(memory, "read_region_spanning", misspliced)
    mf = characterization._open(tmp_path, characterization._gapped_spec())
    try:
        with pytest.raises(AssertionError):
            characterization.test_read_primitives(
                mf, *characterization.READ_CASES["into_adjacent_segment"])
    finally:
        mf.file_handle.close()


# ── Vocabulary contents ───────────────────────────────────────────────────


def test_changed_reason_text_is_detected(monkeypatch):
    monkeypatch.setitem(cov._SCAN_REGION_SEARCH_INCOMPLETE_REASONS, "entropy_window_sampled",
                        "CHANGED")
    assert _any_mentions(_corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus()),
                         "render", "CHANGED")
    assert _any_mentions(_contract_diff(), "private_values",
                         "_SCAN_REGION_SEARCH_INCOMPLETE_REASONS")


def test_removed_oversized_source_contract_entry_is_detected(monkeypatch):
    monkeypatch.delitem(cov._SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS, "ioc_string_scan")
    assert _corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus()) != []
    assert _any_mentions(_contract_diff(), "private_values",
                         "_SCAN_REGION_OVERSIZED_SKIPPED_SOURCE_CONTRACTS")


# ── Coverage report assembly ──────────────────────────────────────────────


def _no_op_like(original):
    def no_op(*args, **kwargs):
        return None
    no_op.__name__, no_op.__qualname__ = original.__name__, original.__qualname__
    return no_op


@pytest.mark.parametrize("validator, code", [
    ("_validate_source_absent_against_sources", "SOURCE_ABSENT"),
    ("_validate_pid_thread_list_fallback_against_sources", "PID_THREAD_LIST_FALLBACK"),
    ("_validate_build_coverage_report_inputs", None),
])
def test_disabled_cross_source_validator_is_detected(monkeypatch, validator, code):
    """The validator replaced by a no-op carrying its own name, so the spec
    table's recorded qualified names cannot give it away."""
    no_op = _no_op_like(getattr(cov, validator))
    monkeypatch.setattr(cov, validator, no_op)
    if code is not None:
        key = cov.LimitationCode[code]
        monkeypatch.setitem(cov._CODE_SPECS, key, dataclasses.replace(
            cov._CODE_SPECS[key], validate_against_sources=no_op))
    differences = _corpus_diff(capture.COVERAGE_CORPUS, capture_coverage_corpus())
    assert _any_mentions(differences, "$.reports")


# ── Legal relocations and their negative control ──────────────────────────
# Structural moves the baseline must accept unchanged, and a copy it must
# refuse. The simulated relocations re-execute a target's single source
# file, so they run against the targets whose baseline definitions all
# still live in that one module; a target already decomposed -- into a
# package, or behind a facade over owner modules -- is its own positive
# control, held by every comparison in test_decomposition_baseline.py.


def _is_monolithic(target) -> bool:
    if hasattr(importlib.import_module(target), "__path__"):
        return False
    owners = load_golden(capture.SURFACE_STRUCTURE)[target]["owners"]
    return all(owner == target for owner in owners.values())


MONOLITHIC_TARGETS = tuple(t for t in TARGET_MODULES if _is_monolithic(t))


def _relocate(target, monkeypatch, tmp_path, copied=()):
    """Turn `target` into a facade over a new owner module: the legacy
    source re-executed as `<package>._relocated_owner` (every definition
    gets a new `__module__`), and a facade installed under the legacy name
    whose source imports every committed export from that owner -- except
    the names in `copied`, which it binds to a copy instead."""
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    package = target.rpartition(".")[0]
    owner_name = f"{package}._relocated_owner"
    owner_path = tmp_path / "relocated_owner.py"
    owner_path.write_bytes(open(importlib.import_module(target).__file__, "rb").read())
    spec = importlib.util.spec_from_file_location(owner_name, owner_path)
    owner = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, owner_name, owner)
    spec.loader.exec_module(owner)

    imported = [n for n in committed["exports"] if n not in copied]
    facade_source = (f"import copy\nimport {owner_name} as _owner\n"
                     f"from {owner_name} import (\n"
                     + "".join(f"    {n},\n" for n in imported) + ")\n"
                     + "".join(f"{n} = copy.copy(_owner.{n})\n" for n in copied))
    facade_path = tmp_path / "facade.py"
    facade_path.write_text(facade_source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location(target, facade_path)
    facade = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facade)
    monkeypatch.setitem(sys.modules, target, facade)
    return owner, facade, committed


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_pure_reexport_facade_keeps_the_contract(target, monkeypatch, tmp_path):
    """Every export re-exported by name from the current module, through a
    facade whose source binds each one with an import; private values are
    found in the module that still defines them."""
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    name = "reexport_facade_" + target.replace(".", "_")
    (tmp_path / f"{name}.py").write_text(
        f"from {target} import (\n" + "".join(f"    {n},\n" for n in committed["exports"])
        + ")\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, name, raising=False)
    contract = capture_contract(target, committed["exports"], committed["private_values"],
                                module_name=name)
    assert diff(committed, roundtrip(contract)) == []


@pytest.mark.parametrize("target", MONOLITHIC_TARGETS)
def test_definitions_moved_to_a_new_owner_keep_the_contract(target, monkeypatch, tmp_path):
    owner, facade, committed = _relocate(target, monkeypatch, tmp_path)
    assert importlib.import_module(target) is facade and owner.__name__ != target
    contract = capture_contract(target, committed["exports"], committed["private_values"])
    assert diff(committed, roundtrip(contract)) == []
    assert duplicate_definitions(
        target, [*committed["exports"], *committed["private_values"]], committed["exports"]) == []


@pytest.mark.parametrize("target", MONOLITHIC_TARGETS)
def test_regeneration_after_a_relocation_keeps_contract_and_follows_owners(
        target, monkeypatch, tmp_path):
    """Running the generator over the relocated layout reproduces the
    committed contract byte for byte, and the regenerated ownership map
    places every moved function in its new owner with its resolution."""
    owner, _facade, _committed = _relocate(target, monkeypatch, tmp_path)
    regenerated = capture.capture_static_goldens(sections=["contract", "structure"])
    assert (dumps(regenerated[capture.SURFACE_CONTRACT])
            == open(golden_path(capture.SURFACE_CONTRACT), "rb").read())
    structure = regenerated[capture.SURFACE_STRUCTURE][target]
    committed_structure = load_golden(capture.SURFACE_STRUCTURE)[target]
    functions = [n for n, kind in committed_structure["baseline_definitions"] if kind == "def"]
    assert functions and all(
        structure["global_resolution"][n]["module"] == owner.__name__ for n in functions)
    assert all(structure["owners"][n] == owner.__name__ for n in functions)
    assert set(structure["global_resolution"]) == set(committed_structure["global_resolution"])


def test_value_copied_into_the_facade_is_detected(monkeypatch, tmp_path):
    target = "dumpex.output.coverage"
    _owner, _facade, committed = _relocate(target, monkeypatch, tmp_path,
                                           copied=("_SOURCE_DISPLAY_NAMES",))
    contract = capture_contract(target, committed["exports"], committed["private_values"])
    assert diff(committed, roundtrip(contract)) == []   # equal content ...
    assert duplicate_definitions(      # ... but two objects
        target, [*committed["exports"], *committed["private_values"]], committed["exports"]) == [
        "_SOURCE_DISPLAY_NAMES: ['dumpex.output._relocated_owner', 'dumpex.output.coverage']"]


def test_value_copied_into_the_records_package_facade_is_detected(monkeypatch):
    """The decomposed records package: a facade binding that is an equal
    copy of its owner's value, rather than the owner's object."""
    target = "dumpex.output.records"
    monkeypatch.setattr(records, "HUNTERS", tuple(list(records.HUNTERS)))
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    assert duplicate_definitions(
        target, [*committed["exports"], *committed["private_values"]], committed["exports"]) == [
        "HUNTERS: ['dumpex.output.records', 'dumpex.output.records.hunt_identity']"]


# ── Split relocation: private definitions in a module that owns no export ──


def _split_names(target):
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    return committed, [*committed["exports"], *committed["private_values"]]


@pytest.mark.parametrize("target", MONOLITHIC_TARGETS)
def test_split_relocation_keeps_every_baseline(target, monkeypatch, tmp_path):
    """Exported classes in one owner, exported functions and values in a
    second, every private value, vocabulary and helper in a third module
    that owns no export, behind a facade exposing only the committed
    exports: the contract and both corpora are unchanged, every baseline
    definition has an owner, and no definition is duplicated."""
    parts = split_relocation(target, monkeypatch, tmp_path)
    assert importlib.import_module(target) is parts["facade"]
    committed, names = _split_names(target)
    contract = capture_contract(target, committed["exports"], committed["private_values"])
    assert diff(committed, roundtrip(contract)) == []
    assert dumps(capture_coverage_corpus()) == open(golden_path(capture.COVERAGE_CORPUS), "rb").read()
    assert dumps(capture_record_corpus()) == open(golden_path(capture.RECORD_CORPUS), "rb").read()
    definitions = load_golden(capture.SURFACE_STRUCTURE)[target]["baseline_definitions"]
    structure = capture_structure(target, committed["exports"], definitions)
    part_names = {m.__name__ for m in parts.values()}
    assert {n: o for n, o in structure["owners"].items() if o not in part_names} == {}
    resolution = structure["global_resolution"]
    assert {v["module"] for v in resolution.values()} <= part_names
    assert [q for q, v in resolution.items() if "declared_module" in v] == []
    moved = [n for n, kind in definitions if kind == "def"]
    assert moved and all(resolution[n]["module"] == structure["owners"][n] for n in moved)
    assert duplicate_definitions(target, names, committed["exports"]) == []


def test_split_functions_resolve_globals_in_their_own_part(monkeypatch, tmp_path):
    """Read from the functions themselves, not from the harness: a moved
    function's globals are its owning part's namespace."""
    parts = split_relocation("dumpex.core.memory", monkeypatch, tmp_path)
    for name in ("read_region_clamped", "enriched_thread_contexts", "open_dump"):
        fn = getattr(parts["facade"], name)
        assert fn.__globals__ is parts[FUNCTIONS].__dict__
        assert fn.__module__ == parts[FUNCTIONS].__name__
    assert parts[INTERNALS]._hexdump_context.__globals__ is parts[INTERNALS].__dict__


@pytest.mark.parametrize("check", seams.CHECKS, ids=lambda c: c.__name__)
def test_split_without_delegation_breaks_each_legacy_seam(check, monkeypatch, tmp_path):
    """A split that re-exports but does not delegate leaves every patch to
    `dumpex.core.memory.<name>` unseen by the moved consumer; each seam
    check must report it."""
    split_relocation("dumpex.core.memory", monkeypatch, tmp_path)
    inner = pytest.MonkeyPatch()
    try:
        with pytest.raises(AssertionError, match="does not"):
            check(inner)
    finally:
        inner.undo()


def test_split_without_delegation_breaks_the_loader_seams(monkeypatch, tmp_path):
    from tests.fixtures.minidump_bytes import DumpSpec, ModuleSpec, ThreadSpec, write_minidump
    path = write_minidump(tmp_path / "seams.dmp", DumpSpec(
        modules=(ModuleSpec(0x400000, 0x1000, "a.exe"),), threads=(ThreadSpec(0x10, ip=0x401000),)))
    split_relocation("dumpex.core.memory", monkeypatch, tmp_path)
    inner = pytest.MonkeyPatch()
    try:
        with pytest.raises(AssertionError, match="CONTEXT"):
            seams.check_loader_seams_reach_open_dump(inner, path)
    finally:
        inner.undo()


def test_split_relocation_keeps_the_leak_guard_working(monkeypatch, tmp_path):
    split_relocation("dumpex.core.memory", monkeypatch, tmp_path)
    assert not hasattr(importlib.import_module("dumpex.core.memory"), "_hexdump_context")
    seam_tests.test_no_memory_function_is_left_replaced()


@pytest.mark.parametrize("target", MONOLITHIC_TARGETS)
def test_regeneration_after_a_split_keeps_the_contract(target, monkeypatch, tmp_path):
    parts = split_relocation(target, monkeypatch, tmp_path)
    regenerated = capture.capture_static_goldens(sections=["contract", "structure"])
    assert (dumps(regenerated[capture.SURFACE_CONTRACT])
            == open(golden_path(capture.SURFACE_CONTRACT), "rb").read())
    owners = regenerated[capture.SURFACE_STRUCTURE][target]["owners"]
    assert set(owners.values()) <= {m.__name__ for m in parts.values()}


def test_copy_bound_in_a_second_split_module_is_detected(monkeypatch, tmp_path):
    target = "dumpex.output.coverage"
    split_relocation(target, monkeypatch, tmp_path,
                     copied_into_functions=("_SCAN_REGION_SEARCH_INCOMPLETE_REASONS",))
    committed, names = _split_names(target)
    assert duplicate_definitions(target, names, committed["exports"]) == [
        "_SCAN_REGION_SEARCH_INCOMPLETE_REASONS: ['dumpex.output._split_functions', "
        "'dumpex.output._split_internals']"]


def test_scalar_budget_redefined_in_a_second_split_module_is_detected(monkeypatch, tmp_path):
    """A budget re-declared as an equal local literal in a second owner:
    the identity-based guard skips scalars, the source-level one reports
    both defining modules."""
    target = "dumpex.core.memory"
    split_relocation(target, monkeypatch, tmp_path,
                     extra_internals="MAX_REGION_READ = 256 * 1024 * 1024\n")
    committed, names = _split_names(target)
    assert duplicate_definitions(target, names, committed["exports"]) == []
    assert duplicate_source_definitions(target, names, committed["exports"]) == [
        "MAX_REGION_READ: ['dumpex.core._split_functions', 'dumpex.core._split_internals']"]


def test_unregistered_vocabulary_in_a_split_module_is_detected(monkeypatch, tmp_path):
    split_relocation("dumpex.output.coverage", monkeypatch, tmp_path, extra_internals=(
        "_UNREGISTERED_VOCABULARY = frozenset({'x'})\n\n\n"
        "def _render_unregistered(limitation):\n"
        "    return str(sorted(_UNREGISTERED_VOCABULARY))\n"))
    assert unaccounted_vocabularies() == ["_UNREGISTERED_VOCABULARY"]


def test_split_relocation_without_additions_leaves_no_unaccounted_vocabulary(
        monkeypatch, tmp_path):
    split_relocation("dumpex.output.coverage", monkeypatch, tmp_path)
    assert unaccounted_vocabularies() == []


# ── State-dependent record invariants ─────────────────────────────────────


def test_disabled_uncollected_profile_check_is_detected(monkeypatch):
    original = records.ProcessPeRecord._check_uncollected
    monkeypatch.setattr(records.ProcessPeRecord, "_check_uncollected", _no_op_like(original))
    differences = _corpus_diff(capture.RECORD_CORPUS, capture_record_corpus())
    assert _any_mentions(differences, "ProcessPeRecord[collected=False]", "fill_probes")
