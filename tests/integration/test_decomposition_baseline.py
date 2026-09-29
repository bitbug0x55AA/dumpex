"""
Records/memory decomposition baseline: live behaviour against the
committed goldens in tests/fixtures/decomposition_baseline/golden/.

These tests only compare; `scripts/update_decomposition_baseline.py` is the
only writer. A difference in a contract golden means observable behaviour
changed: a relocation must not cause one, and an approved behaviour change
updates the affected golden in its own reviewed commit. See
docs/developer/decomposition_baseline.md.
"""
import importlib
import inspect

import pytest

from tests.fixtures.decomposition_baseline import GOLDEN_DIR, TARGET_MODULES, capture
from tests.fixtures.decomposition_baseline.cli_matrix import (
    SCENARIOS, golden_name, run_scenario, yara_available)
from tests.fixtures.decomposition_baseline.consumers import (
    EXTERNAL_CATEGORIES, by_categories, scan_consumers, scan_legacy_rebinds, unreachable_rebinds)
from tests.fixtures.decomposition_baseline.coverage_corpus import (
    capture_coverage_corpus, unaccounted_vocabularies, vocabulary_coverage)
from tests.fixtures.decomposition_baseline.surface import (
    duplicate_definitions, duplicate_source_definitions)
from tests.fixtures.decomposition_baseline.record_corpus import capture_record_corpus
from tests.fixtures.decomposition_baseline.stable import (
    assert_matches_golden, dumps, load_golden)


@pytest.fixture(scope="module")
def baseline_consumers():
    return load_golden(capture.CONSUMERS)


@pytest.fixture(scope="module")
def live_surfaces(baseline_consumers):
    return capture.committed_surfaces()


# ── Symbol surface ────────────────────────────────────────────────────────


def test_surface_contract_matches_baseline(live_surfaces):
    assert_matches_golden(capture.SURFACE_CONTRACT, live_surfaces[0])


def test_surface_structure_matches_baseline(live_surfaces):
    """Structural metadata: the current owner of every baseline definition,
    the legacy module's import provenance, and the module and globals each
    function resolves. A relocation regenerates this file deliberately -- it
    becomes the reviewed old-to-new ownership map -- and must leave every
    contract golden alone."""
    assert_matches_golden(capture.SURFACE_STRUCTURE, live_surfaces[1])


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_every_function_resolves_globals_in_the_module_that_owns_it(live_surfaces, target):
    """The resolution module is read from each function's `__globals__`; it
    must be the owner the structure records, never a namespace the
    function only claims through `__module__`."""
    structure = live_surfaces[1][target]
    resolution, owners = structure["global_resolution"], structure["owners"]
    assert [q for q, v in resolution.items() if "declared_module" in v] == []
    assert [n for n, kind in structure["baseline_definitions"]
            if kind == "def" and resolution[n]["module"] != owners[n]] == []


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_every_baseline_export_resolves_through_the_legacy_path(target):
    module = importlib.import_module(target)
    exports = load_golden(capture.SURFACE_CONTRACT)[target]["exports"]
    missing = [name for name in exports if not hasattr(module, name)]
    assert not missing, f"{target} does not expose: {missing}"


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_no_baseline_value_has_a_second_definition(target):
    """A non-scalar export or private value that the legacy module and its
    owner modules bind to different objects is a copy: mutating the one a
    consumer reaches through the legacy path would not reach the other."""
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    names = [*committed["exports"], *committed["private_values"]]
    assert duplicate_definitions(target, names, committed["exports"]) == []


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_no_baseline_name_is_defined_in_two_family_modules(target):
    """The identity check above cannot see a scalar -- a budget or cap
    copied into a second owner as an equal literal may even be the same
    interned object. Each baseline name is defined in the source of one
    module only."""
    committed = load_golden(capture.SURFACE_CONTRACT)[target]
    names = [*committed["exports"], *committed["private_values"]]
    definitions = [n for n, _ in load_golden(capture.SURFACE_STRUCTURE)[target]["baseline_definitions"]]
    assert duplicate_source_definitions(
        target, sorted({*names, *definitions}), committed["exports"]) == []


@pytest.mark.parametrize("target", TARGET_MODULES)
def test_every_exported_definition_has_one_canonical_owner(target):
    """A class or function reachable through the legacy path is the very
    object its owning module defines under that name -- never a copy."""
    module = importlib.import_module(target)
    exports = load_golden(capture.SURFACE_CONTRACT)[target]["exports"]
    for name in exports:
        obj = getattr(module, name)
        if not (inspect.isclass(obj) or inspect.isfunction(obj)):
            continue
        if not obj.__module__.startswith("dumpex"):
            continue
        owner = importlib.import_module(obj.__module__)
        assert getattr(owner, obj.__name__, None) is obj, (
            f"{target}.{name} is not the object {obj.__module__}.{obj.__name__}")


# ── Consumers ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("category", ("production", "scripts"))
def test_supported_consumers_match_baseline(baseline_consumers, category):
    """Which names shipped code imports, reads module-qualified or patches,
    and from which files. Relocation preserves external import sites."""
    live = by_categories(scan_consumers(), (category,))
    expected = by_categories(baseline_consumers, (category,))
    assert live == expected, (
        f"{category} consumers of the decomposed modules changed; if intentional, regenerate "
        f"with `python scripts/update_decomposition_baseline.py consumers` and review")


def test_consumer_inventory_holds_files_outside_the_family_only(baseline_consumers):
    """How the decomposed modules import one another is structure, recorded
    in surface_structure.json's `family_consumers`."""
    assert by_categories(baseline_consumers, EXTERNAL_CATEGORIES) == baseline_consumers


# Legacy attributes a test replaces for their own sake: the mutation
# controls reorder and copy the facade's HUNTERS to prove the contract
# capture and the duplicate guard read the legacy path itself.
_INTENTIONAL_LEGACY_REBINDS = (
    ("tests/integration/test_decomposition_baseline_mutations.py",
     "dumpex.output.records", "HUNTERS"),
)


def test_no_test_rebinds_a_legacy_name_that_is_read_from_its_owner():
    """A function relocated to an owner module reads its globals there, so
    replacing the legacy module's attribute does not reach it: such a test
    patches nothing it can observe. It must patch the owner module (or the
    namespace the reader resolves in) instead."""
    assert unreachable_rebinds(scan_legacy_rebinds(), load_golden(capture.SURFACE_STRUCTURE),
                               exempt=_INTENTIONAL_LEGACY_REBINDS) == []


def test_a_legacy_rebinding_of_a_relocated_validator_is_reported(tmp_path):
    sample = tmp_path / "tests" / "unit" / "test_sample.py"
    sample.parent.mkdir(parents=True)
    sample.write_text(
        "import dumpex.output.records as records\n\n\n"
        "def test_sample(monkeypatch):\n"
        "    monkeypatch.setattr(records, '_require_nonneg_int', lambda v, f: None)\n"
        "    monkeypatch.setattr(records.ThreadRecord, '__post_init__', lambda self: None)\n",
        encoding="utf-8")
    rebinds = scan_legacy_rebinds(str(tmp_path))
    assert rebinds == {"dumpex.output.records": {
        "_require_nonneg_int": ["tests/unit/test_sample.py"]}}
    reported = unreachable_rebinds(rebinds, load_golden(capture.SURFACE_STRUCTURE))
    assert len(reported) == 1
    assert reported[0].startswith(
        "tests/unit/test_sample.py: dumpex.output.records._require_nonneg_int is read from [")
    assert "'dumpex.output.records.extraction'" in reported[0]


def test_every_baseline_consumer_name_still_resolves(baseline_consumers):
    """Every name a shipped file imported, read or patched at the baseline,
    private names included, still resolves on its legacy module path."""
    missing = []
    for target, names in baseline_consumers.items():
        module = importlib.import_module(target)
        missing += [f"{target}.{name}" for name in names if not hasattr(module, name)]
    assert not missing, f"unresolvable on the legacy path: {missing}"


# ── Corpora ───────────────────────────────────────────────────────────────


def test_coverage_corpus_matches_baseline():
    corpus = capture_coverage_corpus()
    unrendered = [e["code"] for e in corpus["limitations"]
                  if not any(c["outcome"] == "rendered" for c in e["cases"])]
    assert not unrendered, f"codes without a rendered case: {unrendered}"
    assert_matches_golden(capture.COVERAGE_CORPUS, corpus)


def test_every_vocabulary_member_has_a_rendered_case():
    missing = {k: v for k, v in vocabulary_coverage(capture_coverage_corpus()).items() if v}
    assert not missing, f"vocabulary members with no rendered case: {missing}"


def test_every_renderer_vocabulary_is_accounted_for():
    """A private collection a coverage renderer, summary or validator reads
    must be exercised member by member (coverage_corpus.VOCABULARIES) or
    named where another section covers it."""
    assert unaccounted_vocabularies() == []


def test_record_corpus_matches_baseline():
    assert_matches_golden(capture.RECORD_CORPUS, capture_record_corpus())


def test_record_samples_cover_every_record_dataclass():
    """`_CodeSpec` is the coverage registry's own row type; its instances
    are captured row by row in the coverage corpus instead."""
    import dataclasses
    from tests.fixtures.decomposition_baseline.record_samples import SAMPLES
    missing = []
    for target in ("dumpex.output.records", "dumpex.output.coverage"):
        module = importlib.import_module(target)
        exports = load_golden(capture.SURFACE_CONTRACT)[target]["exports"]
        for name in exports:
            obj = getattr(module, name)
            if (inspect.isclass(obj) and dataclasses.is_dataclass(obj) and name not in SAMPLES
                    and name != "_CodeSpec"):
                missing.append(name)
    assert not missing, f"record dataclasses without a baseline sample: {missing}"


# ── Command line ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_cli_scenario_matches_baseline(scenario, monkeypatch, tmp_path):
    if scenario.needs_yara and not yara_available():
        pytest.skip("yara-python is not installed")
    result = run_scenario(scenario, monkeypatch, str(tmp_path))
    assert_matches_golden(golden_name(scenario), result)


def test_cli_goldens_have_no_orphans():
    import os
    present = {f"cli/{n}" for n in os.listdir(os.path.join(GOLDEN_DIR, "cli"))}
    assert present == {golden_name(s) for s in SCENARIOS}


# ── Generator ─────────────────────────────────────────────────────────────


def _generator():
    import importlib.util
    import os
    from tests.fixtures.decomposition_baseline import REPO_ROOT
    path = os.path.join(REPO_ROOT, "scripts", "update_decomposition_baseline.py")
    spec = importlib.util.spec_from_file_location("update_decomposition_baseline", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_fails_when_a_scenario_cannot_run_here(monkeypatch, capsys):
    script = _generator()
    monkeypatch.setattr(script.cli_matrix, "yara_available", lambda: False)
    assert script.main(["--check", "cli"]) == 1
    assert "skipped: cli/hunt_all (yara-python not installed)" in capsys.readouterr().out
    assert script.main(["--check", "--allow-skip", "cli"]) == 0


def _golden_copy(monkeypatch, tmp_path):
    import shutil
    from tests.fixtures.decomposition_baseline import stable
    copy = tmp_path / "golden"
    shutil.copytree(stable.GOLDEN_DIR, copy)
    monkeypatch.setattr(stable, "GOLDEN_DIR", str(copy))
    return copy


def _read(path):
    import json
    return json.loads(path.read_text(encoding="ascii"))


@pytest.mark.parametrize("argv", [
    ["--drop", "dumpex.core.memory:_NO_SUCH_NAME", "contract"],
    ["--drop", "dumpex.core.no_such_module:_IOC_ENC_ASCII"],
    ["--drop-seam", "dumpex.hunt.no_such_module:read_region", "seams"],
])
def test_drop_of_something_the_baseline_does_not_hold_is_refused(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        _generator().main(argv)
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err


def test_drop_regenerates_contract_and_structure_together(monkeypatch, tmp_path):
    golden = _golden_copy(monkeypatch, tmp_path)
    assert _generator().main(["--drop", "dumpex.core.memory:_IOC_ENC_ASCII", "structure"]) == 0
    contract = _read(golden / capture.SURFACE_CONTRACT)["dumpex.core.memory"]
    structure = _read(golden / capture.SURFACE_STRUCTURE)["dumpex.core.memory"]
    assert "_IOC_ENC_ASCII" not in contract["private_values"]
    assert "_IOC_ENC_ASCII" not in {n for n, _ in structure["baseline_definitions"]}
    assert "_IOC_ENC_UTF16" in contract["private_values"]


def test_drop_seam_removes_an_entry_the_scan_no_longer_finds(monkeypatch, tmp_path):
    golden = _golden_copy(monkeypatch, tmp_path)
    seams = _read(golden / capture.SEAMS)
    seams["consumer_seams"]["dumpex.hunt.renamed_away"] = {"read_region": {
        "kinds": ["assign"], "same_object_as": {"dumpex.core.memory": True}}}
    (golden / capture.SEAMS).write_bytes(dumps(seams))
    script = _generator()
    assert script.main(["--check", "seams"]) == 1
    assert script.main(["--drop-seam", "dumpex.hunt.renamed_away:read_region", "seams"]) == 0
    assert "dumpex.hunt.renamed_away" not in _read(golden / capture.SEAMS)["consumer_seams"]
    assert script.main(["--check", "seams"]) == 0
