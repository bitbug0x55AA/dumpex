"""
Module-level replacement seams of the decomposed modules, and the test
reset isolation that keeps those replacements from leaking.

* Every name some test replaces on a legacy module path is still an
  attribute of that module (`seams.json`'s ``legacy_patch_targets``).
* Every consumer module that holds a target module's object by name --
  and that tests replace there instead -- still holds that very object
  (`seams.json`'s ``consumer_seams``).
* Replacing a legacy `dumpex.core.memory` name still reaches the function
  that consumes it (the `check_*` functions in
  `tests.fixtures.decomposition_baseline.seams`).
* `tests/conftest.py` restores every consumer seam the test files replace,
  as the live scan finds them, around every test; no test replaces a
  target module attribute by plain assignment.
* No earlier test has left a replacement behind on `dumpex.core.memory`.
"""
import importlib

import pytest

import dumpex.core.memory as memory
import dumpex.hunt.cs_beacon as cs_beacon
import dumpex.hunt.pipe as pipe
import dumpex.hunt.stomping as stomping
from tests.fixtures.decomposition_baseline import MEMORY, capture, seams
from tests.fixtures.decomposition_baseline.consumers import (
    plain_assignments_to_targets, scan_reader_seams, unreset_seams)
from tests.fixtures.decomposition_baseline.stable import load_golden
from tests.fixtures.decomposition_baseline.surface import baseline_object
from tests.fixtures.minidump_bytes import DumpSpec, ModuleSpec, ThreadSpec, write_minidump


@pytest.mark.parametrize("check", seams.CHECKS, ids=lambda c: c.__name__)
def test_legacy_memory_seam_reaches_its_consumer(check, monkeypatch):
    check(monkeypatch)


def test_loader_seams_reach_open_dump(monkeypatch, tmp_path):
    path = write_minidump(tmp_path / "seams.dmp", DumpSpec(
        modules=(ModuleSpec(0x400000, 0x1000, "a.exe"),), threads=(ThreadSpec(0x10, ip=0x401000),)))
    seams.check_loader_seams_reach_open_dump(monkeypatch, path)


def _patched_names():
    targets = load_golden(capture.SEAMS)["legacy_patch_targets"]
    return sorted((target, name) for target, names in targets.items() for name in names)


@pytest.mark.parametrize("target, name", _patched_names())
def test_every_replaced_legacy_name_is_still_an_attribute(target, name):
    assert hasattr(importlib.import_module(target), name), (
        f"tests replace {target}.{name}, but the legacy module has no such attribute")


def _reader_seams():
    return sorted((consumer, name, target, same)
                  for consumer, names in load_golden(capture.SEAMS)["consumer_seams"].items()
                  for name, entry in names.items()
                  for target, same in entry["same_object_as"].items())


@pytest.mark.parametrize("consumer, name, target, same", _reader_seams())
def test_consumer_reader_seam_holds_the_canonical_object(consumer, name, target, same):
    held = getattr(importlib.import_module(consumer), name)
    canonical = getattr(importlib.import_module(target), name)
    assert (held is canonical) is same, (
        f"{consumer}.{name} {'is not' if same else 'is'} {target}.{name}")


def _conftest_resets() -> set:
    from tests import conftest
    reset = set(conftest.READER_SEAMS)
    reset |= {(m.__name__, "enriched_thread_contexts")
              for m in conftest._ENRICHED_THREAD_CONTEXT_MODULES}
    reset |= {(m.__name__, "get_thread_contexts") for m in conftest._RAW_THREAD_CONTEXT_MODULES}
    return reset


def test_conftest_resets_every_consumer_reader_seam():
    """Against the live scan of the test files, so a seam a new test
    introduces fails here until conftest restores it."""
    live = scan_reader_seams()
    committed = load_golden(capture.SEAMS)["consumer_seams"]
    unreset = unreset_seams({**committed, **live}, _conftest_resets())
    assert not unreset, f"tests replace these without a conftest reset: {unreset}"


def test_no_test_replaces_a_target_module_attribute_by_plain_assignment():
    offenders = plain_assignments_to_targets()
    assert not offenders, ("use monkeypatch, which undoes the replacement: "
                           + "; ".join(offenders))


def _fixture_tree(tmp_path, source: str):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_leaky.py").write_text(source, encoding="utf-8")
    return str(tmp_path)


def test_scanner_reports_a_plain_assignment_seam_and_the_guard_rejects_it(tmp_path):
    root = _fixture_tree(tmp_path, (
        "import dumpex.hunt.injection as injection\n"
        "def test_x():\n"
        "    injection.read_region = lambda mf, addr, size: b''\n"))
    found = scan_reader_seams(root)
    assert found == {"dumpex.hunt.injection": {"read_region": {
        "kinds": ["assign"], "same_object_as": {"dumpex.core.memory": True}}}}
    assert unreset_seams(found, set()) == [("dumpex.hunt.injection", "read_region")]
    assert unreset_seams(found, _conftest_resets()) == []


def test_scanner_reports_a_string_path_patch_seam(tmp_path):
    root = _fixture_tree(tmp_path, (
        "def test_x(monkeypatch):\n"
        "    monkeypatch.setattr('dumpex.hunt._location.va_to_file_offset', None)\n"))
    assert scan_reader_seams(root) == {"dumpex.hunt._location": {"va_to_file_offset": {
        "kinds": ["patch"], "same_object_as": {"dumpex.core.memory": True}}}}


def test_scanner_reports_a_plain_assignment_to_a_target_module(tmp_path):
    root = _fixture_tree(tmp_path, (
        "import dumpex.core.memory as core_memory\n"
        "def test_x():\n"
        "    core_memory.read_region = None\n"))
    assert plain_assignments_to_targets(root) == [
        "tests/test_leaky.py: dumpex.core.memory.read_region"]


def test_reader_seam_leak_simulation():
    import dumpex.hunt.injection as injection
    injection.read_region = lambda mf, addr, size: b""


def test_reader_seam_reset_restores_the_canonical_reader():
    import dumpex.hunt.injection as injection
    assert injection.read_region is memory.read_region


# ── conftest reset isolation ───────────────────────────────────────────────
# The first test replaces the readers without monkeypatch, the way a
# careless test would; the second relies on tests/conftest.py having put
# the canonical objects back. Each also holds on its own.


def test_conftest_reset_leak_simulation():
    assert stomping.enriched_thread_contexts is memory.enriched_thread_contexts
    stomping.enriched_thread_contexts = lambda mf: []
    pipe.enriched_thread_contexts = lambda mf: []
    cs_beacon.get_thread_contexts = lambda mf: []


def test_conftest_reset_restores_the_canonical_readers():
    assert stomping.enriched_thread_contexts is memory.enriched_thread_contexts
    assert pipe.enriched_thread_contexts is memory.enriched_thread_contexts
    assert cs_beacon.get_thread_contexts is memory.get_thread_contexts


# ── leak guard ─────────────────────────────────────────────────────────────


def test_no_memory_function_is_left_replaced():
    """Every function `dumpex.core.memory` defined at the baseline -- on the
    legacy path, or wherever it is defined now -- is still the function of
    that name: a replacement that outlived its test would have a different
    qualified name (a lambda, a test-local helper)."""
    leaked = []
    structure = load_golden(capture.SURFACE_STRUCTURE)[MEMORY]
    for name, how in structure["baseline_definitions"]:
        if how != "def":
            continue
        obj = baseline_object(MEMORY, name)
        if getattr(obj, "__qualname__", None) != name:
            leaked.append(f"{name} -> {obj!r}")
    assert not leaked, "replaced without restoration: " + ", ".join(leaked)


def test_memory_module_is_the_legacy_entry_point():
    assert memory.__name__ == MEMORY
