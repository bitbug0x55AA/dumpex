"""The release contract for the instruction decoder.

Instruction context is a built-in Report capability, so the decoder is a
base dependency: a wheel, an sdist, an install from a Git ref, and the
official Windows executable all carry it. No extra may be the thing that
supplies it, the frozen build has to bundle the Capstone package together
with its native library, the release has to prove at build time that the
packaged decoder actually decodes, and the bundle has to carry Capstone's
license with the code it ships.
"""
import importlib.metadata
import importlib.util
import re
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
_BUILD_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "build.yml"
_TESTS_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "tests.yml"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_SCRIPTS = _REPO_ROOT / "scripts"


def _workflow() -> str:
    return _BUILD_WORKFLOW.read_text(encoding="utf-8")


def _load_script(name):
    path = _SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── every installation declares the capability it ships ───────────────

def _pyproject() -> str:
    return _PYPROJECT.read_text(encoding="utf-8")


def _base_dependencies_block() -> str:
    text = _pyproject()
    return text[text.index("dependencies = ["):
                text.index("[project.optional-dependencies]")]


def test_capstone_is_a_base_dependency():
    assert '"capstone>=5.0,<6",' in _base_dependencies_block()


def test_the_disasm_extra_is_an_empty_compatibility_alias():
    # `pip install dumpex[disasm]` keeps resolving for instructions
    # already in circulation, and installs nothing the plain package does
    # not.
    assert "disasm = []" in _pyproject()


def test_capstone_is_constrained_in_exactly_one_place():
    # Two constraints can disagree; the base requirement is the only
    # version statement about the decoder in the project metadata.
    assert _pyproject().count('"capstone') == 1


def test_the_installed_distribution_requires_capstone_unconditionally():
    # The resolved metadata, not the source text: a base requirement
    # carries no marker, an extra's requirement carries `extra == "..."`.
    requirements = importlib.metadata.distribution("dumpex").requires or ()
    unconditional = [line for line in requirements if ";" not in line]
    assert any(line.lower().startswith("capstone") for line in unconditional), (
        f"capstone reaches this environment only through an extra: {requirements}")


def test_the_release_environment_installs_no_decoder_extra():
    # The decoder comes from the base requirement. Naming an extra here
    # would reintroduce a release whose decoder came from somewhere a
    # user's own install does not have.
    assert '-e ".[full,dev]"' in _workflow()
    requested_extras = re.findall(r"\.\[([^\]]*)\]", _workflow())
    assert requested_extras
    assert all("disasm" not in extras for extras in requested_extras), requested_extras


def test_the_release_verifies_the_decoder_came_from_the_base_requirement():
    workflow = _workflow()
    assert "$baseRequirements -notcontains 'capstone'" in workflow
    assert "python -m dumpex --self-check" in workflow


def test_the_base_install_is_proven_on_the_newest_supported_interpreter():
    # The package-smoke job installs with no extras, so it is the gate
    # that proves a default installation resolves a decoder. It runs on
    # the newest interpreter the project claims support for.
    tests_workflow = _TESTS_WORKFLOW.read_text(encoding="utf-8")
    assert 'python-version: ["3.10", "3.12", "3.14"]' in tests_workflow


def test_every_supported_installation_shape_is_smoke_tested():
    # A wheel, an sdist, and a Git ref build their metadata by different
    # routes, so each is its own proof that a default install resolves the
    # decoder. The Git-ref clone points at this checkout, not a remote, so
    # the commit under test is the one installed.
    tests_workflow = _TESTS_WORKFLOW.read_text(encoding="utf-8")
    for artifact in ("dist/*.whl", "dist/*.tar.gz",
                     '"git+file://$GITHUB_WORKSPACE@package-smoke-ref"'):
        assert artifact in tests_workflow, artifact
    assert '-m dumpex --self-check' in tests_workflow


# ── the native backend travels with the package ───────────────────────

def test_the_build_collects_the_whole_capstone_distribution():
    assert "--collect-all capstone" in _workflow()


def test_the_archive_is_checked_for_the_native_library():
    workflow = _workflow()
    assert "$archive.Contains('capstone.dll')" in workflow
    assert "missing the Capstone native library" in workflow


# ── the packaged decoder is executed before publication ───────────────

def test_the_built_executable_runs_the_decoder_smoke():
    assert "python scripts/frozen_disasm_smoke.py dist/dumpex.exe" in _workflow()


def test_the_executable_extracted_from_the_final_zip_runs_the_same_smoke():
    assert ("python scripts/frozen_disasm_smoke.py (Join-Path $extractDir 'dumpex.exe')"
            in _workflow())


def _run_smoke(monkeypatch, returncode, stdout):
    """Run the frozen smoke against a stand-in executable that reports
    ``returncode`` and ``stdout``. Returns the smoke's own exit code."""
    smoke = _load_script("frozen_disasm_smoke")

    def fake_run(argv, **kwargs):
        assert argv[1] == "--self-check"
        return subprocess.CompletedProcess(argv, returncode, stdout, "")

    monkeypatch.setattr(smoke.subprocess, "run", fake_run)
    monkeypatch.setattr(smoke.sys, "argv", ["frozen_disasm_smoke.py", "dumpex.exe"])
    try:
        smoke.main()
    except SystemExit as exit_info:
        return exit_info.code
    return 0


_PASSING_OUTPUT = ("dumpex self-check: instruction decoder\n"
                   "  runtime: frozen\n"
                   "  backend: available (capstone 5.0.7)\n"
                   "  x86: 90 c3 -> nop, ret\n"
                   "  x64: 90 c3 -> nop, ret\n"
                   "self-check: PASS\n")


def test_the_smoke_passes_a_build_whose_decoder_answers(monkeypatch):
    assert _run_smoke(monkeypatch, 0, _PASSING_OUTPUT) == 0


def test_the_smoke_fails_a_non_zero_self_check(monkeypatch):
    failing = ("dumpex self-check: instruction decoder\n"
               "  backend: load_failure\n"
               "self-check: FAIL\n")
    assert _run_smoke(monkeypatch, 1, failing) == 1


def test_the_smoke_fails_a_zero_exit_that_reported_no_decode(monkeypatch):
    # A build that exits 0 without decoding is still a build that cannot
    # decode; a silent pass here would publish it.
    assert _run_smoke(monkeypatch, 0, "dumpex self-check: instruction decoder\n") == 1


def test_the_smoke_fails_when_only_one_architecture_decoded(monkeypatch):
    partial = _PASSING_OUTPUT.replace("  x86: 90 c3 -> nop, ret\n", "")
    assert _run_smoke(monkeypatch, 0, partial) == 1


def test_the_smoke_requires_both_architectures_and_a_loaded_backend():
    smoke = _load_script("frozen_disasm_smoke")
    assert "backend: available" in smoke.REQUIRED_LINES
    assert "x86: 90 c3 -> nop, ret" in smoke.REQUIRED_LINES
    assert "x64: 90 c3 -> nop, ret" in smoke.REQUIRED_LINES
    assert "self-check: PASS" in smoke.REQUIRED_LINES


# ── the license travels with the code ─────────────────────────────────

def test_dependency_license_collection_reaches_capstone_from_the_base_closure():
    # The empty extra is the base dependency closure, and capstone is in
    # it, so no extra has to be enabled for Capstone's notice to travel
    # with the code the bundle ships.
    collector = _load_script("collect_dependency_licenses")
    assert "" in collector._ENABLED_EXTRAS
    assert "disasm" not in collector._ENABLED_EXTRAS


def test_the_bundle_is_checked_for_a_capstone_license_file():
    workflow = _workflow()
    assert "-Filter '*capstone*'" in workflow
    assert "no Capstone license file" in workflow


def test_the_notices_describe_the_windows_bundle_as_unconditional():
    notices = (_REPO_ROOT / "THIRD_PARTY_NOTICES").read_text(encoding="utf-8")
    assert "incorporates Capstone unconditionally" in notices
    assert "Copyright (c) 2013, COSEINC. All rights reserved." in notices

    credits = (_REPO_ROOT / "CREDITS").read_text(encoding="utf-8")
    assert "bundled unconditionally in the official Windows executable" in credits


def test_the_notices_describe_the_python_distribution_as_carrying_capstone():
    # The inventory has to match what is actually shipped: a dependency
    # described as optional understates what the wheel redistributes.
    notices = (_REPO_ROOT / "THIRD_PARTY_NOTICES").read_text(encoding="utf-8")
    assert "base requirement of the Python distribution" in notices

    credits = (_REPO_ROOT / "CREDITS").read_text(encoding="utf-8")
    assert "A base requirement of the Python distribution" in credits
