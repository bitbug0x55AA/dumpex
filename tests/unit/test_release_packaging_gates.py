"""The release contract for the bundled instruction decoder.

The Python distribution may keep the decoder optional; the official
Windows executable may not. Its users cannot install a Python extra into
an executable, so the build has to declare the dependency, bundle the
Capstone package together with its native library, prove at build time
that the packaged decoder actually decodes, and carry Capstone's license
with the code it ships.
"""
import importlib.util
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[2]
_BUILD_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "build.yml"
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


# ── the release declares the capability it ships ──────────────────────

def test_the_release_environment_names_the_disasm_extra():
    # Never inherited from `dev`: a dev-extra cleanup must not be able to
    # silently remove the decoder from a release build.
    assert '-e ".[full,disasm,dev]"' in _workflow()


def test_the_disasm_extra_pins_capstone():
    assert 'disasm = [\n    "capstone>=5.0,<6",\n]' in _PYPROJECT.read_text(encoding="utf-8")


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

def test_dependency_license_collection_covers_the_disasm_extra():
    collector = _load_script("collect_dependency_licenses")
    assert "disasm" in collector._ENABLED_EXTRAS


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
