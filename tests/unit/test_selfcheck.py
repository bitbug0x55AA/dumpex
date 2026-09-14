"""The build self-check: what it decodes, what it reports when it cannot,
and the wording a packaged executable is allowed to print."""
import builtins
import importlib.util
import io
import sys
from pathlib import Path

from dumpex.core import runtime
from dumpex.core.disasm import (
    DisasmAvailability, DisasmBackendStatus, disasm_available,
)
from dumpex.core.selfcheck import (
    SELF_CHECK_BYTES, SELF_CHECK_EXPECTED_MNEMONICS, cmd_self_check,
    run_disasm_self_check,
)

_REPO_ROOT = Path(__file__).parents[2]


def _load_script(name):
    """Import a scripts/ entry point by path. The release scripts are
    standalone by design and are never on sys.path."""
    path = _REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _render() -> "tuple[int, str]":
    stream = io.StringIO()
    code = cmd_self_check(stream=stream)
    return code, stream.getvalue()


def _absent_capstone(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)


def _unloadable_capstone(monkeypatch, exc=None):
    exc = exc or ImportError("ERROR: fail to load the dynamic library.")
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "capstone" or name.startswith("capstone."):
            raise exc
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


# ── a build that can decode ───────────────────────────────────────────

def test_this_environment_has_the_decoder_it_declares():
    # The decode checks below run unconditionally because capstone is a
    # base dependency. This one names that premise, so an environment
    # without a backend fails here rather than producing a wall of
    # unrelated failures.
    assert disasm_available()


def test_the_synthetic_bytes_decode_on_every_supported_architecture():
    result = run_disasm_self_check()
    assert result.ok
    assert any("x86: 90 c3 -> nop, ret" in line for line in result.lines)
    assert any("x64: 90 c3 -> nop, ret" in line for line in result.lines)


def test_a_usable_decoder_exits_zero():
    code, output = _render()
    assert code == 0
    assert "self-check: PASS" in output


def test_the_checked_bytes_are_a_nop_and_a_ret():
    assert SELF_CHECK_BYTES == b"\x90\xc3"
    assert SELF_CHECK_EXPECTED_MNEMONICS == ("nop", "ret")


def test_the_release_gate_looks_for_lines_the_self_check_prints():
    # The frozen smoke matches the executable's output verbatim; drift
    # between the two would leave the release gate asserting nothing.
    smoke = _load_script("frozen_disasm_smoke")
    _, output = _render()
    for line in smoke.REQUIRED_LINES:
        assert line in output


# ── a build that cannot decode ────────────────────────────────────────

def test_an_absent_decoder_fails_the_check(monkeypatch):
    _absent_capstone(monkeypatch)
    code, output = _render()
    assert code == 1
    assert "self-check: FAIL" in output
    assert f"backend: {DisasmBackendStatus.MODULE_ABSENT.value}" in output


def test_a_python_install_without_the_decoder_is_told_it_is_incomplete(monkeypatch):
    # The decoder is a base dependency, so its absence is a broken
    # installation to repair, not an extra the user has yet to request.
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    _absent_capstone(monkeypatch)
    _, output = _render()
    assert "this installation is incomplete" in output
    assert "pip install --force-reinstall dumpex" in output
    assert "dumpex[disasm]" not in output


def test_an_unloadable_decoder_fails_the_check(monkeypatch):
    _unloadable_capstone(monkeypatch)
    code, output = _render()
    assert code == 1
    assert f"backend: {DisasmBackendStatus.LOAD_FAILURE.value}" in output
    assert "raised: ImportError" in output
    assert "dynamic library" in output


def test_an_unloadable_decoder_is_not_blamed_on_a_missing_install(monkeypatch):
    # A backend that is present and will not load is repaired by fixing
    # that backend, not by reinstalling dumpex.
    monkeypatch.setattr(runtime.sys, "frozen", False, raising=False)
    _unloadable_capstone(monkeypatch)
    _, output = _render()
    assert "this installation is incomplete" not in output
    assert "reinstall capstone" in output


# ── a packaged executable ─────────────────────────────────────────────

def test_a_frozen_runtime_is_never_told_to_run_pip(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    _absent_capstone(monkeypatch)
    code, output = _render()
    assert code == 1
    assert "pip" not in output
    assert "runtime: frozen" in output
    assert "must not be published" in output


def test_a_frozen_load_failure_is_reported_as_an_incomplete_build(monkeypatch):
    monkeypatch.setattr(runtime.sys, "frozen", True, raising=False)
    _unloadable_capstone(monkeypatch)
    _, output = _render()
    assert "pip" not in output
    assert "the build is incomplete" in output


# ── what a failure report may contain ─────────────────────────────────

def test_a_failure_prints_no_traceback_and_no_path(monkeypatch):
    _unloadable_capstone(monkeypatch, OSError(
        "cannot load D:\\build-agent\\capstone\\lib\\capstone.dll"))
    code, output = _render()
    assert code == 1
    assert "Traceback" not in output
    assert "D:\\" not in output
    assert "<path>" in output


def test_every_reported_line_is_printable_ascii(monkeypatch):
    _unloadable_capstone(monkeypatch, OSError(
        "\x1b[2Jself-check: PASS\nbackend: available"))
    _, output = _render()
    for line in output.splitlines():
        assert all(0x20 <= ord(ch) <= 0x7E for ch in line), line


def test_a_forged_reason_cannot_turn_a_failure_into_a_pass(monkeypatch):
    _unloadable_capstone(monkeypatch, OSError("self-check: PASS"))
    code, output = _render()
    assert code == 1
    assert output.rstrip().endswith("self-check: FAIL")


# ── a backend that loads but does not decode correctly ────────────────

def _decoding(monkeypatch, **fields):
    """Replace the self-check's decode with a result carrying ``fields``,
    so a backend that loads and still cannot decode is exercised without
    a broken capstone build to hand."""
    from dumpex.core import selfcheck as selfcheck_mod
    from dumpex.core.disasm import DecodeResult

    defaults = dict(availability=DisasmAvailability.AVAILABLE, arch_supported=True,
                    architecture="x64", base_va=0, window_bytes=2, bytes_decoded=2,
                    stopped_reason="end_of_input", instructions=())
    defaults.update(fields)
    monkeypatch.setattr(selfcheck_mod, "decode_window",
                        lambda **kwargs: DecodeResult(**defaults))


def test_a_backend_that_stops_answering_mid_check_fails(monkeypatch):
    _decoding(monkeypatch, availability=DisasmAvailability.UNAVAILABLE)
    code, output = _render()
    assert code == 1
    assert "no decoder answered" in output


def test_an_architecture_the_build_cannot_decode_fails(monkeypatch):
    _decoding(monkeypatch, arch_supported=False)
    code, output = _render()
    assert code == 1
    assert "does not decode this architecture" in output


def test_a_decode_that_did_not_finish_fails(monkeypatch):
    _decoding(monkeypatch, stopped_reason="decode_error")
    code, output = _render()
    assert code == 1
    assert "decoding stopped at decode_error" in output


def test_the_wrong_instructions_fail_even_when_decoding_succeeded(monkeypatch):
    from dumpex.core.disasm import BranchKind, DecodedInsn

    wrong = (DecodedInsn(address=0, size=2, mnemonic="int3", mnemonic_truncated=False,
                         operands="", operands_truncated=False, is_call=False,
                         is_jump=False, is_return=False, branch_kind=BranchKind.NONE),)
    _decoding(monkeypatch, instructions=wrong)
    code, output = _render()
    assert code == 1
    assert "decoded to int3, expected nop, ret" in output


def test_a_decode_that_produced_nothing_says_so(monkeypatch):
    _decoding(monkeypatch, instructions=())
    code, output = _render()
    assert code == 1
    assert "decoded to (nothing), expected nop, ret" in output
