"""The decoder backend seam: telling an absent dependency apart from one
that is present and will not load, and keeping the reason for either
bounded and safe to print.

The absent states below are simulated. capstone is a base dependency, so
a real installation reaches
:func:`test_a_loaded_backend_is_named_on_every_decode_result`."""
import builtins
import sys

import pytest

from dumpex.core import disasm
from dumpex.core.disasm import (
    MAX_BACKEND_REASON_CHARS, DisasmAvailability, DisasmBackendStatus,
    backend_status, decode_window, disasm_available,
)

_NOP_RET = b"\x90\xc3"
BASE = 0x140001000


def _raising_import(monkeypatch, exc):
    """Make ``import capstone`` raise ``exc`` while every other import
    keeps working, so one backend failure can be reproduced exactly."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "capstone" or name.startswith("capstone."):
            raise exc
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_an_uninstalled_capstone_is_an_absent_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.MODULE_ABSENT
    assert not backend.available
    assert not disasm_available()


def test_a_native_library_that_does_not_load_is_not_an_absent_module(monkeypatch):
    # capstone resolves capstone.dll through ctypes.CDLL() during its own
    # import and raises ImportError when no candidate path loads.
    _raising_import(monkeypatch,
                    ImportError("ERROR: fail to load the dynamic library."))
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.LOAD_FAILURE
    assert backend.exception_type == "ImportError"
    assert "dynamic library" in backend.reason


def test_an_unloadable_native_library_is_a_load_failure(monkeypatch):
    _raising_import(monkeypatch, OSError("is not a valid Win32 application"))
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.LOAD_FAILURE
    assert backend.exception_type == "OSError"


def test_a_missing_dependency_of_capstone_is_a_load_failure(monkeypatch):
    # capstone is installed; something it imports is not. The declared
    # dependency is present, so this is a broken backend, not an absent one.
    _raising_import(monkeypatch, ModuleNotFoundError("No module named 'ctypes'",
                                                     name="ctypes"))
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.LOAD_FAILURE


@pytest.mark.parametrize("submodule", ["capstone.x86", "capstone.x86_const"])
def test_a_missing_capstone_submodule_is_a_load_failure(monkeypatch, submodule):
    # The distribution is installed and incomplete -- a damaged install,
    # or packaging that left a submodule behind. Installing what is
    # already there is not the remedy.
    _raising_import(monkeypatch,
                    ModuleNotFoundError(f"No module named '{submodule}'",
                                        name=submodule))
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.LOAD_FAILURE


def test_an_unnamed_import_failure_is_not_read_as_an_absent_dependency(monkeypatch):
    _raising_import(monkeypatch, ModuleNotFoundError("something went missing"))
    assert backend_status().status is DisasmBackendStatus.LOAD_FAILURE


def test_an_internal_capstone_import_failure_is_a_load_failure(monkeypatch):
    _raising_import(monkeypatch, RuntimeError("capstone internals disagreed"))
    backend = backend_status()
    assert backend.status is DisasmBackendStatus.LOAD_FAILURE
    assert backend.exception_type == "RuntimeError"


@pytest.mark.parametrize("message", [
    r"cannot load C:\profiles\Jane Doe\AppData\Local\capstone.dll",
    r"cannot load C:\Program Files\Python\capstone.dll",
    r"cannot load C:/profiles/Jane Doe/AppData/capstone.dll",
    r"cannot load \\build server\share\capstone.dll",
    'cannot load "C:\\Program Files\\Python\\capstone.dll"',
    r"cannot load C:\profiles\Jane Doe",
    r"cannot load /opt/build agent/lib/libcapstone.so",
])
def test_a_backend_reason_redacts_a_path_whose_spaces_hide_its_end(monkeypatch, message):
    # A directory name may contain a space, so a path is redacted through
    # to the next quote or the end of the message rather than to the next
    # space -- a surname or an install directory must not survive in the
    # tail of a release log.
    _raising_import(monkeypatch, OSError(message))
    reason = backend_status().reason

    assert "<path>" in reason
    for leak in ("Jane", "Doe", "Program Files", "build server", "build agent",
                 "AppData", "capstone.dll", "libcapstone.so", "share"):
        assert leak not in reason


def test_a_backend_reason_keeps_the_text_around_a_quoted_path(monkeypatch):
    _raising_import(monkeypatch, OSError(
        "Could not find module 'C:\\lib\\capstone.dll' (or one of its dependencies)"))
    assert backend_status().reason == (
        "Could not find module '<path>' (or one of its dependencies)")


def test_a_backend_reason_drops_control_characters(monkeypatch):
    _raising_import(monkeypatch, OSError(
        "\x1b[31mSELF-CHECK PASS\x1b[0m\nself-check: PASS"))
    reason = backend_status().reason

    assert "\x1b" not in reason and "\n" not in reason
    assert all(0x20 <= ord(ch) <= 0x7E for ch in reason)


def test_a_backend_reason_is_cut_to_its_cap(monkeypatch):
    _raising_import(monkeypatch, OSError("load failed: " + "z" * 400))
    backend = backend_status()

    assert len(backend.reason) == MAX_BACKEND_REASON_CHARS
    assert backend.reason_truncated


def test_a_loaded_backend_carries_no_failure_reason():
    backend = backend_status()
    assert backend.available, (
        "capstone is a base dependency of dumpex: an environment that can "
        "import dumpex must be able to decode")
    assert backend.exception_type is None
    assert backend.reason is None
    assert backend.version


def test_decode_window_reports_the_backend_that_did_not_load(monkeypatch):
    _raising_import(monkeypatch,
                    ImportError("ERROR: fail to load the dynamic library."))
    result = decode_window(code=_NOP_RET, base_va=BASE, architecture="x64")

    assert result.availability is DisasmAvailability.UNAVAILABLE
    assert result.instructions == ()
    assert not result.decoded_ok
    assert result.backend.status is DisasmBackendStatus.LOAD_FAILURE


def test_decode_window_reports_an_absent_module_as_absent(monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    result = decode_window(code=_NOP_RET, base_va=BASE, architecture="x64")

    assert result.availability is DisasmAvailability.UNAVAILABLE
    assert result.backend.status is DisasmBackendStatus.MODULE_ABSENT


def test_a_loaded_backend_is_named_on_every_decode_result():
    assert disasm_available(), (
        "capstone is a base dependency of dumpex: an environment that can "
        "import dumpex must be able to decode")
    result = decode_window(code=_NOP_RET, base_va=BASE, architecture="x64")
    assert result.backend.status is DisasmBackendStatus.AVAILABLE

    unsupported = decode_window(code=_NOP_RET, base_va=BASE, architecture="arm64")
    assert unsupported.backend.status is DisasmBackendStatus.AVAILABLE


def test_the_backend_is_consulted_on_every_call(monkeypatch):
    # No cached module survives a change in what is importable, so a
    # decoder that disappears mid-process is reported, not assumed.
    first = backend_status().status
    monkeypatch.setitem(sys.modules, "capstone", None)
    assert backend_status().status is DisasmBackendStatus.MODULE_ABSENT
    monkeypatch.undo()
    assert backend_status().status is first


def test_a_non_string_exception_message_still_yields_a_bounded_reason(monkeypatch):
    class _Weird(Exception):
        def __str__(self):
            return "\x00\x01" * 200

    _raising_import(monkeypatch, _Weird())
    reason = backend_status().reason
    assert len(reason) <= MAX_BACKEND_REASON_CHARS
    assert all(0x20 <= ord(ch) <= 0x7E for ch in reason)


def test_sanitizing_leaves_ordinary_prose_alone():
    reason, truncated = disasm._sanitize_reason("the backend and/or its loader failed")
    assert reason == "the backend and/or its loader failed"
    assert not truncated


def test_the_backend_version_falls_back_to_the_native_library():
    class _Binding:
        def cs_version(self):
            return (5, 0, 1280)

    assert disasm._backend_version(_Binding()) == "5.0.1280"


def test_an_unreadable_backend_version_is_reported_as_absent():
    class _Binding:
        def cs_version(self):
            raise OSError("the native library did not answer")

    assert disasm._backend_version(_Binding()) is None


def test_a_hostile_backend_version_is_sanitized_like_any_other_reason():
    class _Binding:
        __version__ = "5.0.7\nself-check: PASS"

    assert "\n" not in disasm._backend_version(_Binding())
