"""
Unit tests for dumpex.rules_pkg.loader — TTP rule loading/validation.

Covers _validate_rules_schema()'s rejection paths (the guard that stops a
malformed rules.yaml from silently compiling into a rule set that matches
almost anything, see the function's own docstring), --rules-file's
fail-closed behavior (missing/unreadable/unparseable/invalid-schema is a
hard exit, never a silent fallback to a DIFFERENT ruleset), and the
non-explicit path's fallback to built-in defaults.

Every test resets configure_rules_source(None) before and after so the
module-level cache/explicit-path/source-info globals never leak between
tests regardless of execution order.
"""
import json
import os
import re
import tempfile

import pytest

import dumpex.rules_pkg.loader as loader


@pytest.fixture(autouse=True)
def _reset_rules_state():
    loader.configure_rules_source(None)
    yield
    loader.configure_rules_source(None)


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


# ── _validate_rules_schema ──────────────────────────────────────────────

def test_validate_schema_accepts_well_formed_full_document():
    raw = {
        "version": 1,
        "suspicious_protections": ["PAGE_EXECUTE_READWRITE"],
        "stomping_whitelist": ["ws2_32.dll"],
        "stomping_ioc_patterns": [r"cmd\.exe"],
        "stomping_net_ioc_patterns": [r"https?://"],
        "pipe_c2_context_patterns": [r"https?://"],
        "framework_pipes": [
            {"pattern": r"msagent_", "framework": "Cobalt Strike",
             "technique": "SMB Beacon pipe", "mitre": "T1090.001"},
        ],
    }
    loader._validate_rules_schema(raw)   # must not raise


def test_validate_schema_rejects_unknown_top_level_field():
    with pytest.raises(ValueError, match="unknown top-level field"):
        loader._validate_rules_schema({"pipe_c2_context_pattern": ["typo"]})


def test_validate_schema_rejects_non_int_version():
    with pytest.raises(ValueError, match="version"):
        loader._validate_rules_schema({"version": "1"})


def test_validate_schema_rejects_non_list_pattern_field():
    # A bare string instead of a list: iterating it char-by-char would
    # silently compile into a near-match-anything regex (see the
    # function's own docstring) -- must be rejected, not silently accepted.
    with pytest.raises(ValueError, match="stomping_ioc_patterns"):
        loader._validate_rules_schema({"stomping_ioc_patterns": "http"})


def test_validate_schema_rejects_non_string_list_items():
    with pytest.raises(ValueError, match="stomping_whitelist"):
        loader._validate_rules_schema({"stomping_whitelist": ["ok.dll", 123]})


def test_validate_schema_rejects_framework_pipes_not_list_of_dicts():
    with pytest.raises(ValueError, match="framework_pipes"):
        loader._validate_rules_schema({"framework_pipes": ["not-a-dict"]})


def test_validate_schema_rejects_framework_pipe_missing_pattern():
    with pytest.raises(ValueError, match=r"framework_pipes\[0\]\.pattern"):
        loader._validate_rules_schema({"framework_pipes": [{"framework": "X"}]})


def test_validate_schema_rejects_framework_pipe_unknown_field():
    with pytest.raises(ValueError, match="unknown field"):
        loader._validate_rules_schema(
            {"framework_pipes": [{"pattern": "x", "bogus_field": "y"}]})


def test_validate_schema_rejects_framework_pipe_non_string_field():
    with pytest.raises(ValueError, match=r"framework_pipes\[0\]\.mitre"):
        loader._validate_rules_schema(
            {"framework_pipes": [{"pattern": "x", "mitre": 1234}]})


# ── --rules-file (explicit source): fail-closed, never falls back ────────

def test_explicit_rules_file_missing_exits_nonzero(tmp_path):
    loader.configure_rules_source(str(tmp_path / "does_not_exist.yaml"))
    with pytest.raises(SystemExit) as exc:
        loader.get_rules()
    assert exc.value.code != 0


def test_explicit_rules_file_invalid_json_exits_nonzero(tmp_path):
    path = _write(tmp_path, "bad.json", "{not valid json")
    loader.configure_rules_source(path)
    with pytest.raises(SystemExit):
        loader.get_rules()


def test_explicit_rules_file_non_mapping_top_level_exits_nonzero(tmp_path):
    path = _write(tmp_path, "list.json", json.dumps(["a", "b"]))
    loader.configure_rules_source(path)
    with pytest.raises(SystemExit):
        loader.get_rules()


def test_explicit_rules_file_unknown_schema_version_exits_nonzero(tmp_path):
    path = _write(tmp_path, "rules.json", json.dumps({"version": 99}))
    loader.configure_rules_source(path)
    with pytest.raises(SystemExit):
        loader.get_rules()


def test_explicit_rules_file_invalid_schema_exits_nonzero(tmp_path):
    path = _write(tmp_path, "rules.json",
                   json.dumps({"version": 1, "stomping_whitelist": "not-a-list"}))
    loader.configure_rules_source(path)
    with pytest.raises(SystemExit):
        loader.get_rules()


def test_explicit_rules_file_valid_json_loads_successfully(tmp_path):
    content = {"version": 1, "stomping_whitelist": ["custom.dll"]}
    path = _write(tmp_path, "rules.json", json.dumps(content))
    loader.configure_rules_source(path)
    rules = loader.get_rules()
    assert rules["stomping_whitelist"] == {"custom.dll"}

    info = loader.get_rules_source_info()
    assert info["explicit"] is True
    assert info["path"] == path
    assert info["version"] == 1
    assert len(info["sha256"]) == 64


def test_explicit_rules_file_get_rules_caches_across_calls(tmp_path):
    path = _write(tmp_path, "rules.json", json.dumps({"version": 1}))
    loader.configure_rules_source(path)
    first  = loader.get_rules()
    second = loader.get_rules()
    assert first is second   # cached, not reloaded/recompiled


def test_configure_rules_source_none_clears_explicit_override(tmp_path):
    path = _write(tmp_path, "rules.json", json.dumps({"version": 1}))
    loader.configure_rules_source(path)
    loader.get_rules()
    assert loader.get_rules_source_info()["explicit"] is True

    loader.configure_rules_source(None)
    loader.get_rules()   # falls through to packaged/built-in defaults
    assert loader.get_rules_source_info()["explicit"] is False


# ── non-explicit path: falls back to built-in defaults when nothing else ──
# is found (packaged rules.yaml missing, no --rules-file) ─────────────────

def test_falls_back_to_builtin_defaults_when_no_source_found(monkeypatch):
    monkeypatch.setattr(loader, "_find_rules_source", lambda: None)
    rules = loader.get_rules()
    assert rules["suspicious_protections"] == loader._DEFAULT_RULES["suspicious_protections"]
    info = loader.get_rules_source_info()
    assert info["path"] is None
    assert info["sha256"] is None
    assert info["explicit"] is False


def test_compiled_rules_have_expected_shapes(monkeypatch):
    monkeypatch.setattr(loader, "_find_rules_source", lambda: None)
    rules = loader.get_rules()
    assert isinstance(rules["suspicious_protections"], set)
    assert isinstance(rules["stomping_whitelist"], set)
    assert isinstance(rules["stomping_ioc_patterns"], re.Pattern)
    assert rules["stomping_ioc_patterns"].search("cmd.exe")
    assert isinstance(rules["framework_pipes"], list)
    pattern, framework, technique, mitre = rules["framework_pipes"][0]
    assert isinstance(pattern, re.Pattern)
    assert isinstance(framework, str)
