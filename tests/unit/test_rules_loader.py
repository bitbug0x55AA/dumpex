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
import hashlib
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


def test_validate_schema_rejects_malformed_mitre_id():
    # Review finding: a malformed `mitre` string must be rejected HERE,
    # at load time -- not left to surface only once this specific
    # entry's pattern happens to match a pipe name in some dump (which
    # would abort that hunt run deep inside Finding.__post_init__, and
    # never surface at all for a pattern that's never actually hit).
    with pytest.raises(ValueError, match=r"framework_pipes\[0\]\.mitre"):
        loader._validate_rules_schema(
            {"framework_pipes": [{"pattern": "evil", "mitre": "not-an-attack-id"}]})


def test_validate_schema_rejects_malformed_mitre_id_missing_leading_t():
    with pytest.raises(ValueError, match=r"framework_pipes\[0\]\.mitre"):
        loader._validate_rules_schema(
            {"framework_pipes": [{"pattern": "evil", "mitre": "1055"}]})


def test_validate_schema_accepts_empty_mitre_as_no_mapping():
    # "" (or the key simply absent) means "no ATT&CK mapping for this
    # entry" -- a legitimate value, not a malformed one.
    loader._validate_rules_schema({"framework_pipes": [{"pattern": "x", "mitre": ""}]})
    loader._validate_rules_schema({"framework_pipes": [{"pattern": "x"}]})


def test_validate_schema_accepts_valid_mitre_sub_technique_id():
    loader._validate_rules_schema(
        {"framework_pipes": [{"pattern": "x", "mitre": "T1559.001"}]})


@pytest.mark.parametrize("bad_mitre", ["T1055\n", "T1559.001\n"])
def test_validate_schema_rejects_mitre_id_with_trailing_newline(bad_mitre):
    # Review finding: Python's `$` matches just before a trailing
    # newline, not only at the true end of string -- is_valid_technique_id()
    # (dumpex.core.mitre) uses fullmatch() specifically to close this, and
    # this loader must actually reject the value that predicate rejects.
    with pytest.raises(ValueError, match=r"framework_pipes\[0\]\.mitre"):
        loader._validate_rules_schema(
            {"framework_pipes": [{"pattern": "evil", "mitre": bad_mitre}]})


def test_packaged_rules_yaml_mitre_ids_are_all_valid():
    # Regression: the shipped rules.yaml/built-in defaults must themselves
    # pass the same format check a custom --rules-file is held to.
    loader.configure_rules_source(None)
    r = loader.get_rules(announce=False)
    from dumpex.core.mitre import is_valid_technique_id
    for _pattern, _framework, _technique, mitre in r["framework_pipes"]:
        assert not mitre or is_valid_technique_id(mitre), f"invalid packaged mitre id: {mitre!r}"


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


def test_explicit_rules_file_invalid_mitre_id_exits_nonzero(tmp_path):
    # A malformed `mitre` in a user-supplied --rules-file must fail
    # closed at load time, same as any other schema violation -- not
    # load successfully and only fail later, deep inside a hunt run, the
    # first time this entry's pattern happens to match something.
    content = {"version": 1, "framework_pipes": [
        {"pattern": "evil", "framework": "X", "mitre": "not-an-attack-id"}]}
    path = _write(tmp_path, "rules.json", json.dumps(content))
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


def test_explicit_rules_file_crlf_sha256_matches_raw_bytes(tmp_path):
    # Review finding: text-mode read (Path.read_text()) performs universal-
    # newline translation, silently turning "\r\n" into "\n" -- hashing the
    # re-encoded, already-translated text produced a digest that could
    # never match `certutil -hashfile`/`sha256sum` run against the actual
    # file, defeating the whole point of this field as verifiable
    # provenance. The digest MUST be computed over the exact bytes on disk.
    content = (b'{"version": 1, "stomping_whitelist": ["custom.dll"]}\r\n')
    path = tmp_path / "rules.json"
    path.write_bytes(content)
    real_sha256 = hashlib.sha256(content).hexdigest()

    loader.configure_rules_source(str(path))
    loader.get_rules()
    info = loader.get_rules_source_info()
    assert info["sha256"] == real_sha256


def test_packaged_rules_file_crlf_sha256_matches_raw_bytes(tmp_path, monkeypatch):
    # Same regression as the --rules-file test above, but for the
    # non-explicit (_find_rules_source()/_RuleSource) path -- both used to
    # share the identical text-then-reencode bug.
    content = b"version: 1\r\nstomping_whitelist:\r\n  - custom.dll\r\n"
    path = tmp_path / "rules.yaml"
    path.write_bytes(content)
    real_sha256 = hashlib.sha256(content).hexdigest()

    src = loader._RuleSource(str(path), ".yaml", path.read_bytes)
    monkeypatch.setattr(loader, "_find_rules_source", lambda: src)

    loader.get_rules(announce=False)
    info = loader.get_rules_source_info()
    assert info["sha256"] == real_sha256


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


# ── packaged rules.yaml is the canonical source; _DEFAULT_RULES is an ────
# emergency-only fallback for a corrupted/missing package resource, not a
# second copy of the ruleset that's free to drift from it ────────────────

def test_packaged_rules_match_builtin_fallback():
    """
    _DEFAULT_RULES only runs when the packaged rules.yaml can't be read at
    all (see _load_rules's exception handler) -- a case that, with pyyaml
    now a base dependency, should be rare. If it ever IS hit, it must
    produce the same ruleset the packaged file does, not a stale one.
    Editing rules.yaml without updating _DEFAULT_RULES to match must fail
    this test, not silently ship a fallback that scores differently.
    """
    import yaml
    from importlib import resources

    text = resources.files("dumpex.rules_pkg").joinpath("data", "rules.yaml").read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    loader._validate_rules_schema(raw)   # same schema check the loader itself applies

    defaults = loader._DEFAULT_RULES

    assert set(raw["suspicious_protections"]) == defaults["suspicious_protections"]
    assert set(raw["stomping_whitelist"]) == defaults["stomping_whitelist"]

    for field in ("stomping_ioc_patterns", "stomping_net_ioc_patterns", "pipe_c2_context_patterns"):
        assert raw[field] == defaults[field], f"'{field}' drifted between rules.yaml and _DEFAULT_RULES"

    # Compare the raw pattern/framework/technique/mitre fields directly --
    # not _compile_rules()'s output, which turns these into compiled
    # re.Pattern objects that can never compare equal across two
    # independently-compiled sources even when their source text matches.
    assert raw["framework_pipes"] == defaults["framework_pipes"], \
        "'framework_pipes' drifted between rules.yaml and _DEFAULT_RULES"


def test_base_install_loads_packaged_rules_not_builtin_fallback():
    """
    pyyaml is a base dependency (see pyproject.toml) specifically so a
    plain `pip install dumpex` -- no --rules-file, no yara-python -- can
    still read the packaged canonical rules.yaml instead of silently
    dropping to _DEFAULT_RULES. Exercises the real, unpatched
    _find_rules_source()/_packaged_source() resolution path.
    """
    rules = loader.get_rules()
    assert rules["suspicious_protections"]

    info = loader.get_rules_source_info()
    assert info is not None
    assert info["path"] is not None
    assert "rules_pkg" in info["path"]
    assert info["explicit"] is False
    assert info["sha256"] is not None
    assert len(info["sha256"]) == 64
