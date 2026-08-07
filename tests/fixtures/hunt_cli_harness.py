"""
Shared CLI-invocation harness for `--hunt` fixtures -- used by BOTH
tests/integration/test_hunt_cli_compat_freeze.py and
scripts/update_hunt_cli_goldens.py, so the two can never drift apart on
what "running a scenario" means (frozen datetime, rules-loader reset,
object-address normalization, where the console body actually ends).
Extracted from test_hunt_cli_compat_freeze.py as part of the Phase 3
golden-infrastructure work: the golden generator used to be an
uncommitted, one-off script reimplementing this by hand.
"""
import contextlib
import datetime
import io
import json
import re
import sys

import dumpex.cli as cli
import dumpex.ui.structured as structured_mod
import dumpex.rules_pkg.loader as rules_loader
import dumpex.hunt.yara_hunt as yara_hunt_mod

_OBJ_ADDR_RE = re.compile(r"(<[\w.]+ object at )0x[0-9A-Fa-f]+(>)")


def normalize_object_addresses(obj):
    """Replace `<module.Class object at 0x...>` -- the live interpreter
    heap address `_json_safe()`'s `str(obj)` fallback embeds for any raw
    fake/real object it doesn't know how to convert -- with a fixed
    placeholder, matching the same normalization the golden fixtures
    themselves were generated with. Without this, comparing either
    hunter's full JSON record against a golden snapshot would be flaky by
    construction: the address is different on every single run, identical
    input or not."""
    if isinstance(obj, str):
        return _OBJ_ADDR_RE.sub(r"\g<1>0xNORMALIZED\g<2>", obj)
    if isinstance(obj, list):
        return [normalize_object_addresses(x) for x in obj]
    if isinstance(obj, dict):
        return {k: normalize_object_addresses(v) for k, v in obj.items()}
    return obj


class _FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, tzinfo=tz)


_real_timezone = datetime.timezone
_real_timedelta = datetime.timedelta


class FrozenDateTimeModule:
    datetime = _FixedDateTime
    timezone = _real_timezone
    timedelta = _real_timedelta


def run_cli(monkeypatch, tmp_path, argv_extra, mf):
    """Run the real `cli.main()` end to end against a synthetic `mf`, with
    everything a byte-for-byte-reproducible golden snapshot needs pinned:
    frozen `datetime.datetime.now()` (so `meta.execution.started_at/
    finished_at/duration_seconds` are reproducible) and reset global
    rules-loader state (so no earlier scenario's loaded/cached rules can
    leak in). `monkeypatch` is the caller's -- a pytest fixture when called
    from a test (auto-`.undo()`'d when that test ends), or a
    `pytest.MonkeyPatch()` instance the generator script constructs and
    `.undo()`'s itself, in a `finally`, once each scenario run's result has
    been extracted -- see scripts/update_hunt_cli_goldens.py."""
    monkeypatch.setattr(cli, "datetime", FrozenDateTimeModule)
    monkeypatch.setattr(structured_mod, "datetime", FrozenDateTimeModule)
    # Reset via monkeypatch (auto-restored when a pytest-fixture caller's
    # test ends), not configure_rules_source(None) (a bare global mutation
    # with no restoration) -- see this module's own docstring.
    monkeypatch.setattr(rules_loader, "_RULES_CACHE", None)
    monkeypatch.setattr(rules_loader, "_EXPLICIT_RULES_PATH", None)
    monkeypatch.setattr(rules_loader, "_LAST_SOURCE_INFO", None)
    monkeypatch.setattr(yara_hunt_mod, "_LAST_YARA_PROVENANCE", None)

    dump_path = str(tmp_path / "test.dmp")
    with open(dump_path, "wb") as fh:
        fh.write(b"synthetic dump content")
    mf.filename = dump_path
    monkeypatch.setattr(cli, "open_dump", lambda path: mf)

    out_json = str(tmp_path / "out.json")
    argv = ["dumpex", dump_path, *argv_extra, "--json", out_json, "--force"]
    monkeypatch.setattr(sys, "argv", argv)

    buf = io.StringIO()
    exit_code = 0
    with contextlib.redirect_stdout(buf):
        try:
            cli.main()
        except SystemExit as exc:
            exit_code = exc.code
    doc = json.loads(open(out_json, encoding="utf-8").read())
    return exit_code, doc, buf.getvalue()


def split_console_body(console_text: str) -> str:
    """Console output ends with a JSON write confirmation line whose byte
    offset/path is run-specific -- golden
    fixtures freeze everything BEFORE that point only."""
    write_start = console_text.find("  [·] JSON written")
    assert write_start != -1, "missing JSON write confirmation line"
    return console_text[:write_start]
