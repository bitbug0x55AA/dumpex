"""Keep the CLI reference aligned with the shipped interface."""
import pathlib
import re


_REFERENCE = pathlib.Path(__file__).parent.parent.parent / "docs" / "user" / "CLI_REFERENCE.md"


def _text() -> str:
    return _REFERENCE.read_text(encoding="utf-8")


def test_cli_reference_covers_every_command():
    text = _text()
    for command in (
        "list",
        "modules",
        "threads",
        "extract",
        "strings",
        "process",
        "handles",
        "profile",
        "sysinfo",
        "diff",
        "report",
        "hunt",
    ):
        assert f"`--{command}" in text


def test_cli_reference_covers_hunters_and_core_options():
    text = _text()
    for hunter in (
        "injection",
        "hollowing",
        "stomping",
        "pipe",
        "cs-beacon",
        "yara",
        "obfuscation",
    ):
        assert f"`{hunter}`" in text

    for option in (
        "--verbose",
        "--ref-dir",
        "--yara-dir",
        "--rules-file",
        "--triage-skipped",
        "--report-tid",
        "--report-addr",
        "--report-string",
        "--json",
        "--txt",
        "--redact-paths",
    ):
        assert option in text


def test_cli_reference_local_markdown_links_resolve():
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", _text()):
        path = target.split("#", 1)[0]
        if not path or "://" in path:
            continue
        assert (_REFERENCE.parent / path).resolve().is_file(), target
