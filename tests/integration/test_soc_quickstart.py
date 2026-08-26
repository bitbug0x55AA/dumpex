"""Keep the quickstart's operational guidance aligned with the CLI."""
import pathlib
import re


_QUICKSTART = pathlib.Path(__file__).parent.parent.parent / "docs" / "user" / "SOC_QUICKSTART.md"


def _text() -> str:
    return _QUICKSTART.read_text(encoding="utf-8")


def test_quickstart_preserves_status_coverage_disposition():
    text = _text()
    for value in (
        "DETECTED",
        "NOT_DETECTED_IN_SCANNED_SCOPE",
        "INCONCLUSIVE",
        "NOT_EVALUATED",
        "complete",
        "partial",
        "not_evaluated",
    ):
        assert value in text

    assert "`status` and `coverage.status` are separate axes" in text
    assert "Never translate `INCONCLUSIVE` or `NOT_EVALUATED` into “clean.”" in text


def test_quickstart_covers_every_command_and_hunter():
    text = _text()
    for command in (
        "profile",
        "sysinfo",
        "process",
        "handles",
        "list",
        "modules",
        "threads",
        "hunt",
        "report",
        "extract",
        "strings",
        "diff",
    ):
        assert f"`--{command}" in text

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


def test_quickstart_keeps_core_follow_up_and_provenance():
    text = _text()
    for term in (
        "--ref-dir",
        "--triage-skipped",
        "--redact-paths",
        "investigation_actions",
        "meta.evidence",
        "meta.execution",
        "meta.rules",
        "meta.yara_rules",
    ):
        assert term in text


def test_quickstart_local_markdown_links_resolve():
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", _text()):
        path = target.split("#", 1)[0]
        if not path or "://" in path:
            continue
        assert (_QUICKSTART.parent / path).resolve().is_file(), target
