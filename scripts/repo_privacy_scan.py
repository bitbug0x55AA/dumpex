"""Fail CI when tracked files violate dumpex's privacy boundary.

This scanner complements a general secret scanner.  It deliberately reports
only rule IDs, paths, and line numbers; matched content is never echoed because
the finding itself may be sensitive.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MAX_TEXT_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    message: str
    line: int | None = None

    def render(self) -> str:
        location = f"{self.path}:{self.line}" if self.line is not None else self.path
        return f"[{self.rule}] {location} - {self.message}"


FORBIDDEN_PATH_RULES: tuple[tuple[str, str, str], ...] = (
    (
        "private-corpus-material",
        "tests/corpus/private/**",
        "local-only corpus material must not be tracked",
    ),
    (
        "real-corpus-sample",
        "tests/corpus/clean/samples/**",
        "real clean samples must remain outside Git",
    ),
    (
        "real-corpus-sample",
        "tests/corpus/evil/samples/**",
        "real malicious samples must remain outside Git",
    ),
    (
        "real-corpus-manifest",
        "tests/corpus/clean/manifest.yaml",
        "real manifests may contain private case metadata",
    ),
    (
        "real-corpus-manifest",
        "tests/corpus/evil/manifest.yaml",
        "real manifests may contain private case metadata",
    ),
    (
        "local-tool-settings",
        ".claude/settings.local.json",
        "local tool settings may contain usernames and command history",
    ),
    (
        "local-tool-settings",
        ".idea/workspace.xml",
        "IDE workspace state is local and may contain absolute paths",
    ),
)

SENSITIVE_SUFFIXES = frozenset({".dmp", ".mdmp", ".vmem", ".p12", ".pfx", ".ovpn"})
SENSITIVE_NAMES = frozenset(
    {
        ".env",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)
ENV_TEMPLATE_NAMES = frozenset({".env.example", ".env.sample", ".env.template"})


@dataclass(frozen=True)
class ContentRule:
    rule: str
    regex: re.Pattern[str]
    message: str


CONTENT_RULES: tuple[ContentRule, ...] = (
    ContentRule(
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.IGNORECASE,
        ),
        "private key material is present",
    ),
    ContentRule(
        "windows-user-profile",
        re.compile(r"\b[A-Z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+", re.IGNORECASE),
        "an absolute Windows user-profile path is present",
    ),
)


def _normalise_path(path: str | Path) -> str:
    return str(path).replace("\\", "/").removeprefix("./")


def check_path(path: str | Path) -> list[Finding]:
    normalised = _normalise_path(path)
    lowered = normalised.lower()
    name = lowered.rsplit("/", 1)[-1]
    suffix = Path(name).suffix.lower()
    findings: list[Finding] = []

    for rule, pattern, message in FORBIDDEN_PATH_RULES:
        if fnmatch.fnmatch(lowered, pattern.lower()):
            findings.append(Finding(rule, normalised, message))

    if suffix in SENSITIVE_SUFFIXES:
        findings.append(
            Finding(
                "sensitive-file-type",
                normalised,
                f"files with the {suffix} suffix must not be tracked",
            )
        )

    if name in SENSITIVE_NAMES or (
        name.startswith(".env.") and name not in ENV_TEMPLATE_NAMES
    ):
        findings.append(
            Finding(
                "credential-file",
                normalised,
                "credential-bearing files must not be tracked",
            )
        )

    return findings


def check_content(path: str | Path, data: bytes) -> list[Finding]:
    normalised = _normalise_path(path)
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for content_rule in CONTENT_RULES:
            if content_rule.regex.search(line):
                findings.append(
                    Finding(
                        content_rule.rule,
                        normalised,
                        content_rule.message,
                        line_number,
                    )
                )
    return findings


def scan_files(root: Path, paths: Iterable[str]) -> list[Finding]:
    findings: list[Finding] = []
    for raw_path in sorted({_normalise_path(path) for path in paths}):
        findings.extend(check_path(raw_path))
        file_path = root / Path(raw_path)
        if file_path.is_file():
            try:
                findings.extend(check_content(raw_path, file_path.read_bytes()))
            except OSError as exc:
                findings.append(
                    Finding("unreadable-file", raw_path, f"could not read tracked file: {exc}")
                )
    return findings


def tracked_files(root: Path) -> list[str]:
    command = [
        "git",
        "-c",
        f"safe.directory={root.resolve().as_posix()}",
        "ls-files",
        "-z",
    ]
    result = subprocess.run(
        command,
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return [part.decode("utf-8") for part in result.stdout.split(b"\0") if part]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan tracked files for dumpex privacy-policy violations."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root (default: current directory)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    try:
        paths = tracked_files(root)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"privacy scan could not enumerate tracked files: {exc}", file=sys.stderr)
        return 2

    findings = scan_files(root, paths)
    if findings:
        print(f"Privacy policy scan failed with {len(findings)} finding(s):", file=sys.stderr)
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        print("Matched content is intentionally omitted from this log.", file=sys.stderr)
        return 1

    print(f"Privacy policy scan passed for {len(paths)} tracked file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
