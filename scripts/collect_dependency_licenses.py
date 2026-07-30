"""Collect license files for runtime dependencies into a release artifact.

The frozen Windows executable contains dependency code, so its release must
carry those dependencies' own notices in addition to dumpex's project and
embedded-source notices.
"""

from __future__ import annotations

import argparse
from collections import deque
from importlib import metadata
from pathlib import Path
import re
import shutil

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


_PROJECT = "dumpex"
_ENABLED_EXTRAS = ("", "full")
_NOTICE_PREFIXES = ("license", "copying", "notice")


def _runtime_distributions() -> list[metadata.Distribution]:
    """Return dumpex's base/full dependency closure, excluding dumpex itself."""
    environment = default_environment()
    pending: deque[str] = deque()
    seen = {_PROJECT}
    result: list[metadata.Distribution] = []

    project = metadata.distribution(_PROJECT)
    for requirement_text in project.requires or ():
        requirement = Requirement(requirement_text)
        if requirement.marker is None or any(
            requirement.marker.evaluate({**environment, "extra": extra})
            for extra in _ENABLED_EXTRAS
        ):
            pending.append(requirement.name)

    while pending:
        requested_name = pending.popleft()
        canonical_name = canonicalize_name(requested_name)
        if canonical_name in seen:
            continue

        distribution = metadata.distribution(requested_name)
        seen.add(canonical_name)
        result.append(distribution)

        for requirement_text in distribution.requires or ():
            requirement = Requirement(requirement_text)
            if requirement.marker is None or requirement.marker.evaluate(
                {**environment, "extra": ""}
            ):
                pending.append(requirement.name)

    return sorted(
        result,
        key=lambda distribution: canonicalize_name(
            distribution.metadata["Name"]
        ),
    )


def _is_notice_file(path: Path) -> bool:
    name = path.name.lower()
    return any(
        name == prefix
        or name.startswith(f"{prefix}.")
        or name.startswith(f"{prefix}-")
        for prefix in _NOTICE_PREFIXES
    )


def collect(output_dir: Path) -> None:
    """Copy dependency license files and write a versioned index."""
    output_dir = output_dir.resolve()
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    index_lines = [
        "Runtime dependency licenses",
        "===========================",
        "",
        "These are the license and notice files shipped by the installed",
        "distributions used to build the dumpex executable.",
        "",
    ]

    for distribution in _runtime_distributions():
        package_name = distribution.metadata["Name"]
        version = distribution.version
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", package_name)
        package_dir = output_dir / f"{safe_name}-{version}"

        notice_files = [
            file
            for file in (distribution.files or ())
            if _is_notice_file(Path(str(file)))
        ]
        if not notice_files:
            raise RuntimeError(
                f"{package_name} {version} contains no discoverable license "
                "or notice file"
            )

        package_dir.mkdir()
        index_lines.append(f"{package_name} {version}")
        for number, file in enumerate(notice_files, start=1):
            source = Path(distribution.locate_file(file))
            destination_name = source.name
            destination = package_dir / destination_name
            if destination.exists():
                destination = package_dir / f"{number}-{destination_name}"
            shutil.copyfile(source, destination)
            index_lines.append(f"  {package_dir.name}/{destination.name}")
        index_lines.append("")

    (output_dir / "INDEX.txt").write_text(
        "\n".join(index_lines), encoding="utf-8", newline="\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "output_dir",
        type=Path,
        help="directory to replace with the collected dependency notices",
    )
    args = parser.parse_args()
    collect(args.output_dir)


if __name__ == "__main__":
    main()
