"""Validate, materialize, and remove private dumpex process-dump corpora.

The public repository owns the corpus contract. Real manifests and DMP files
remain in private storage and are copied into the ignored tests/corpus paths
only for an authorized test run.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import sys

import yaml


KINDS = ("clean", "evil")
HUNTERS = {
    "injection",
    "hollowing",
    "stomping",
    "pipe",
    "cs-beacon",
    "yara",
    "obfuscation",
}
STATUSES = {
    "DETECTED",
    "NOT_DETECTED_IN_SCANNED_SCOPE",
    "INCONCLUSIVE",
    "NOT_EVALUATED",
}
COVERAGE_STATUSES = {"complete", "partial", "not_evaluated"}
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class CorpusError(ValueError):
    """A corpus violates the public contract or safe filesystem boundaries."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _private_targets(root: Path) -> list[Path]:
    return [
        root / kind / private_name
        for kind in KINDS
        for private_name in ("manifest.yaml", "samples")
    ]


def _assert_corpus_mount(root: Path) -> Path:
    resolved = root.resolve()
    if not (resolved / "README.md").is_file():
        raise CorpusError(f"refusing corpus operation: missing {resolved / 'README.md'}")
    for kind in KINDS:
        if not (resolved / kind / "README.md").is_file():
            raise CorpusError(
                f"refusing corpus operation: missing {resolved / kind / 'README.md'}"
            )
    return resolved


def _safe_sample_path(kind_root: Path, value: object, sample_id: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{sample_id}: file must be a non-empty relative path")

    portable = PurePosixPath(value.replace("\\", "/"))
    if portable.is_absolute() or ".." in portable.parts:
        raise CorpusError(f"{sample_id}: sample path escapes its corpus: {value!r}")
    if not portable.parts or portable.parts[0] != "samples":
        raise CorpusError(f"{sample_id}: file must live below samples/: {value!r}")

    candidate = kind_root.joinpath(*portable.parts).resolve()
    try:
        candidate.relative_to(kind_root.resolve())
    except ValueError as exc:
        raise CorpusError(
            f"{sample_id}: resolved sample path escapes its corpus: {value!r}"
        ) from exc
    return candidate


def _load_yaml_mapping(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as fh:
            value = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise CorpusError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CorpusError(f"{path}: manifest root must be a mapping")
    return value


def validate_manifest(
    manifest_path: Path,
    *,
    expected_kind: str | None = None,
    require_files: bool = True,
) -> dict:
    manifest_path = manifest_path.resolve()
    manifest = _load_yaml_mapping(manifest_path)
    label = str(manifest_path)

    if manifest.get("version") != 2:
        raise CorpusError(f"{label}: version must be 2")

    kind = manifest.get("kind")
    if kind not in KINDS:
        raise CorpusError(f"{label}: kind must be clean or evil")
    if expected_kind is not None and kind != expected_kind:
        raise CorpusError(
            f"{label}: manifest kind {kind!r} does not match directory "
            f"{expected_kind!r}"
        )

    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        raise CorpusError(f"{label}: policy must be a mapping")
    if kind == "clean":
        false_positive = policy.get("false_positive")
        if not isinstance(false_positive, dict):
            raise CorpusError(f"{label}: false_positive policy must be a mapping")
        maximum = false_positive.get("max_detected_hunts")
        if maximum != 0:
            raise CorpusError(
                f"{label}: clean policy must set "
                "false_positive.max_detected_hunts: 0"
            )
    else:
        false_negative = policy.get("false_negative")
        if not isinstance(false_negative, dict):
            raise CorpusError(f"{label}: false_negative policy must be a mapping")
        required = false_negative.get("require_ground_truth_detection")
        if required is not True:
            raise CorpusError(
                f"{label}: evil policy must set "
                "false_negative.require_ground_truth_detection: true"
            )

    samples = manifest.get("samples")
    if not isinstance(samples, list) or not samples:
        raise CorpusError(f"{label}: samples must be a non-empty list")

    ids: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise CorpusError(f"{label}: samples[{index}] must be a mapping")
        sample_id = sample.get("id")
        if not isinstance(sample_id, str) or not sample_id.strip():
            raise CorpusError(f"{label}: samples[{index}].id is required")
        if sample_id in ids:
            raise CorpusError(f"{label}: duplicate sample id {sample_id!r}")
        ids.add(sample_id)

        for field in ("file", "sha256", "category", "source", "authorization"):
            if not isinstance(sample.get(field), str) or not sample[field].strip():
                raise CorpusError(f"{sample_id}: missing required field {field!r}")

        expected_hash = sample["sha256"]
        if not SHA256_RE.fullmatch(expected_hash):
            raise CorpusError(f"{sample_id}: sha256 must contain 64 hex characters")

        sample_path = _safe_sample_path(manifest_path.parent, sample["file"], sample_id)
        if require_files:
            if not sample_path.is_file():
                raise CorpusError(f"{sample_id}: sample file not found: {sample_path}")
            actual_hash = sha256_file(sample_path)
            if actual_hash.lower() != expected_hash.lower():
                raise CorpusError(
                    f"{sample_id}: sha256 mismatch "
                    f"(expected {expected_hash.lower()}, got {actual_hash})"
                )

        if kind == "clean":
            if sample.get("category") != "clean":
                raise CorpusError(f"{sample_id}: clean corpus requires category: clean")
        else:
            ground_truth = sample.get("ground_truth")
            if not isinstance(ground_truth, dict):
                raise CorpusError(f"{sample_id}: ground_truth mapping is required")
            detected_hunts = ground_truth.get("detected_hunts")
            if not isinstance(detected_hunts, list) or not detected_hunts:
                raise CorpusError(
                    f"{sample_id}: ground_truth.detected_hunts must be non-empty"
                )
            if not all(isinstance(hunter, str) for hunter in detected_hunts):
                raise CorpusError(
                    f"{sample_id}: ground_truth.detected_hunts must contain strings"
                )
            if len(detected_hunts) != len(set(detected_hunts)):
                raise CorpusError(
                    f"{sample_id}: ground_truth.detected_hunts must be unique"
                )
            unknown = set(detected_hunts) - HUNTERS
            if unknown:
                raise CorpusError(
                    f"{sample_id}: unknown ground-truth hunters: {sorted(unknown)}"
                )
            if (
                not isinstance(ground_truth.get("basis"), str)
                or not ground_truth["basis"].strip()
            ):
                raise CorpusError(f"{sample_id}: ground_truth.basis is required")

        expected = sample.get("expected", {})
        if not isinstance(expected, dict):
            raise CorpusError(f"{sample_id}: expected must be a mapping")
        expected_hunts = expected.get("hunt", {})
        if not isinstance(expected_hunts, dict):
            raise CorpusError(f"{sample_id}: expected.hunt must be a mapping")
        for hunter, assertion in expected_hunts.items():
            if hunter not in HUNTERS:
                raise CorpusError(f"{sample_id}: unknown expected hunter {hunter!r}")
            if not isinstance(assertion, dict):
                raise CorpusError(
                    f"{sample_id}/{hunter}: expected assertion must be a mapping"
                )
            status = assertion.get("status")
            if status is not None and status not in STATUSES:
                raise CorpusError(
                    f"{sample_id}/{hunter}: invalid status {status!r}"
                )
            coverage = assertion.get("coverage_status")
            if coverage is not None and coverage not in COVERAGE_STATUSES:
                raise CorpusError(
                    f"{sample_id}/{hunter}: invalid coverage_status {coverage!r}"
                )
            minimum = assertion.get("min_score")
            if minimum is not None and (
                not isinstance(minimum, int)
                or isinstance(minimum, bool)
                or minimum < 0
            ):
                raise CorpusError(
                    f"{sample_id}/{hunter}: min_score must be a non-negative integer"
                )

    return manifest


def discover_manifests(root: Path) -> dict[str, Path]:
    resolved = root.resolve()
    return {
        kind: path
        for kind in KINDS
        if (path := resolved / kind / "manifest.yaml").is_file()
    }


def validate_root(
    root: Path,
    *,
    require_kinds: tuple[str, ...] = (),
    require_files: bool = True,
    public_mount: bool = False,
) -> dict[str, dict]:
    resolved = _assert_corpus_mount(root) if public_mount else root.resolve()
    manifests = discover_manifests(resolved)
    missing = set(require_kinds) - set(manifests)
    if missing:
        raise CorpusError(f"{resolved}: missing required corpora: {sorted(missing)}")
    if not manifests:
        raise CorpusError(f"{resolved}: no clean/manifest.yaml or evil/manifest.yaml")

    loaded = {
        kind: validate_manifest(
            path,
            expected_kind=kind,
            require_files=require_files,
        )
        for kind, path in manifests.items()
    }
    all_ids = [
        sample["id"]
        for manifest in loaded.values()
        for sample in manifest["samples"]
    ]
    duplicates = sorted(
        {sample_id for sample_id in all_ids if all_ids.count(sample_id) > 1}
    )
    if duplicates:
        raise CorpusError(f"duplicate sample ids across corpora: {duplicates}")
    return loaded


def _versioned_source(source: Path, version: str | None) -> Path:
    resolved = source.resolve()
    if version:
        if not VERSION_RE.fullmatch(version):
            raise CorpusError(
                "corpus version may contain only letters, numbers, dot, underscore, "
                "and hyphen"
            )
        resolved = (resolved / version).resolve()
    if not resolved.is_dir():
        raise CorpusError(f"private corpus source does not exist: {resolved}")
    return resolved


def cleanup(root: Path) -> list[Path]:
    resolved = _assert_corpus_mount(root)
    removed = []
    for target in _private_targets(resolved):
        try:
            target.resolve().relative_to(resolved)
        except ValueError as exc:
            raise CorpusError(f"refusing cleanup outside corpus mount: {target}") from exc
        if target.is_symlink():
            target.unlink()
            removed.append(target)
        elif target.is_dir():
            shutil.rmtree(target)
            removed.append(target)
        elif target.exists():
            target.unlink()
            removed.append(target)
    return removed


def materialize(
    source: Path,
    destination: Path,
    *,
    version: str | None = None,
    require_kinds: tuple[str, ...] = (),
) -> tuple[Path, dict[str, dict]]:
    source_root = _versioned_source(source, version)
    destination_root = _assert_corpus_mount(destination)
    if source_root == destination_root:
        raise CorpusError("private source and public corpus mount must be different")

    loaded = validate_root(
        source_root,
        require_kinds=require_kinds,
        require_files=True,
    )
    existing = [
        path
        for path in _private_targets(destination_root)
        if path.exists() or path.is_symlink()
    ]
    if existing:
        raise CorpusError(
            "destination already contains private corpus artifacts; run cleanup first: "
            + ", ".join(str(path) for path in existing)
        )

    copied_targets: list[Path] = []
    try:
        for kind, manifest in loaded.items():
            source_kind = source_root / kind
            destination_kind = destination_root / kind
            destination_kind.mkdir(parents=True, exist_ok=True)

            manifest_target = destination_kind / "manifest.yaml"
            shutil.copy2(source_kind / "manifest.yaml", manifest_target)
            copied_targets.append(manifest_target)

            for sample in manifest["samples"]:
                source_sample = _safe_sample_path(
                    source_kind, sample["file"], sample["id"]
                )
                destination_sample = _safe_sample_path(
                    destination_kind, sample["file"], sample["id"]
                )
                destination_sample.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_sample, destination_sample)
                copied_targets.append(destination_sample)

        verified = validate_root(
            destination_root,
            require_kinds=require_kinds,
            require_files=True,
            public_mount=True,
        )
    except BaseException:
        cleanup(destination_root)
        raise
    return source_root, verified


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate private corpus data")
    validate.add_argument("--root", type=Path, required=True)
    validate.add_argument(
        "--require-kind",
        action="append",
        choices=KINDS,
        default=[],
        dest="require_kinds",
    )
    validate.add_argument(
        "--contract-only",
        action="store_true",
        help="validate manifests without requiring referenced DMP files",
    )
    validate.add_argument(
        "--public-mount",
        action="store_true",
        help="require the tracked tests/corpus README structure",
    )

    copy = subparsers.add_parser(
        "materialize", help="copy a validated private corpus into tests/corpus"
    )
    copy.add_argument("--source", type=Path, required=True)
    copy.add_argument("--destination", type=Path, required=True)
    copy.add_argument("--version")
    copy.add_argument(
        "--require-kind",
        action="append",
        choices=KINDS,
        default=[],
        dest="require_kinds",
    )

    remove = subparsers.add_parser(
        "cleanup", help="remove only ignored manifests and sample directories"
    )
    remove.add_argument("--root", type=Path, required=True)
    remove.add_argument(
        "--yes",
        action="store_true",
        help="confirm removal of materialized private corpus artifacts",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            loaded = validate_root(
                args.root,
                require_kinds=tuple(args.require_kinds),
                require_files=not args.contract_only,
                public_mount=args.public_mount,
            )
            sample_count = sum(len(manifest["samples"]) for manifest in loaded.values())
            print(
                f"Validated {sample_count} sample(s) across "
                f"{', '.join(sorted(loaded))} corpus."
            )
        elif args.command == "materialize":
            _, loaded = materialize(
                args.source,
                args.destination,
                version=args.version,
                require_kinds=tuple(args.require_kinds),
            )
            sample_count = sum(len(manifest["samples"]) for manifest in loaded.values())
            print(
                f"Materialized {sample_count} sample(s) across "
                f"{', '.join(sorted(loaded))} corpus."
            )
        else:
            if not args.yes:
                raise CorpusError("cleanup requires --yes")
            removed = cleanup(args.root)
            print(f"Removed {len(removed)} private corpus path(s).")
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
