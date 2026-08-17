"""
Opt-in validation against private real-dump corpora.

``DUMPEX_CORPUS_MANIFEST`` may point to one manifest or to ``tests/corpus``;
directory mode discovers ``clean/manifest.yaml`` and ``evil/manifest.yaml``.
The default suite still has no corpus or network dependency.
"""
from contextlib import redirect_stderr, redirect_stdout
from functools import lru_cache
import hashlib
import io
import os

import pytest

from dumpex.core.memory import open_dump
from dumpex.hunt import cmd_hunt
from dumpex.output.records import HUNTERS


_CONFIG_PATH = os.environ.get("DUMPEX_CORPUS_MANIFEST")
# Not a local copy of the seven names: a manifest naming a hunter this
# build does not have must be rejected against the roster the build
# actually runs, not against a list that drifts with it.
_HUNTERS = set(HUNTERS)


def _discover_manifests(config_path):
    if not config_path:
        return []
    absolute = os.path.abspath(config_path)
    if os.path.isfile(absolute):
        return [absolute]
    if os.path.isdir(absolute):
        return [
            path
            for kind in ("clean", "evil")
            if os.path.isfile(path := os.path.join(absolute, kind, "manifest.yaml"))
        ]
    return []


_MANIFEST_PATHS = _discover_manifests(_CONFIG_PATH)
if not _MANIFEST_PATHS:
    pytest.skip(
        "no real-dump corpus configured -- set DUMPEX_CORPUS_MANIFEST to a "
        "manifest file or tests/corpus directory",
        allow_module_level=True,
    )

yaml = pytest.importorskip("yaml")

_MANIFESTS = []
_SAMPLES = []
for manifest_path in _MANIFEST_PATHS:
    with open(manifest_path, encoding="utf-8") as fh:
        manifest = yaml.safe_load(fh) or {}
    manifest["_path"] = manifest_path
    manifest["_dir"] = os.path.dirname(manifest_path)
    _MANIFESTS.append(manifest)
    for sample in manifest.get("samples", []):
        record = dict(sample)
        record["_manifest_path"] = manifest_path
        record["_manifest_dir"] = manifest["_dir"]
        record["_kind"] = manifest.get("kind")
        record["_policy"] = manifest.get("policy", {})
        _SAMPLES.append(record)

_SAMPLE_BY_ID = {sample.get("id"): sample for sample in _SAMPLES}


def _sample_ids(samples=None):
    if samples is None:
        samples = _SAMPLES
    return [sample.get("id", "?") for sample in samples]


def _sample_path(sample):
    return os.path.join(sample["_manifest_dir"], sample["file"])


@lru_cache(maxsize=None)
def _all_hunt_results(sample_id):
    sample = _SAMPLE_BY_ID[sample_id]
    mf = open_dump(_sample_path(sample))
    # Hunt renderers can include strings recovered from process memory.
    # Corpus CI publishes only assertion failures and JUnit metadata, never
    # raw hunter console output from private dumps.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return cmd_hunt(mf, "all", verbose=False)


def test_manifest_versions_and_fp_fn_policies():
    for manifest in _MANIFESTS:
        path = manifest["_path"]
        assert manifest.get("version") == 2, f"{path}: manifest version must be 2"
        kind = manifest.get("kind")
        assert kind in {"clean", "evil"}, f"{path}: kind must be clean or evil"

        policy = manifest.get("policy", {})
        if kind == "clean":
            assert policy.get("false_positive", {}).get("max_detected_hunts") == 0, (
                f"{path}: clean corpus must enforce "
                "policy.false_positive.max_detected_hunts: 0"
            )
        else:
            assert policy.get("false_negative", {}).get(
                "require_ground_truth_detection"
            ) is True, (
                f"{path}: evil corpus must enforce "
                "policy.false_negative.require_ground_truth_detection: true"
            )


def test_manifest_entries_have_required_fields_and_unique_ids():
    ids = []
    for sample in _SAMPLES:
        for field in ("id", "file", "sha256", "category", "source", "authorization"):
            assert sample.get(field), (
                f"sample {sample.get('id', '?')!r} missing required field {field!r}"
            )
        ids.append(sample["id"])

        if sample["_kind"] == "clean":
            assert sample["category"] == "clean", (
                f"clean corpus sample {sample['id']!r} must use category: clean"
            )
        else:
            detected_hunts = sample.get("ground_truth", {}).get("detected_hunts")
            assert detected_hunts, (
                f"evil corpus sample {sample['id']!r} must declare "
                "ground_truth.detected_hunts"
            )
            unknown = set(detected_hunts) - _HUNTERS
            assert not unknown, (
                f"sample {sample['id']!r} has unknown ground-truth hunters: "
                f"{sorted(unknown)}"
            )
            assert sample.get("ground_truth", {}).get("basis"), (
                f"evil corpus sample {sample['id']!r} must document "
                "ground_truth.basis"
            )

    duplicates = sorted({sample_id for sample_id in ids if ids.count(sample_id) > 1})
    assert not duplicates, f"duplicate corpus sample ids: {duplicates}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_ids())
def test_sample_file_matches_manifest_sha256(sample):
    path = _sample_path(sample)
    assert os.path.isfile(path), f"sample file not found: {path}"

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    expected = sample["sha256"].lower()
    assert actual == expected, (
        f"sample {sample['id']!r} content does not match its manifest sha256 "
        f"-- corpus drift or substitution (expected {expected}, got {actual})"
    )


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_ids())
def test_sample_matches_expected_results(sample):
    expected = sample.get("expected", {})

    if expected.get("open_dump_fails"):
        with pytest.raises(SystemExit):
            open_dump(_sample_path(sample))
        return

    results = _all_hunt_results(sample["id"])
    for ttp, assertion in expected.get("hunt", {}).items():
        assert ttp in _HUNTERS, f"{sample['id']}: unknown expected hunter {ttp!r}"
        result = results[ttp]
        if "status" in assertion:
            assert result.get("status") == assertion["status"], (
                f"{sample['id']}/{ttp}: expected status {assertion['status']!r}, "
                f"got {result.get('status')!r}"
            )
        if "coverage_status" in assertion:
            assert result.get("coverage_status") == assertion["coverage_status"], (
                f"{sample['id']}/{ttp}: expected coverage_status "
                f"{assertion['coverage_status']!r}, "
                f"got {result.get('coverage_status')!r}"
            )
        if "min_score" in assertion:
            assert result.get("score", 0) >= assertion["min_score"], (
                f"{sample['id']}/{ttp}: expected score >= "
                f"{assertion['min_score']}, got {result.get('score')}"
            )


_CLEAN_SAMPLES = [sample for sample in _SAMPLES if sample["_kind"] == "clean"]


@pytest.mark.parametrize("sample", _CLEAN_SAMPLES, ids=_sample_ids(_CLEAN_SAMPLES))
def test_clean_sample_has_zero_false_positives(sample):
    """FP = any DETECTED hunter on a sample independently known to be clean."""
    results = _all_hunt_results(sample["id"])
    detected = sorted(
        ttp for ttp, result in results.items() if result.get("status") == "DETECTED"
    )
    assert not detected, (
        f"{sample['id']}: false positive(s) on clean sample: {detected}"
    )


_EVIL_GROUND_TRUTH = [
    (sample, ttp)
    for sample in _SAMPLES
    if sample["_kind"] == "evil"
    for ttp in sample.get("ground_truth", {}).get("detected_hunts", [])
]


@pytest.mark.parametrize(
    "sample,ttp",
    _EVIL_GROUND_TRUTH,
    ids=[f"{sample['id']}/{ttp}" for sample, ttp in _EVIL_GROUND_TRUTH],
)
def test_evil_ground_truth_has_zero_false_negatives(sample, ttp):
    """FN = a ground-truth hunter returning anything other than DETECTED."""
    result = _all_hunt_results(sample["id"])[ttp]
    assert result.get("status") == "DETECTED", (
        f"{sample['id']}/{ttp}: false negative -- ground truth requires "
        f"DETECTED, got {result.get('status')!r} "
        f"(coverage={result.get('coverage_status')!r}, score={result.get('score')!r})"
    )
