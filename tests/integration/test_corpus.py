"""
Real-dump validation harness. Runs dumpex's hunters against an external,
private corpus of real minidumps -- clean, malicious, missing-stream,
corrupted, and short-read samples -- verified against a manifest, rather
than the synthetic object graphs every other test in this repo builds
(see tests/fixtures/fakes.py).

Entirely opt-in: skipped unless DUMPEX_CORPUS_MANIFEST points at a real
manifest file. No sample data, and no manifest with real hashes, lives in
this repo -- see tests/corpus/README.md for why and how to set one up.
CI has no access to any private corpus, so this always skips there too.
"""
import hashlib
import os

import pytest

from dumpex.core.memory import open_dump
from dumpex.hunt import cmd_hunt

_MANIFEST_PATH = os.environ.get("DUMPEX_CORPUS_MANIFEST")

if not _MANIFEST_PATH or not os.path.isfile(_MANIFEST_PATH):
    pytest.skip(
        "no real-dump corpus configured -- set DUMPEX_CORPUS_MANIFEST to a "
        "manifest.yaml (see tests/corpus/README.md) to run this suite",
        allow_module_level=True,
    )

yaml = pytest.importorskip("yaml")

with open(_MANIFEST_PATH, encoding="utf-8") as fh:
    _MANIFEST = yaml.safe_load(fh)

_MANIFEST_DIR = os.path.dirname(os.path.abspath(_MANIFEST_PATH))
_SAMPLES = _MANIFEST.get("samples", [])

_REQUIRED_CATEGORIES = {"clean", "malicious", "missing_stream", "corrupted", "short_read"}


def _sample_ids():
    return [s["id"] for s in _SAMPLES]


def test_manifest_covers_all_required_categories():
    present = {s["category"] for s in _SAMPLES}
    missing = _REQUIRED_CATEGORIES - present
    assert not missing, (
        f"corpus manifest is missing at least one sample in each required "
        f"category: {sorted(missing)}"
    )


def test_manifest_entries_have_required_fields():
    for s in _SAMPLES:
        for field in ("id", "file", "sha256", "category", "source", "authorization"):
            assert s.get(field), f"sample {s.get('id', '?')!r} missing required field {field!r}"
        assert s["category"] in _REQUIRED_CATEGORIES, \
            f"sample {s['id']!r} has unrecognized category {s['category']!r}"


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_ids())
def test_sample_file_matches_manifest_sha256(sample):
    path = os.path.join(_MANIFEST_DIR, sample["file"])
    assert os.path.isfile(path), f"sample file not found: {path}"

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    actual = h.hexdigest()
    expected = sample["sha256"].lower()
    assert actual == expected, (
        f"sample {sample['id']!r} content does not match its manifest sha256 "
        f"-- corpus drift or a substituted file (expected {expected}, got {actual})"
    )


@pytest.mark.parametrize("sample", _SAMPLES, ids=_sample_ids())
def test_sample_matches_expected_verdict(sample):
    path = os.path.join(_MANIFEST_DIR, sample["file"])
    expected = sample.get("expected", {})

    if expected.get("open_dump_fails"):
        with pytest.raises(SystemExit):
            open_dump(path)
        return

    mf = open_dump(path)
    for ttp, exp in expected.get("hunt", {}).items():
        result = cmd_hunt(mf, ttp, verbose=False)[ttp]
        if "status" in exp:
            assert result.get("status") == exp["status"], (
                f"{sample['id']}/{ttp}: expected status {exp['status']!r}, "
                f"got {result.get('status')!r}"
            )
        if "coverage_status" in exp:
            assert result.get("coverage_status") == exp["coverage_status"], (
                f"{sample['id']}/{ttp}: expected coverage_status "
                f"{exp['coverage_status']!r}, got {result.get('coverage_status')!r}"
            )
        if "min_score" in exp:
            assert result.get("score", 0) >= exp["min_score"], (
                f"{sample['id']}/{ttp}: expected score >= {exp['min_score']}, "
                f"got {result.get('score')}"
            )
