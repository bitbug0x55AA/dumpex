import hashlib
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from scripts import corpus_manager


HUNTS = ("injection", "hollowing", "stomping", "pipe", "cs-beacon", "yara", "obfuscation")


def _public_mount(root: Path):
    root.mkdir(parents=True)
    (root / "README.md").write_text("corpus mount", encoding="utf-8")
    for kind in ("clean", "evil"):
        category = root / kind
        category.mkdir(parents=True)
        (category / "README.md").write_text(kind, encoding="utf-8")


def _sample(kind: str, data: bytes, *, sample_id: str | None = None):
    record = {
        "id": sample_id or f"{kind}_sample",
        "file": f"samples/{kind}.dmp",
        "sha256": hashlib.sha256(data).hexdigest(),
        "category": "clean" if kind == "clean" else "malicious",
        "source": "controlled test fixture",
        "authorization": "unit-test data",
        "expected": {"hunt": {"injection": {"min_score": 0}}},
    }
    if kind == "evil":
        record["ground_truth"] = {
            "detected_hunts": ["injection"],
            "basis": "controlled unit-test ground truth",
        }
    return record


def _write_private_kind(
    root: Path,
    kind: str,
    *,
    data: bytes = b"not a real dump",
    sample_id: str | None = None,
):
    category = root / kind
    sample = _sample(kind, data, sample_id=sample_id)
    sample_path = category / sample["file"]
    sample_path.parent.mkdir(parents=True, exist_ok=True)
    sample_path.write_bytes(data)
    policy = (
        {"false_positive": {"max_detected_hunts": 0}}
        if kind == "clean"
        else {"false_negative": {"require_ground_truth_detection": True}}
    )
    manifest = {
        "version": 2,
        "kind": kind,
        "policy": policy,
        "samples": [sample],
    }
    (category / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    return manifest


def test_tracked_example_manifests_satisfy_json_schema_and_contract():
    corpus_root = Path(__file__).parents[1] / "corpus"
    schema = json.loads(
        (corpus_root / "manifest-v2.schema.json").read_text(encoding="utf-8")
    )
    for kind in ("clean", "evil"):
        path = corpus_root / kind / "manifest.example.yaml"
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
        jsonschema.validate(manifest, schema)
        corpus_manager.validate_manifest(
            path,
            expected_kind=kind,
            require_files=False,
        )


def test_materialize_validates_hashes_copies_only_references_and_cleans_up(tmp_path):
    source = tmp_path / "private"
    destination = tmp_path / "public"
    _public_mount(destination)
    _write_private_kind(source, "clean", data=b"clean")
    _write_private_kind(source, "evil", data=b"evil")
    unrelated = source / "evil" / "samples" / "not-in-manifest.dmp"
    unrelated.write_bytes(b"must not be copied")

    _, loaded = corpus_manager.materialize(
        source,
        destination,
        require_kinds=("clean", "evil"),
    )

    assert set(loaded) == {"clean", "evil"}
    assert (destination / "clean" / "samples" / "clean.dmp").read_bytes() == b"clean"
    assert (destination / "evil" / "samples" / "evil.dmp").read_bytes() == b"evil"
    assert not (destination / "evil" / "samples" / unrelated.name).exists()
    assert (destination / "clean" / "README.md").is_file()

    removed = corpus_manager.cleanup(destination)
    assert len(removed) == 4
    assert (destination / "README.md").is_file()
    assert (destination / "evil" / "README.md").is_file()
    assert not (destination / "evil" / "manifest.yaml").exists()
    assert not (destination / "evil" / "samples").exists()


def test_validate_rejects_hash_drift(tmp_path):
    _write_private_kind(tmp_path, "evil", data=b"original")
    (tmp_path / "evil" / "samples" / "evil.dmp").write_bytes(b"substituted")

    with pytest.raises(corpus_manager.CorpusError, match="sha256 mismatch"):
        corpus_manager.validate_root(tmp_path, require_kinds=("evil",))


def test_validate_rejects_weakened_clean_fp_policy(tmp_path):
    manifest = _write_private_kind(tmp_path, "clean")
    manifest["policy"]["false_positive"]["max_detected_hunts"] = 1
    (tmp_path / "clean" / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(corpus_manager.CorpusError, match="max_detected_hunts: 0"):
        corpus_manager.validate_root(tmp_path)


def test_validate_rejects_evil_without_independent_ground_truth(tmp_path):
    manifest = _write_private_kind(tmp_path, "evil")
    manifest["samples"][0].pop("ground_truth")
    (tmp_path / "evil" / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(corpus_manager.CorpusError, match="ground_truth mapping"):
        corpus_manager.validate_root(tmp_path)


@pytest.mark.parametrize(
    "unsafe_path",
    ("../outside.dmp", "samples/../../outside.dmp", "C:/outside.dmp"),
)
def test_validate_rejects_sample_path_escape(tmp_path, unsafe_path):
    manifest = _write_private_kind(tmp_path, "evil")
    manifest["samples"][0]["file"] = unsafe_path
    (tmp_path / "evil" / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(corpus_manager.CorpusError, match="sample path|samples/"):
        corpus_manager.validate_root(tmp_path)


def test_validate_rejects_duplicate_ids_across_clean_and_evil(tmp_path):
    _write_private_kind(tmp_path, "clean", sample_id="duplicate")
    _write_private_kind(tmp_path, "evil", sample_id="duplicate")

    with pytest.raises(corpus_manager.CorpusError, match="duplicate sample ids"):
        corpus_manager.validate_root(tmp_path)


def test_cleanup_requires_tracked_mount_shape(tmp_path):
    with pytest.raises(corpus_manager.CorpusError, match="missing"):
        corpus_manager.cleanup(tmp_path)


def test_all_hunter_names_stay_aligned_with_corpus_contract():
    assert corpus_manager.HUNTERS == set(HUNTS)


def test_private_corpus_workflow_cannot_schedule_runner_from_public_repo():
    workflow = (
        Path(__file__).parents[2] / ".github" / "workflows" / "corpus.yml"
    ).read_text(encoding="utf-8")
    assert "if: github.event.repository.private == true" in workflow
    assert "pull_request:" not in workflow
    assert "pull_request_target:" not in workflow
