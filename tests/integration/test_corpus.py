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
from dumpex.core.va_range import VirtualRange
from dumpex.hunt import cmd_hunt, execute_targeted
from dumpex.hunt._registry import REGISTRY
from dumpex.hunt._request import HuntRequest
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


# ── oversized queue entry -> originating targeted rescan ───────────────
#
# The workflow `--hunt-addr` exists for, replayed end to end against a real
# dump: a full-scope hunt skips an oversized target, the investigation queue
# recommends a hunter-specific rescan of exactly that target, and the rescan is
# run over it. What is asserted is that the rescan is ACTIONABLE and
# scope-honest -- it explains what each closure did with the bytes, names the
# gate behind any closure that declined them, and claims completeness for the
# granted source only. A rescan that finds nothing is a valid outcome; one that
# explains nothing is the under-informative result this replay exists to catch.

_TARGETED_RESCAN_SAMPLES = [
    sample for sample in _SAMPLES
    if sample.get("expected", {}).get("targeted_rescan")
]


def _queued_rescan_target(sample_id, hunter):
    """The queue's own oversized entry recommending a rescan by ``hunter``, as
    ``(base_address, size)``.

    Read off the investigation queue rather than the manifest: pinning an
    address in the manifest would make the replay test a different scan from
    the one the queue actually recommends, and would silently keep passing if
    the queue stopped producing the entry at all."""
    _results, _records, actions, _provenance = _all_hunt_records(sample_id)
    for action in actions:
        recommends = any(hunter in recommendation.hunters
                         for recommendation in action.recommended_actions)
        oversized = any(relationship.cause == "oversized_skipped"
                        and relationship.hunter == hunter
                        for relationship in action.skipped_by)
        if recommends and oversized:
            return action.target.base_address, action.target.size
    return None


@lru_cache(maxsize=None)
def _all_hunt_records(sample_id):
    sample = _SAMPLE_BY_ID[sample_id]
    mf = open_dump(_sample_path(sample))
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        return cmd_hunt(mf, "all", verbose=False, collect_records=True)


@pytest.mark.parametrize("sample", _TARGETED_RESCAN_SAMPLES,
                         ids=_sample_ids(_TARGETED_RESCAN_SAMPLES))
def test_an_oversized_queue_entry_rescans_into_an_actionable_result(sample):
    assertion = sample["expected"]["targeted_rescan"]
    hunter = assertion["hunter"]
    assert hunter in _HUNTERS, f"{sample['id']}: unknown rescan hunter {hunter!r}"

    queued = _queued_rescan_target(sample["id"], hunter)
    assert queued is not None, (
        f"{sample['id']}: the full-scope hunt left no oversized {hunter} target in the "
        f"investigation queue, so there is no rescan for this sample to originate -- "
        f"either the sample changed or the queue stopped producing the entry"
    )
    base_address, size = queued

    source = REGISTRY.targeted_source(hunter)
    request = HuntRequest.targeted(
        hunter, source, VirtualRange(base_address=base_address, size=size),
        scopes=REGISTRY.granted_scopes(hunter, source))
    mf = open_dump(_sample_path(sample))
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        execution = execute_targeted(mf, request)
    record = execution.result.records[0]
    scopes = record.details.targeted_scope

    if "coverage_status" in assertion:
        assert record.coverage.status.value == assertion["coverage_status"], (
            f"{sample['id']}: expected rescan coverage_status "
            f"{assertion['coverage_status']!r}, got {record.coverage.status.value!r}"
        )

    # Scope honesty: the rescan speaks for the range it was given and for the
    # granted source only, and every closure identifies that exact range.
    for entry in scopes:
        assert entry.source == source
        assert int(entry.base_address, 16) == base_address
        assert entry.size == size

    if assertion.get("require_applicability_reasons", True):
        for entry in scopes:
            if entry.coverage_status == "not_applicable":
                assert entry.applicability_reason, (
                    f"{sample['id']}/{entry.scope}: a closure that declined the target "
                    f"must name the eligibility gate that declined it"
                )
            else:
                assert entry.applicability_reason is None

    # Actionability: a closure that reached the bytes says what it did with
    # them, whether or not it found anything.
    required = set(assertion.get("require_measurements", ["bytes_evaluated"]))
    for entry in scopes:
        if entry.coverage_status in ("not_applicable", "not_evaluated"):
            continue
        measured = {measurement.name for measurement in entry.measurements}
        missing = required - measured
        assert not missing, (
            f"{sample['id']}/{entry.scope}: a {entry.coverage_status} closure retained no "
            f"{sorted(missing)} -- the result states a conclusion without stating what "
            f"was measured to reach it"
        )

    # A real sample can pin a minimum observed value, not just the existence of
    # a measurement name. This catches regressions where the targeted pass runs
    # and explains itself but still misses the payload the sample exists to
    # exercise (for example a page-local entropy peak).
    entries_by_scope = {entry.scope: entry for entry in scopes}
    for scope, minimums in assertion.get("min_measurements", {}).items():
        assert scope in entries_by_scope, (
            f"{sample['id']}: expected targeted scope {scope!r} is not present"
        )
        entry = entries_by_scope[scope]
        for name, minimum in minimums.items():
            values = [
                measurement.value for measurement in entry.measurements
                if measurement.name == name
                and isinstance(measurement.value, (int, float))
                and not isinstance(measurement.value, bool)
            ]
            assert values, (
                f"{sample['id']}/{scope}: expected numeric measurement {name!r}"
            )
            assert max(values) >= minimum, (
                f"{sample['id']}/{scope}: expected {name} >= {minimum}, got {values}"
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
