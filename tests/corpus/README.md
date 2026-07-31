# Real-dump validation corpus

The default test suite builds synthetic PE headers and minidump object graphs.
This directory provides the optional second layer: validation against private,
analyst-authorized Windows process dumps captured from real software.

Real dumps are never committed. They may contain malware bytes, hostnames,
usernames, internal addresses, credentials, or other sensitive process memory.
Only the harness, documentation, and example manifests belong in Git.

## Layout

Clean and malicious evidence are managed independently:

```text
tests/corpus/
  clean/
    README.md
    manifest.example.yaml
    manifest.yaml            # ignored
    samples/                 # ignored
  evil/
    README.md
    manifest.example.yaml
    manifest.yaml            # ignored
    samples/                 # ignored
```

- `clean/` is the false-positive corpus. A clean sample fails the suite if any
  hunter returns `DETECTED`.
- `evil/` is the false-negative corpus. Each sample declares the hunters that
  independent ground truth says must return `DETECTED`.

Coverage and exact-result assertions remain separate from FP/FN policy.
`DETECTED` with partial coverage is still a true positive. `INCONCLUSIVE`,
`NOT_EVALUATED`, and `NOT_DETECTED_IN_SCANNED_SCOPE` all count as a miss when a
hunter is listed in `ground_truth.detected_hunts`.

## Running the corpus

Point `DUMPEX_CORPUS_MANIFEST` at one manifest:

```powershell
$env:DUMPEX_CORPUS_MANIFEST = "tests\corpus\evil\manifest.yaml"
pytest tests/integration/test_corpus.py -v
```

To run every private manifest currently present, point it at this directory:

```powershell
$env:DUMPEX_CORPUS_MANIFEST = "tests\corpus"
pytest tests/integration/test_corpus.py -v
```

Directory mode discovers `clean/manifest.yaml` and `evil/manifest.yaml`.
Without the environment variable, the module skips before reading any sample.

## Adding a sample

1. Decide whether the sample is a known-clean negative or malicious positive.
2. Copy the matching `manifest.example.yaml` to `manifest.yaml`.
3. Place the DMP under that category's ignored `samples/` directory.
4. Record its SHA-256, source, authorization, capture metadata, and stable
   expected results.
5. For evil samples, derive `ground_truth.detected_hunts` from evidence
   independent of dumpex: a controlled technique, trusted sandbox telemetry,
   an authoritative challenge write-up, or manual reverse engineering.
6. Run the category manifest before promoting it into the private corpus.

Do not generate expected results by copying the current dumpex output. That
would make the detector its own oracle and hide false negatives.

## Manifest policy

Version 2 manifests carry a category-level policy:

```yaml
version: 2
kind: clean  # or evil
policy:
  false_positive:
    max_detected_hunts: 0
```

or:

```yaml
version: 2
kind: evil
policy:
  false_negative:
    require_ground_truth_detection: true
```

The integration harness validates these policies before testing results. See
the category README and example manifest for the fields required on each
sample.

## Evidence handling

Every entry must have truthful `source` and `authorization` fields. Preserve
the original artifact separately, hash every DMP, restrict corpus access, and
do not put either clean or malicious process memory in public CI artifacts.
