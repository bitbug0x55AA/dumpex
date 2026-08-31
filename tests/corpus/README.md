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
4. Give it a stable, non-sensitive ID that does not contain a customer, case,
   host, or analyst name; this ID can appear in CI and JUnit output.
5. Record its SHA-256, source, authorization, capture metadata, and stable
   expected results.
6. For evil samples, derive `ground_truth.detected_hunts` from evidence
   independent of dumpex: a controlled technique, trusted sandbox telemetry,
   an authoritative challenge write-up, or manual reverse engineering.
7. Run the category manifest before promoting it into the private corpus.

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

## Targeted-rescan replay

A sample may additionally declare `expected.targeted_rescan`, which replays the
recovery workflow `--hunt-addr` exists for against that dump: the full-scope
hunt leaves an oversized target in the investigation queue, the queue
recommends a rescan by the named hunter, and that rescan runs over exactly that
target.

```yaml
expected:
  targeted_rescan:
    hunter: obfuscation
    coverage_status: partial          # optional
    require_applicability_reasons: true
    require_measurements:
      - bytes_evaluated
    min_measurements:                 # optional, keyed by targeted scope
      entropy:
        entropy_windows_above_threshold: 1
```

The rescan target is read off the queue, never off the manifest: pinning an
address here would test a different scan from the one the queue recommends, and
would keep passing if the queue stopped producing the entry at all.

What this asserts is that the rescan is **actionable and scope-honest**, not
that it detects anything. Finding nothing over the requested range is a valid
outcome; producing a result that explains nothing is not. So every closure that
reached the bytes must retain the named measurements, every closure that
declined the target must name the eligibility gate that declined it, and every
closure must identify the requested range rather than the containing
descriptor.

`min_measurements` is the stronger real-sample assertion: it requires the
named scope to emit a numeric measurement at or above the declared value. Use
it when the corpus sample is expected to exercise a specific observation, such
as at least one page-sized entropy window above threshold.

The machine-readable contract is
[`manifest-v2.schema.json`](manifest-v2.schema.json). The stricter
`scripts/corpus_manager.py` validation additionally checks unique IDs, safe
relative paths, SHA-256 content, category policy, and independent evil-sample
ground truth.

## Private corpus automation

`.github/workflows/corpus.yml` runs the corpus gates on a protected,
self-hosted Windows runner. It supports manual dispatch and a weekly schedule,
and refuses to execute from anything other than the repository's default
branch. It never executes submitted EXE files.

Because the canonical dumpex repository is public, the workflow also refuses
to schedule its runner job unless it is running from a private repository.
Run it only from a private automation mirror. Never register an ordinary
persistent self-hosted runner directly with the public repository.

Configure the GitHub environment and runner before enabling the workflow:

1. Create a protected GitHub environment named `malware-lab` and require
   reviewer approval for access.
2. Register an isolated runner with the labels `windows`, `x64`,
   `dumpex-corpus`, and `isolated`. Do not assign fork PR jobs to it.
3. Set the environment variable `DUMPEX_CORPUS_SOURCE` to a read-only private
   corpus directory accessible to that runner.
4. Optionally set `DUMPEX_CORPUS_VERSION`. When set, the workflow reads that
   named child directory below `DUMPEX_CORPUS_SOURCE`.

The private source has the same category layout as the ignored mount:

```text
private-corpus/
  2026.08.1/                 # optional version directory
    clean/
      manifest.yaml
      samples/*.dmp
    evil/
      manifest.yaml
      samples/*.dmp
```

The workflow currently requires the `evil` corpus because no clean DMP has
been promoted yet. Once at least one reviewed clean sample exists, add
`--require-kind clean` to the materialization step so both FP and FN coverage
are mandatory.

The manager validates the private source before copying only manifest-referenced
files into `tests/corpus`. It refuses stale destination data and removes the
materialized manifests and samples in an `always()` cleanup step:

```powershell
python scripts/corpus_manager.py validate `
  --root D:\private-corpus\2026.08.1 `
  --require-kind evil

python scripts/corpus_manager.py cleanup --root tests/corpus --yes

python scripts/corpus_manager.py materialize `
  --source D:\private-corpus `
  --version 2026.08.1 `
  --destination tests/corpus `
  --require-kind evil
```

CI uploads only JUnit assertions. Hunter console rendering is suppressed
during corpus tests because it may contain strings recovered from private
process memory.

## Evidence handling

Every entry must have truthful `source` and `authorization` fields. Preserve
the original artifact separately, hash every DMP, restrict corpus access, and
do not put either clean or malicious process memory in public CI artifacts.
