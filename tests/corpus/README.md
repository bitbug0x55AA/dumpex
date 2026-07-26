# Real-dump validation corpus

Every test elsewhere in this repo builds its own synthetic PE header /
minidump object graph (see `tests/fixtures/fakes.py`) — that's deliberate,
so `pytest` from a bare checkout needs no external fixtures, network
access, or malware corpus (see `tests/conftest.py`). It also means the
whole suite has never been validated against a **real** Windows minidump,
synthetic or malicious, captured by a real tool against a real process.

This directory is the harness for that second, optional layer of
validation. It is **not** wired into the default `pytest` run and adds no
dependency to the base dev install — `tests/integration/test_corpus.py`
skips itself entirely unless a manifest is explicitly configured.

## Why this isn't just committed to the repo

A real corpus needs, at minimum:

- **Clean** baseline dumps (ordinary processes, no injection/hollowing/
  beacon activity) — to catch false positives.
- **Malicious** dumps (real injection, stomping, C2 pipes, or a real
  Cobalt Strike / other framework beacon) — to catch false negatives.
- **Missing-stream** dumps (captured without `MiniDumpWithHandleData`,
  without `MiniDumpWithFullMemory`, etc.) — to validate the
  coverage/INCONCLUSIVE machinery against dumps that are genuinely
  incomplete, not just synthetically constructed to look that way.
- **Corrupted / truncated** dumps — to validate `open_dump()`'s failure
  handling (see `tests/unit/test_open_dump.py` for the synthetic version
  of this) against whatever a real truncated capture actually looks like.
- **Short-read** dumps — a real dump where the underlying capture tool
  legitimately returned less than a declared region/segment size.

A malicious sample is, definitionally, live or previously-live malware.
Committing it to a public (or even a shared internal) git history is a
liability regardless of how it's licensed, and clean/malicious captures
from a real environment can carry hostnames, usernames, internal IPs, and
other case-sensitive material that has no business in version control.
This directory is therefore just the **shape** (manifest schema,
harness, documentation) — the actual `manifest.yaml` and `samples/`
directory are `.gitignore`d and live outside this repo (a private corpus
repo, an internal file share, a case evidence store — wherever your
org's authorized-sample handling policy says they belong).

## Setting it up

1. Assemble your own private sample set under a directory of your choosing
   (referred to below as `$CORPUS_DIR`), organized however you like —
   the manifest's `file` field is a path relative to the manifest itself.
2. Copy `manifest.example.yaml` to `$CORPUS_DIR/manifest.yaml` and fill in
   one entry per sample: `sha256` (see below), `category`, `source`,
   `authorization`, `capture` params, and `expected` results.
3. Compute each sample's sha256 and paste it into the manifest —
   `sha256sum sample.dmp` or `python3 -c "import hashlib,sys;
   print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"
   sample.dmp`. The test harness verifies this against the actual file
   on every run — a stale/substituted sample fails loudly instead of
   silently validating against the wrong bytes.
4. Point the harness at it:
   ```
   export DUMPEX_CORPUS_MANIFEST=$CORPUS_DIR/manifest.yaml
   pytest tests/integration/test_corpus.py -v
   ```
   Without that environment variable set, `test_corpus.py` is skipped —
   it never runs by accident, and CI (which has no access to any private
   corpus) always skips it too.

## Authorization

Every entry's `source` and `authorization` fields exist because a
malicious sample must have a clear, written chain of custody: where it
came from, under what engagement/case, and what authorizes analyzing and
storing it. Don't add a sample you can't fill those in for truthfully.
See `manifest.example.yaml` for the exact fields and an example of each
of the five minimum categories above.
