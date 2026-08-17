"""Unit tests for dumpex.core.evidence's file-identity helpers.

`cached_sha256_file()` was added when --sysinfo grew a DUMP section that
reports the dump's own SHA-256 (contract §4.2). That digest and
--json's meta.evidence[].sha256 are now two consumers of the same fact
about the same file in one invocation, so the interesting properties are
not "does SHA-256 work" (hashlib's job) but the two this wrapper exists
for: one read per file per run, and no stale digest when the file
underneath actually changed.
"""
import hashlib

import pytest

from dumpex.core import evidence
from dumpex.core.evidence import cached_sha256_file, sha256_file


@pytest.fixture(autouse=True)
def _clear_cache():
    evidence._SHA256_CACHE.clear()
    yield
    evidence._SHA256_CACHE.clear()


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_sha256_file_matches_hashlib_over_the_same_bytes(tmp_path):
    data = b"\x00\xff" * 5000
    assert sha256_file(_write(tmp_path, "a.dmp", data)) == hashlib.sha256(data).hexdigest()


def test_sha256_file_chunking_does_not_change_the_digest(tmp_path):
    # A multi-gigabyte dump is hashed in chunks; the digest must not
    # depend on where the chunk boundaries fall.
    data = bytes(range(256)) * 40
    path = _write(tmp_path, "b.dmp", data)
    expected = hashlib.sha256(data).hexdigest()
    assert sha256_file(path, chunk_size=1) == expected
    assert sha256_file(path, chunk_size=7) == expected
    assert sha256_file(path, chunk_size=1 << 20) == expected


def test_cached_sha256_file_reads_the_file_only_once(tmp_path, monkeypatch):
    data = b"cache me"
    path = _write(tmp_path, "c.dmp", data)
    calls = []
    real = evidence.sha256_file
    monkeypatch.setattr(evidence, "sha256_file",
                         lambda p, *a, **k: (calls.append(p), real(p, *a, **k))[1])

    first = cached_sha256_file(path)
    second = cached_sha256_file(path)
    assert first == second == hashlib.sha256(data).hexdigest()
    assert len(calls) == 1, "a second consumer must not re-read a multi-gigabyte dump"


def test_cached_sha256_file_normalizes_the_path_before_caching(tmp_path, monkeypatch):
    # --sysinfo passes mf.filename (whatever was on argv) and meta.evidence
    # passes an already-absolute path. Both must hit the same cache entry,
    # or the dedup silently does nothing in the exact case it exists for.
    path = _write(tmp_path, "d.dmp", b"same file")
    calls = []
    real = evidence.sha256_file
    monkeypatch.setattr(evidence, "sha256_file",
                         lambda p, *a, **k: (calls.append(p), real(p, *a, **k))[1])

    monkeypatch.chdir(tmp_path)
    assert cached_sha256_file("d.dmp") == cached_sha256_file(path)
    assert len(calls) == 1


def test_cached_sha256_file_rehashes_when_the_file_actually_changed(tmp_path):
    # The cache must never outlive the bytes it describes: a stale digest
    # reported as an evidence identifier is worse than a slow one.
    path = _write(tmp_path, "e.dmp", b"before")
    assert cached_sha256_file(path) == hashlib.sha256(b"before").hexdigest()

    import os
    _write(tmp_path, "e.dmp", b"after this")
    os.utime(path, ns=(0, 0))   # force a distinct mtime, not just a distinct size
    assert cached_sha256_file(path) == hashlib.sha256(b"after this").hexdigest()


def test_cached_sha256_file_propagates_a_missing_file(tmp_path):
    # Callers decide how to report it (--sysinfo turns it into
    # SYSINFO_DUMP_FILE_UNREADABLE), so the helper must not swallow it
    # into a sentinel digest.
    with pytest.raises(OSError):
        cached_sha256_file(str(tmp_path / "nope.dmp"))
