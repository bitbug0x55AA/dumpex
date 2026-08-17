"""Evidence-file identity helpers for structured output metadata (--json)."""
import hashlib
import os

# 4 MiB — large enough to keep syscall overhead low, small enough that a
# multi-gigabyte minidump is never loaded into memory at once just to
# compute its hash.
_HASH_CHUNK_SIZE = 4 * 1024 * 1024


def sha256_file(path: str, chunk_size: int = _HASH_CHUNK_SIZE) -> str:
    """
    SHA-256 of a file's contents, read in bounded chunks. Deterministic
    over file bytes only (not path or mtime), so the same dump produces
    the same hash across different commands/invocations — the property
    that makes it usable as an evidence identifier.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# {(abspath, st_size, st_mtime_ns): sha256_hex} for the current process.
_SHA256_CACHE = {}


def cached_sha256_file(path: str) -> str:
    """
    sha256_file(path), computed at most once per process for a given file.

    Two independent consumers now want the same digest of the same dump in
    a single invocation: `--sysinfo`'s DUMP section (SysInfoRecord.
    dump_sha256) and `--json`'s meta.evidence entry. Hashing a
    multi-gigabyte minidump twice per run is pure waste, and it also lets
    the two reported values disagree if the file changed in between —
    which would be a genuinely confusing evidence artifact, not just a
    slow one.

    The cache key includes st_size/st_mtime_ns, so a file replaced or
    appended to mid-run is re-hashed rather than served a stale digest.
    Deliberately a wrapper rather than memoization applied to
    sha256_file() itself: that function stays a pure, cache-free primitive
    for callers that must observe the bytes as they are right now.

    Raises whatever os.stat()/open()/read() raise — callers decide how to
    report the failure (a coverage limitation for --sysinfo,
    meta.evidence's own "error" key for --json).
    """
    resolved = os.path.abspath(path)
    st = os.stat(resolved)
    key = (resolved, st.st_size, st.st_mtime_ns)
    digest = _SHA256_CACHE.get(key)
    if digest is None:
        digest = sha256_file(resolved)
        _SHA256_CACHE[key] = digest
    return digest
