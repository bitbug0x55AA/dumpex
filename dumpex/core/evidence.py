"""Evidence-file identity helpers for structured output metadata (--json/--csv)."""
import hashlib

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
