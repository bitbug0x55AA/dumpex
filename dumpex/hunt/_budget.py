"""Shared scan-resource budget.

A hunt module's per-region/per-signature caps (e.g. "≤200 decompress
attempts per signature per region") bound a single region in isolation, but
say nothing about the sum across an entire dump: a crafted or merely large
dump with many qualifying regions can still turn "≤200 per region" into an
unbounded amount of total work and retained memory. ScanBudget tracks
consumption across the WHOLE hunt call (all regions, all signatures) so a
single limit actually caps the worst case, not just each region's slice
of it.
"""
import time
import hashlib
from dataclasses import dataclass, field


@dataclass
class ScanBudget:
    max_bytes_read: int        # cumulative bytes of decoded/decompressed content produced
    max_attempts: int          # cumulative decode/decompress attempts, across all regions
    max_retained_bytes: int    # cumulative bytes of decoded content actually kept for reporting
    max_hits: int              # cumulative hits retained
    deadline: float = None     # optional time.monotonic() cutoff; None = no deadline

    _attempts: int = field(default=0, init=False, repr=False)
    _bytes_read: int = field(default=0, init=False, repr=False)
    _retained_bytes: int = field(default=0, init=False, repr=False)
    _hits: int = field(default=0, init=False, repr=False)
    _seen_hashes: set = field(default_factory=set, init=False, repr=False)
    exhausted_reason: str = field(default="", init=False)

    def exhausted(self) -> bool:
        return bool(self.exhausted_reason)

    def note_attempt(self) -> bool:
        """Call before spending one decode/decompress attempt. Returns
        False (and marks the budget exhausted) once the attempt budget or
        deadline is used up — the caller must stop trying further
        candidates immediately, not just for the current region."""
        if self.exhausted_reason:
            return False
        if self._attempts >= self.max_attempts:
            self.exhausted_reason = "max_attempts"
            return False
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.exhausted_reason = "deadline"
            return False
        self._attempts += 1
        return True

    def note_bytes_read(self, n: int):
        self._bytes_read += n
        if self._bytes_read >= self.max_bytes_read:
            self.exhausted_reason = self.exhausted_reason or "max_bytes_read"

    def note_retained(self, n: int) -> bool:
        """Call before actually keeping `n` bytes of decoded content in a
        findings structure. Returns False once the retained-bytes budget
        would be exceeded — caller should store a truncated preview
        instead of the full content."""
        if self._retained_bytes + n > self.max_retained_bytes:
            return False
        self._retained_bytes += n
        return True

    def note_hit(self) -> bool:
        if self._hits >= self.max_hits:
            self.exhausted_reason = self.exhausted_reason or "max_hits"
            return False
        self._hits += 1
        return True

    def seen_content(self, data: bytes) -> bool:
        """
        Cross-region content dedup: returns True (and registers the hash)
        the first time this exact decoded content is seen anywhere in the
        hunt, False on every repeat. Lets callers discard a duplicate
        immediately — before classifying it or retaining any bytes — rather
        than collecting every occurrence and deduplicating only at report
        time (by which point all the duplicates' full decoded bytes were
        already held in memory for the whole scan).
        """
        h = hashlib.sha256(data).digest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True
