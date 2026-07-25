"""Shared scan-resource budget.

A hunt module's per-region/per-signature caps (e.g. "≤200 decompress
attempts per signature per region") bound a single region in isolation, but
say nothing about the sum across an entire dump: a crafted or merely large
dump with many qualifying regions can still turn "≤200 per region" into an
unbounded amount of total work and retained memory. ScanBudget tracks
consumption across the WHOLE hunt call (all regions, all signatures) so a
single limit actually caps the worst case, not just each region's slice
of it.

Design note: registering a hit goes through take_hit() and ONLY take_hit()
— there is no separate "note" method whose boolean result a caller could
compute and then not act on. A prior version split hit-counting
(note_hit()) from retained-bytes accounting (note_retained()), and a caller
that checked one but not the other (or checked neither) could still append
an item after the budget was exhausted — e.g. max_hits=1 ended up retaining
2 results because the note_hit() return value was never inspected at the
call site. take_hit()'s return value is the ONLY signal a caller has for
whether an item was actually admitted, which makes that class of bug
impossible to reproduce: nothing else confirms the hit was accepted.
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
        """
        True once any limit — including the deadline — has been hit.

        The deadline is evaluated HERE, not only inside note_attempt():
        a caller that polls exhausted() directly in a loop that doesn't
        route every iteration through note_attempt() (e.g. the XOR
        key-scoring loop, which is cheap enough not to need a per-key
        attempt count) must still see an expired deadline as exhausted.
        Checking the deadline only inside note_attempt() meant a budget
        that had already timed out kept reporting exhausted()==False to
        any caller that hadn't just called note_attempt().
        """
        if not self.exhausted_reason and self.deadline is not None and time.monotonic() >= self.deadline:
            self.exhausted_reason = "deadline"
        return bool(self.exhausted_reason)

    def note_attempt(self) -> bool:
        """Call before spending one decode/decompress attempt. Returns
        False (and marks the budget exhausted) once the attempt budget or
        deadline is used up — the caller must stop trying further
        candidates immediately, not just for the current region."""
        if self.exhausted():
            return False
        if self._attempts >= self.max_attempts:
            self.exhausted_reason = "max_attempts"
            return False
        self._attempts += 1
        return True

    def note_bytes_read(self, n: int):
        """Track cumulative decode/decompress OUTPUT volume, regardless of
        whether any of it ends up retained — distinct from max_retained_bytes,
        which only counts bytes actually kept in a findings structure."""
        self._bytes_read += n
        if self._bytes_read >= self.max_bytes_read:
            self.exhausted_reason = self.exhausted_reason or "max_bytes_read"

    def take_hit(self, retained_bytes: int = 0) -> bool:
        """
        Atomically check-and-commit ONE hit: budget not exhausted, hit
        count under max_hits, AND (if retained_bytes > 0) the
        retained-bytes budget has room for it — all three or none. This is
        the only way to register a hit against the budget; callers MUST
        gate on the return value:

            if not budget.take_hit(len(item)):
                break
            hits.append(item)

        Once take_hit() returns False the budget is exhausted for the rest
        of the hunt (not just this call) — a caller should stop pulling
        further results from whatever it's iterating, not just skip this
        one item and keep going.
        """
        if self.exhausted():
            return False
        if self._hits >= self.max_hits:
            self.exhausted_reason = "max_hits"
            return False
        if retained_bytes and self._retained_bytes + retained_bytes > self.max_retained_bytes:
            self.exhausted_reason = "max_retained_bytes"
            return False
        self._hits += 1
        if retained_bytes:
            self._retained_bytes += retained_bytes
        return True

    def poll(self) -> bool:
        """
        Cheap periodic check for long-running loops that don't otherwise
        touch the budget every iteration (e.g. XOR brute force scoring 255
        keys against a fixed sample) — returns False once exhausted
        (including by an expired deadline), so the loop can bail out
        promptly instead of running to completion after the budget expired.
        """
        return not self.exhausted()

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
