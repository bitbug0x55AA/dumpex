"""
Layers 2-4 of dumpex.hunt.encoding — Base64, single-byte XOR brute-force,
and GZIP/ZLIB decompression.

`scan_decode_layers` is the entry point _hunt_encoding calls: it owns the
per-region read loop (one shared read + coverage pass feeds all three
sub-layers, since they all need the same region bytes) and returns a
DecodeResult of standardized Hit objects. `_scan_base64`/`_scan_xor`/
`_scan_compressed` below it are lower-level generators over an
already-read `data: bytes` buffer -- kept as their own testable units
(existing unit tests call them directly), yielding raw tuples rather
than Hit objects; `scan_decode_layers` is what converts each yield into
a Hit and applies the budget's take_hit() gate.
"""
import re
import zlib

from dumpex.core.memory import addr_to_module, prot_str
from dumpex.hunt._budget import ScanBudget
from dumpex.hunt._coverage import CoverageTracker, region_scan_target
from dumpex.hunt.encoding.classification import _IOC_PAT, _classify_decoded
from dumpex.hunt.encoding.config import (
    EncodingConfig, B64_MIN_LEN, XOR_SCAN_MAX, XOR_SAMPLE_SIZE, XOR_SCORE_MIN,
    DECOMPRESS_MAX_OUTPUT, DECODE_SCAN_MAX,
)
from dumpex.hunt.encoding.models import DecodeResult, Hit

_B64_PAT = re.compile(
    rb'(?:[A-Za-z0-9+/]{4}){12,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
    rb'|(?:[A-Za-z0-9\-_]{4}){12,}(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?'
)

_GZIP_SIG  = b'\x1f\x8b'
_ZLIB_SIGS = (b'\x78\x9c', b'\x78\xda', b'\x78\x01', b'\x78\x5e')


def _is_system_dll(module) -> bool:
    """True if module is a Microsoft system DLL under System32/SysWOW64/WinSxS."""
    if module is None:
        return False
    path = (module.name or "").replace("\\", "/").lower()
    return (
        "/windows/system32/"  in path or
        "/windows/syswow64/" in path or
        "/windows/winsxs/"   in path
    )


# ══════════════════════════════════════════════════════════════════════════
# LAYER 2 — Base64
# ══════════════════════════════════════════════════════════════════════════

def _scan_base64(data: bytes, region_base: int, budget: ScanBudget, config: EncodingConfig = None):
    """
    Yields (offset, raw, decoded, cls) candidates. Bounds decode ATTEMPTS
    (note_attempt) and skips exact-duplicate content (seen_content) here,
    since those are properties of the candidate itself — but does NOT
    decide whether to keep/retain a candidate: that's the consumer's call
    via budget.take_hit(), the single point where hit-count and
    retained-bytes limits are enforced together (see _budget.py).
    """
    b64_min_len = config.b64_min_len if config is not None else B64_MIN_LEN
    for m in _B64_PAT.finditer(data):
        if budget.exhausted():
            return
        raw = m.group(0)
        if len(raw) < b64_min_len:
            continue
        if not budget.note_attempt():
            return
        try:
            normalised = raw.replace(b'-', b'+').replace(b'_', b'/')
            pad = len(normalised) % 4
            if pad:
                normalised += b'=' * (4 - pad)
            decoded = __import__('base64').b64decode(normalised)
        except Exception:
            continue
        if len(decoded) < 16:
            continue
        if not budget.seen_content(decoded):
            continue   # identical payload already seen elsewhere in this hunt
        cls = _classify_decoded(decoded)
        if cls['type'] == 'binary' and not cls['ioc_strings']:
            continue
        budget.note_bytes_read(len(decoded))
        yield m.start(), raw, decoded, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 3 — Single-byte XOR brute-force
# ══════════════════════════════════════════════════════════════════════════

# Precomputed ONCE at import time, not per call: table[b] == 1 if byte
# value b is printable ASCII (or tab/LF/CR), else 0. _XOR_DECODE_TABLES /
# _XOR_SCORE_TABLES below fold this together with each of the 256
# possible single-byte XOR keys, so scoring/decoding a whole buffer is a
# single C-level bytes.translate() call with an O(1) table lookup instead
# of rebuilding a 256-entry table via a Python-level generator expression
# on every call. The previous implementation (even after switching to
# translate()) still cost ~4096 Python-level XOR operations PER KEY,
# times 255 keys, PER ELIGIBLE REGION just to build that table — with
# only the shared decode budget's own deadline eventually stopping it,
# that measurably dominated this hunter's total scan time once region
# counts reached the hundreds (see tests/perf/test_benchmarks.py, which
# caught this regression).
_XOR_PRINTABLE_FLAGS = bytes(1 if (32 <= b < 127 or b in (9, 10, 13)) else 0 for b in range(256))
_XOR_DECODE_TABLES = [bytes(b ^ key for b in range(256)) for key in range(256)]
_XOR_SCORE_TABLES   = [bytes(_XOR_PRINTABLE_FLAGS[b ^ key] for b in range(256)) for key in range(256)]


def _xor_table(key: int) -> bytes:
    """256-entry translation table for XOR-decoding with a single-byte key."""
    return _XOR_DECODE_TABLES[key]


def _score_xor_key(data: bytes, key: int) -> float:
    printable = sum(data.translate(_XOR_SCORE_TABLES[key]))
    return printable / len(data)


def _scan_xor(data: bytes, region_base: int, budget: ScanBudget, config: EncodingConfig = None):
    # The key-scoring pass below is already tightly bounded (exactly 255
    # keys scored against a fixed 4KB sample, only for MEM_PRIVATE regions
    # <= XOR_SCAN_MAX) — it doesn't draw on the shared decode/decompress
    # attempt budget, only on the dedup/retention accounting shared with
    # the other layers once a candidate actually decodes. It still polls
    # the budget periodically (every 16 keys) so an expired deadline stops
    # the loop promptly instead of always running all 255 keys first.
    xor_sample_size = config.xor_sample_size if config is not None else XOR_SAMPLE_SIZE
    xor_score_min   = config.xor_score_min   if config is not None else XOR_SCORE_MIN
    sample = data[:xor_sample_size]
    candidates = []
    for key in range(1, 256):
        if key % 16 == 0 and not budget.poll():
            return
        score = _score_xor_key(sample, key)
        if score >= xor_score_min:
            decoded_sample = sample.translate(_xor_table(key))
            text = decoded_sample.decode('ascii', errors='replace')
            if _IOC_PAT.search(text) or any(
                kw in text.lower() for kw in
                ('http', 'pipe', 'cmd', 'shellcode', 'beacon', 'rundll')
            ):
                candidates.append((key, score))

    for key, _ in sorted(candidates, key=lambda x: -x[1])[:5]:
        if budget.exhausted():
            return
        decoded = data.translate(_xor_table(key))
        if not budget.seen_content(decoded):
            continue
        cls = _classify_decoded(decoded)
        if cls['is_pe'] or cls['is_shellcode'] or cls['ioc_strings']:
            budget.note_bytes_read(len(decoded))
            yield key, decoded, cls


# ══════════════════════════════════════════════════════════════════════════
# LAYER 4 — GZIP / ZLIB
# ══════════════════════════════════════════════════════════════════════════

def _bounded_decompress(payload: bytes, wbits: int, max_output: int = None) -> tuple:
    """
    Decompress with a hard output-size cap. zlib.decompress() has no such
    cap — a small, even accidentally-truncated, compressed blob can expand
    to gigabytes (zip bomb), and the input-size limit callers apply
    upstream doesn't bound that. decompressobj().decompress(data,
    max_length=N) stops after N output bytes, which is all classification
    needs (PE header / IOC strings live in the first few KB anyway).

    `max_output` (default None -> this module's own DECOMPRESS_MAX_OUTPUT)
    lets _hunt_encoding thread through its own live
    `encoding.DECOMPRESS_MAX_OUTPUT` value rather than this module's
    separate copy.

    max_length also means a merely truncated/corrupted stream can return
    partial output with no exception raised at all: decompressobj() doesn't
    validate the trailing checksum (or even reach end-of-stream) until the
    input runs out, and running out of input mid-stream is silent, not an
    error. `d.eof` distinguishes a stream that actually completed from one
    that merely ran out of input; the `unconsumed_tail` check tells that
    apart from the legitimate "hit the output cap while more valid input
    remained" case (large-but-valid payloads must NOT raise here, only
    genuinely truncated ones raise).

    That still leaves a real gap for output AT the cap: a stream large
    enough that decompression hits the cap before the input is exhausted
    looks identical here whether the remaining, never-fed compressed bytes
    are intact or corrupted/truncated -- the checksum covering the FULL
    stream is never reached either way, by design (that's the whole point
    of capping). Returning `(out, complete)` lets callers tell "verified
    end-to-end" (complete=True, d.eof) apart from "valid as far as
    examined, but truncation beyond the cap can't be ruled out"
    (complete=False) and downgrade confidence accordingly instead of
    treating both the same.
    """
    if max_output is None:
        max_output = DECOMPRESS_MAX_OUTPUT
    d = zlib.decompressobj(wbits)
    out = d.decompress(payload, max_output)
    if not d.eof and not d.unconsumed_tail:
        raise zlib.error("truncated compressed stream")
    return out, d.eof


def _scan_compressed(data: bytes, region_base: int, budget: ScanBudget, config: EncodingConfig = None):
    """
    Scan for GZIP/ZLIB magic bytes and attempt decompression at each one.

    Decompress attempts are bounded by the shared, whole-hunt `budget`
    (ENCODING_BUDGET_MAX_ATTEMPTS) rather than a fixed count per signature
    per region — a 2-byte magic sequence has no error-correction, so a
    region with many coincidental (or adversarially placed) occurrences
    could otherwise trigger unbounded decompressobj() attempts across a
    dump with many such regions, even though each individual attempt is
    itself output-capped (_bounded_decompress). Successful decodes are
    deduplicated by content hash here; whether one gets RETAINED (vs.
    dropped once the budget is tight) is the consumer's call via
    budget.take_hit(), not decided in this generator.

    Yields (offset, algo, decoded, cls, complete) -- `complete` is
    _bounded_decompress's eof signal, passed through so a candidate that
    only decoded up to the output cap (stream never verified end-to-end)
    can be scored/reported at reduced confidence rather than treated the
    same as a fully-verified decode.
    """
    max_output = config.decompress_max_output if config is not None else DECOMPRESS_MAX_OUTPUT
    start = 0
    while True:
        if budget.exhausted():
            return
        idx = data.find(_GZIP_SIG, start)
        if idx == -1:
            break
        if not budget.note_attempt():
            return
        try:
            decoded, complete = _bounded_decompress(data[idx:], wbits=47, max_output=max_output)
            if len(decoded) >= 64 and budget.seen_content(decoded):
                budget.note_bytes_read(len(decoded))
                yield idx, 'gzip', decoded, _classify_decoded(decoded), complete
        except Exception:
            pass
        start = idx + 1

    for sig in _ZLIB_SIGS:
        start = 0
        while True:
            if budget.exhausted():
                return
            idx = data.find(sig, start)
            if idx == -1:
                break
            if not budget.note_attempt():
                return
            try:
                decoded, complete = _bounded_decompress(data[idx:], wbits=zlib.MAX_WBITS, max_output=max_output)
                if len(decoded) >= 64 and budget.seen_content(decoded):
                    budget.note_bytes_read(len(decoded))
                    yield idx, 'zlib', decoded, _classify_decoded(decoded), complete
            except Exception:
                pass
            start = idx + 1


# ══════════════════════════════════════════════════════════════════════════
# Combined entry point — the per-region read loop that used to live inline
# in _hunt_encoding. Feeds all three sub-layers from one shared region read.
# ══════════════════════════════════════════════════════════════════════════

def scan_decode_layers(regions, modules, mf, read_region, config: EncodingConfig, budget: ScanBudget) -> DecodeResult:
    """
    Layers 2-4 combined: reads each eligible region ONCE and feeds Base64,
    single-byte XOR, and GZIP/ZLIB decoding from that one read, applying
    the shared budget's take_hit() gate to each candidate before it's
    kept. Returns a DecodeResult of standardized Hit lists (one per
    sub-layer) plus the shared region-level CoverageTracker.
    """
    base64_hits, xor_hits, compressed_hits = [], [], []
    coverage = CoverageTracker()

    for r in regions:
        if budget.exhausted():
            break
        if prot_str(r.State) != 'MEM_COMMIT':
            continue
        if prot_str(r.Type) not in ('MEM_PRIVATE', 'MEM_IMAGE'):
            continue
        mod = addr_to_module(r.BaseAddress, modules)
        if prot_str(r.Type) == 'MEM_IMAGE' and _is_system_dll(mod):
            continue
        if r.RegionSize > config.decode_scan_max:
            coverage.note_skipped_oversize(
                region_scan_target(mf, r, config.decode_scan_max))
            continue
        try:
            data = read_region(mf, r.BaseAddress, r.RegionSize)
        except Exception:
            coverage.note_read_failed()
            continue
        if len(data) < r.RegionSize:
            coverage.note_short_read()
            if not data:
                continue
        coverage.note_scanned()

        for off, raw, decoded, cls in _scan_base64(data, r.BaseAddress, budget, config):
            # take_hit() is the ONLY gate for whether this candidate is
            # actually kept — its return value MUST be checked (unlike the
            # old note_hit(), whose result could be silently ignored while
            # still appending the item regardless).
            if not budget.take_hit(len(decoded)):
                break
            base64_hits.append(Hit(layer='base64', region=r, offset=off, decoded=decoded, cls=cls,
                                    complete=True, raw=raw))

        if prot_str(r.Type) == 'MEM_PRIVATE' and r.RegionSize <= config.xor_scan_max:
            for key, decoded, cls in _scan_xor(data, r.BaseAddress, budget, config):
                if not budget.take_hit(len(decoded)):
                    break
                xor_hits.append(Hit(layer='xor', region=r, offset=0, decoded=decoded, cls=cls,
                                     complete=True, key=key))

        if not budget.exhausted():
            for off, algo, decoded, cls, complete in _scan_compressed(data, r.BaseAddress, budget, config):
                if not budget.take_hit(len(decoded)):
                    break
                # complete=False means decompression hit the output cap
                # before the stream's own end-of-stream/checksum was
                # reached -- classification is based on a verified-so-far
                # PREFIX, not a fully end-to-end-validated stream (see
                # _bounded_decompress). Downstream confidence must reflect
                # that, not treat it identically to a complete decode.
                compressed_hits.append(Hit(layer=algo, region=r, offset=off, decoded=decoded, cls=cls,
                                            complete=complete))

    return DecodeResult(base64=base64_hits, xor=xor_hits, compressed=compressed_hits, coverage=coverage)
