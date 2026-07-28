"""
Standardized per-layer result shapes for dumpex.hunt.encoding.

Every scan layer (sleep_mask, entropy, decoding) returns a LayerResult
instead of a hand-rolled tuple, so aggregate.py can process coverage
uniformly across all five layers without knowing each one's internal
shape. Decoded/classified content (sleep_mask, base64, xor, gzip/zlib)
is further standardized into `Hit` so aggregate.py can dedup, classify,
and build Findings for those four layers with shared logic instead of
four near-identical copies of the same dedup/classify/report block.

Entropy doesn't decode anything (it's a statistical observation, not
classified content), so it keeps its own `EntropyHit` shape rather than
being forced into `Hit`.

A layer function itself makes NO decision about score/status/verdict and
prints nothing — it returns data. That decision-making lives entirely in
aggregate.py; rendering it lives entirely in presentation.py.

Two representations exist for a reason, not by accident: aggregate.py
keeps the RAW Hit/EntropyHit objects in EncodingReport (real region
object, real bytes) for presentation.py to print VA/file-offset/decoded
content from -- but the same objects must NEVER be placed directly into
the `findings` dict _hunt_encoding returns, because that dict is also
what dumpex.ui.structured.StructuredOutput serializes to JSON via
_json_safe(), which has no dataclass-awareness and falls back to
str(obj) for anything it doesn't recognize -- for a Hit, that means a
JSON string containing the region object's memory address (different
every run) and the FULL raw `decoded` bytes as an escaped Python bytes
literal, not a hex string. `.to_dict()` below is what aggregate.py calls
before writing anything into `findings` -- see aggregate.py's own
comments at the two call sites for exactly where the object/dict split
happens.
"""
from dataclasses import dataclass, field
from typing import Any


def _region_to_dict(region):
    """JSON-safe description of a region BY VALUE -- dumpex.ui.structured's
    _json_safe() has no case for an arbitrary region object (real
    MinidumpMemoryInfo or this repo's own test fakes), so left unconverted
    it falls back to str(obj), which embeds a live memory address that
    differs on every run. State/Protect/Type are left as whatever
    enum-like object the caller passed in -- _json_safe already knows how
    to reduce those to their .name."""
    if region is None:
        return None
    return {
        "BaseAddress": region.BaseAddress,
        "AllocationBase": getattr(region, "AllocationBase", None),
        "RegionSize": region.RegionSize,
        "State": getattr(region, "State", None),
        "Protect": getattr(region, "Protect", None),
        "Type": getattr(region, "Type", None),
    }


@dataclass
class Hit:
    """One decoded/classified payload from any of the four content-
    producing layers (sleep_mask, base64, xor, gzip/zlib)."""
    layer: str            # 'sleep_mask' | 'base64' | 'xor' | 'gzip' | 'zlib'
    region: Any            # object with .BaseAddress / .RegionSize / .Type / .Protect
    offset: int            # offset within the region where the payload starts (0 for
                           # whole-region layers: sleep_mask, xor)
    decoded: bytes
    cls: dict              # _classify_decoded() result
    complete: bool = True  # gzip/zlib only: whether decompression verified the stream
                           # end-to-end (see decoding._bounded_decompress); always True
                           # for the other three layers, which have no such concept.
    raw: bytes = None      # original encoded bytes, where meaningful (base64 only --
                           # used to report the encoded string's own length)
    key: Any = None        # XOR key: int for the xor layer, bytes for sleep_mask
    key_offset: int = None  # sleep_mask's key rotation offset (0..key_size-1)

    def to_dict(self) -> dict:
        """JSON-safe form for the public `findings` dict -- region is
        described by value (see _region_to_dict); bytes fields (decoded,
        raw, key when it's the sleep_mask XOR key) pass through as-is and
        get hex-encoded by dumpex.ui.structured._json_safe at actual
        serialization time, same as every other hunter's raw bytes
        fields."""
        return {
            "layer": self.layer,
            "region": _region_to_dict(self.region),
            "offset": self.offset,
            "decoded": self.decoded,
            "cls": self.cls,
            "complete": self.complete,
            "raw": self.raw,
            "key": self.key,
            "key_offset": self.key_offset,
        }


@dataclass
class EntropyHit:
    """One high-entropy region flagged by the entropy layer -- a
    statistical observation, never classified/decoded content."""
    region: Any
    entropy: float
    threshold: float

    def to_dict(self) -> dict:
        return {"region": _region_to_dict(self.region), "entropy": self.entropy,
                "threshold": self.threshold}


@dataclass
class LayerResult:
    """hits: list[Hit] for sleep_mask, list[EntropyHit] for entropy --
    coverage is the one thing every layer's result has in common."""
    hits: list = field(default_factory=list)
    coverage: Any = None


@dataclass
class DecodeResult:
    """Combined result of the Base64/XOR/GZIP-ZLIB region scan
    (decoding.scan_decode_layers) -- one shared per-region read/coverage
    pass produces all three layers' hit lists together, mirroring how
    _hunt_encoding's old inline loop read each region's bytes ONCE and
    fed all three decoders from it."""
    base64: list = field(default_factory=list)       # list[Hit]
    xor: list = field(default_factory=list)           # list[Hit]
    compressed: list = field(default_factory=list)    # list[Hit]
    coverage: Any = None
