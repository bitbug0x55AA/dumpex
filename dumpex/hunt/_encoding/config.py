"""
Bundles every dumpex.hunt.encoding tunable that used to be a bare
module-level constant read directly inside a layer's own function body.

Before the encoding.py -> _encoding/* split, `_scan_base64` (say) and its
B64_MIN_LEN constant lived in the SAME file, so `encoding.B64_MIN_LEN = X`
set before calling `_hunt_encoding()` was a live global lookup that
correctly changed `_scan_base64`'s behavior. After the split,
`_scan_base64` moved to decoders.py, which has its OWN separate
`B64_MIN_LEN` binding -- re-exporting the name into encoding.py
(`encoding.B64_MIN_LEN`) makes it readable there, but monkeypatching that
re-exported copy no longer reaches decoders.py's own copy, silently
breaking what used to be a working override:

    encoding.B64_MIN_LEN = 999
    decoders.B64_MIN_LEN   # still 80 -- decoders._scan_base64 never sees the 999

EncodingConfig fixes this the same way `read_region` is already threaded
through explicitly (see dumpex/hunt/encoding.py's own docstring):
_hunt_encoding builds ONE EncodingConfig from its OWN (re-exported, and
therefore still monkeypatchable) module-level constants, then passes that
object into every layer instead of each layer reading a same-named but
differently-bound constant. `EncodingConfig()` with no arguments
reproduces every tunable's original value exactly.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class EncodingConfig:
    entropy_private_threshold: float = 7.2
    entropy_rwx_threshold: float = 6.5
    entropy_scan_max: int = 10 * 1024 * 1024

    b64_min_len: int = 80

    xor_scan_max: int = 512 * 1024
    xor_sample_size: int = 4096
    xor_score_min: float = 0.68

    decompress_max_output: int = 8 * 1024 * 1024

    sleep_mask_key_size: int = 13
    sleep_mask_min_repeat: int = 100
    sleep_mask_max_byte_freq: int = 3
    sleep_mask_min_acbd: float = 20.0
    sleep_mask_max_candidates: int = 10
    sleep_mask_region_max: int = 10 * 1024 * 1024
    sleep_mask_validate_sample: int = 2 * 1024 * 1024
    sleep_mask_validation_marker: bytes = b'sha256\x00'
    sleep_mask_max_windows: int = 200_000
