"""Tunable constants for the Cobalt Strike beacon config hunter, and the
CSBeaconConfig bundle that threads them into scanner.py.

Single canonical home for every CS_* budget/limit constant: `__init__.py`
re-exports these names (so `cs_beacon.CS_MAX_CANDIDATES = 5` before calling
`_hunt_cs_beacon()` still works, as existing tests rely on), then builds a
CSBeaconConfig from its OWN re-exported globals and threads that explicitly
into scanner.py -- scanner.py must never import these constants itself and
use them directly, or a monkeypatch on the facade's copy would silently not
reach it (see dumpex/hunt/encoding/config.py for the same lesson).
"""
from dataclasses import dataclass

CS_BEACON_SIGNATURE  = b'\x00\x01\x00\x01\x00\x02'   # plaintext TLV start
CS_SIG_XOR69         = b'ihihik'                       # above ^ 0x69
CS_SIG_XOR2E         = b'././.,'                       # above ^ 0x2e
CS_MAX_SEG_SCAN      = 50 * 1024 * 1024               # skip segments > 50 MB

# Total resource budget for the WHOLE scan (across every segment), not a
# per-segment limit — a dump stuffed with thousands of decoy/duplicate
# markers (deliberately or by coincidence) must not be able to make this
# hunter run unbounded time/memory. When any cap is hit, the scan stops
# and the result is reported as coverage-partial rather than silently
# treating the unscanned remainder as "checked, nothing there".
CS_CONFIG_DECODE_MAX = 8192          # bytes decoded per candidate (real CS
                                       # configs are a few KB at most; only
                                       # decoding this much instead of a
                                       # fixed 64 KB avoids retaining a huge
                                       # buffer for markers that are never a
                                       # real config)
CS_MAX_CANDIDATES     = 20000        # marker matches examined, whole scan
CS_MAX_DECODED_BYTES  = 64 * 1024 * 1024   # total bytes XOR-decoded, whole scan
CS_MAX_HITS           = 100          # stop once this many configs are found
CS_SCAN_DEADLINE_SECONDS = 60         # wall-clock budget for the whole scan
CS_MAX_TOTAL_SCANNED_BYTES = 500 * 1024 * 1024   # total bytes READ across all
                                                    # segments, whole scan — bounds
                                                    # work even for many large,
                                                    # marker-free segments, where
                                                    # the deadline check inside the
                                                    # per-candidate loop below never
                                                    # runs at all (see the
                                                    # per-segment deadline check)

# Independent memory-context corroboration for a config hit (score 1 -> 2):
# a config's own bytes are inert DATA, so a beacon that is actually loaded
# and running typically has the config sitting in a private allocation
# that ALSO carries executable memory (the decrypted/decompressed payload)
# — as opposed to a bare, isolated copy of just the config bytes.
CS_SUSPICIOUS_PRIVATE_PROTECTIONS = frozenset({
    'PAGE_EXECUTE_READWRITE', 'PAGE_EXECUTE_READ', 'PAGE_EXECUTE',
    'PAGE_EXECUTE_WRITECOPY',
})


@dataclass(frozen=True)
class CSBeaconConfig:
    max_seg_scan: int = CS_MAX_SEG_SCAN
    config_decode_max: int = CS_CONFIG_DECODE_MAX
    max_candidates: int = CS_MAX_CANDIDATES
    max_decoded_bytes: int = CS_MAX_DECODED_BYTES
    max_hits: int = CS_MAX_HITS
    scan_deadline_seconds: float = CS_SCAN_DEADLINE_SECONDS
    max_total_scanned_bytes: int = CS_MAX_TOTAL_SCANNED_BYTES
