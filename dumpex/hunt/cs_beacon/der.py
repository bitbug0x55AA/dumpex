"""DER validation for the beacon config's PublicKey field (0x0007).

A structurally-consistent X.509 SubjectPublicKeyInfo carrying the
rsaEncryption OID is one of the two sanity-check gates (see parser.py's
_cs_sanity_check) a candidate must pass before being counted as a real
beacon config, not just a plaintext-signature/TLV-shaped coincidence.
"""

# DER encoding of the rsaEncryption algorithm OID (1.2.840.113549.1.1.1):
# tag(0x06) + length(0x09) + the 9-byte OID value. Cobalt Strike embeds an
# RSA public key here (SubjectPublicKeyInfo), never any other algorithm.
CS_RSA_ENCRYPTION_OID = bytes.fromhex('06092a864886f70d010101')
CS_PUBLIC_KEY_MIN_LEN = 16   # short-form outer tag+length + minimal AlgorithmIdentifier


def _der_read_length(data: bytes, pos: int) -> "tuple[int, int] | None":
    """
    Read one DER length field (definite form only — BER indefinite-length
    encoding, 0x80, is not valid DER and is rejected) starting at `pos`.
    Returns (length, next_pos) or None if malformed/insufficient bytes.
    """
    if pos >= len(data):
        return None
    first = data[pos]
    if first & 0x80 == 0:
        return first, pos + 1
    n = first & 0x7f
    if n == 0 or pos + 1 + n > len(data):
        return None
    return int.from_bytes(data[pos + 1: pos + 1 + n], 'big'), pos + 1 + n


def _cs_validate_public_key_der(raw: bytes) -> "tuple[bool, str]":
    """
    Validate the PublicKey field (0x0007) as a minimally plausible X.509
    SubjectPublicKeyInfo DER structure:

        SEQUENCE {                        -- SubjectPublicKeyInfo
          SEQUENCE {                      -- AlgorithmIdentifier
            OID  rsaEncryption (1.2.840.113549.1.1.1)
            ...                           -- (params, not checked here)
          }
          ...                             -- subjectPublicKey, not checked
        }

    A prior version only checked that the raw bytes' hex started with
    "308" — three hex nibbles that happen to match ANY DER SEQUENCE
    beginning with a plausible short/long-form length byte, regardless of
    whether the length is internally consistent or the structure has
    anything to do with an RSA key. This checks minimum length, that the
    outer SEQUENCE's declared DER length doesn't exceed the actual buffer,
    and that immediately inside it sits an AlgorithmIdentifier SEQUENCE
    whose OID is exactly rsaEncryption — cheap to spoof entirely, but no
    longer trivially satisfied by 3 fixed nibbles plus arbitrary bytes.

    Returns (valid, reason); reason is a short diagnostic string on
    failure, "" on success.
    """
    if len(raw) < CS_PUBLIC_KEY_MIN_LEN:
        return False, f"PublicKey field too short ({len(raw)} bytes) for a DER SEQUENCE"
    if raw[0] != 0x30:
        return False, "PublicKey field does not start with a DER SEQUENCE tag (0x30)"

    outer = _der_read_length(raw, 1)
    if outer is None:
        return False, "PublicKey field: malformed outer SEQUENCE length"
    outer_len, pos = outer
    outer_end = pos + outer_len
    if outer_end > len(raw):
        return False, (f"PublicKey field: declared SEQUENCE length {outer_len} exceeds "
                        f"available {len(raw) - pos} byte(s)")

    if pos >= outer_end or raw[pos] != 0x30:
        return False, "PublicKey field: AlgorithmIdentifier SEQUENCE tag not found"
    inner = _der_read_length(raw, pos + 1)
    if inner is None:
        return False, "PublicKey field: malformed AlgorithmIdentifier length"
    inner_len, alg_pos = inner
    alg_end = alg_pos + inner_len
    # The AlgorithmIdentifier SEQUENCE must be fully contained within the
    # OUTER SubjectPublicKeyInfo SEQUENCE it's declared to be part of, not
    # merely within the overall buffer — a short outer length paired with
    # a longer inner one would otherwise let AlgorithmIdentifier (and the
    # OID comparison below) read bytes that sit past where the outer
    # SEQUENCE actually claims to end.
    if alg_end > outer_end:
        return False, "PublicKey field: AlgorithmIdentifier extends past the outer SEQUENCE"

    oid_len = len(CS_RSA_ENCRYPTION_OID)
    # The OID itself must fit entirely within AlgorithmIdentifier's own
    # declared length — otherwise a zero-or-short inner_len (e.g. an
    # AlgorithmIdentifier SEQUENCE that declares 0 bytes of content) would
    # let the comparison below read bytes that were never actually
    # claimed to be part of this structure at all, still matching the OID
    # by coincidence if the right bytes happen to sit right after it.
    if alg_pos + oid_len > alg_end:
        return False, "PublicKey field: AlgorithmIdentifier too short to contain the OID"
    if raw[alg_pos: alg_pos + oid_len] != CS_RSA_ENCRYPTION_OID:
        return False, "PublicKey field: AlgorithmIdentifier OID is not rsaEncryption"

    # A SubjectPublicKeyInfo has a BIT STRING (the actual key material)
    # immediately after AlgorithmIdentifier, still within the outer
    # SEQUENCE. A bare tag byte with no length/content behind it is not
    # enough — that's still just as spoofable as the old "308" prefix
    # check this replaced, one tag byte later. The BIT STRING's own DER
    # length must be read and bounds-checked the same way
    # AlgorithmIdentifier's was: it must declare at least the mandatory
    # unused-bits byte, its content must not extend past the outer
    # SEQUENCE, and since it's the SubjectPublicKeyInfo's final field it
    # must consume exactly the rest of the outer SEQUENCE, not leave
    # declared-but-unaccounted-for trailing bytes.
    if alg_end >= outer_end or raw[alg_end] != 0x03:
        return False, "PublicKey field: no BIT STRING follows AlgorithmIdentifier"
    bit_string = _der_read_length(raw, alg_end + 1)
    if bit_string is None:
        return False, "PublicKey field: malformed BIT STRING length"
    bit_string_len, bit_string_pos = bit_string
    # >= 2, not >= 1: byte 0 is the mandatory unused-bits count, but that
    # alone is an EMPTY key ("03 01 00" -- a bare unused-bits byte with no
    # key material at all) and would otherwise still pass. There must be
    # at least one more byte behind it for this to be an actual key.
    if bit_string_len < 2:
        return False, "PublicKey field: BIT STRING too short to contain key material"
    bit_string_end = bit_string_pos + bit_string_len
    if bit_string_end > outer_end:
        return False, "PublicKey field: BIT STRING extends past the outer SEQUENCE"
    if bit_string_end != outer_end:
        return False, "PublicKey field: BIT STRING does not consume the rest of the outer SEQUENCE"
    if raw[bit_string_pos] != 0x00:
        return False, ("PublicKey field: BIT STRING unused-bits byte is not 0 -- an RSA "
                        "SubjectPublicKeyInfo's key material is always byte-aligned")
    # The RSA public key itself (RSAPublicKey ::= SEQUENCE { modulus,
    # publicExponent }) is DER-encoded inside the BIT STRING's content --
    # it must start with a SEQUENCE tag, not arbitrary bytes.
    if raw[bit_string_pos + 1] != 0x30:
        return False, ("PublicKey field: BIT STRING content is not a DER SEQUENCE "
                        "(expected RSAPublicKey)")

    return True, ""
