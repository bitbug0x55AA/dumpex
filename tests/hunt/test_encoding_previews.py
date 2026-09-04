"""Console evidence previews for retained Base64 hits.

`--verbose` quotes the encoded string and the decoded payload dumpex already
holds, bounded and terminal-safe, without reading the dump again and without
changing what structured output carries.
"""
import base64
import hashlib

import pytest

from tests.fixtures.fakes import build_pe_header
from tests.hunt.test_encoding_domain import _check, _coverage
from tests.hunt.test_encoding_projectors import _BASE

from dumpex.hunt._finding import CONFIDENCE_LOW, TAG_OBSERVATION
from dumpex.hunt._location import Location
from dumpex.hunt.encoding import classification
from dumpex.hunt.encoding.config import (
    B64_PREVIEW_ENCODED_CHARS, B64_PREVIEW_HEX_BYTES, B64_PREVIEW_MAX_HITS,
    B64_PREVIEW_TEXT_BYTES,
)
from dumpex.hunt.encoding.domain import EncodingEvidence, EncodingReport
from dumpex.hunt.encoding.models import Classification, DecodedHit, RegionRef
from dumpex.hunt.encoding.report_console import _console_finding, render_console_lines
from dumpex.hunt.encoding.report_facts import finding_from_check_result
from dumpex.hunt.encoding.report_legacy import project_legacy_dict
from dumpex.hunt.encoding.report_record import project_hunter_record
from dumpex.ui.colors import _CONSOLE_ESCAPES


PLAINTEXT = b"configurationVersion=1; serviceEndpoint=https://example.invalid/api"

# Every codepoint a terminal acts on. A newline is excluded from the
# whole-output check only because the rendered console block is itself a
# list of lines joined by newlines -- the per-fact assertions below still
# require an encoded `\x0a` for a newline inside decoded content.
HOSTILE_CODEPOINTS = frozenset(_CONSOLE_ESCAPES) - {0x0A}


# ── Builders ─────────────────────────────────────────────────────────────

def _b64_hit(decoded: bytes, va: int = _BASE, file_offset: int = 0x2200) -> DecodedHit:
    """One retained Base64 hit carrying real content: `raw` is the actual
    Base64 encoding of `decoded`, and the classification is the one the
    scan layer's own classifier produces for those bytes."""
    region = RegionRef(base_address=va, allocation_base=va, size=0x1000,
                       state="MEM_COMMIT", protect="PAGE_READWRITE", type="MEM_PRIVATE")
    return DecodedHit(layer="base64", region=region,
                      location=Location(va=va, region_base=va, file_offset=file_offset),
                      decoded=decoded, classification=classification._classify_decoded(decoded),
                      raw=base64.b64encode(decoded))


def _report_for(*hits: DecodedHit) -> EncodingReport:
    result = _check(check="obfuscation.base64_observation", tag=TAG_OBSERVATION,
                    confidence=CONFIDENCE_LOW, evidence=hits, evidence_limit=15)
    return EncodingReport(score=0, coverage=_coverage(), results=(result,),
                          evidence=EncodingEvidence(base64_hits=hits))


def _verbose_facts(*hits: DecodedHit) -> tuple:
    report = _report_for(*hits)
    return _console_finding(report.results[0], report).verbose_facts


def _fact_for(decoded: bytes) -> str:
    return _verbose_facts(_b64_hit(decoded))[0]


def _pe_bytes() -> bytes:
    return build_pe_header(
        [{"name": b".text", "vaddr": 0x1000, "vsize": 0x200, "rawptr": 0x400,
          "rawsize": 0x200, "chars": 0x60000020}],
        size_of_image=0x2000, trailing_padding=0x300)


# ── Decoded text previews ────────────────────────────────────────────────

def test_short_plaintext_is_quoted_in_full_without_a_truncation_marker():
    fact = _fact_for(PLAINTEXT)
    assert f'Decoded_preview="{PLAINTEXT.decode()}"' in fact
    assert "bytes omitted" not in fact


def test_content_that_fits_the_preview_needs_no_digest_to_identify_it():
    assert "Decoded_sha256" not in _fact_for(PLAINTEXT)


def test_long_plaintext_is_bounded_and_states_the_omitted_byte_count():
    decoded = PLAINTEXT + b" padding=" + b"A" * 300
    fact = _fact_for(decoded)
    omitted = len(decoded) - B64_PREVIEW_TEXT_BYTES
    assert f'Decoded_preview="{decoded[:B64_PREVIEW_TEXT_BYTES].decode()}"' in fact
    assert f"[+{omitted}bytes omitted]" in fact
    assert decoded[B64_PREVIEW_TEXT_BYTES:].decode() not in fact


def test_a_truncated_preview_carries_the_whole_payloads_digest():
    decoded = PLAINTEXT + b" padding=" + b"A" * 300
    assert f"Decoded_sha256={hashlib.sha256(decoded).hexdigest()}" in _fact_for(decoded)


def test_ioc_text_keeps_both_its_content_preview_and_its_ioc_strings():
    fact = _fact_for(PLAINTEXT)
    assert "Decoded_type=IOC_TEXT" in fact
    assert "Decoded_preview=" in fact
    assert "IOC_strings=https://example.invalid/api" in fact


# ── Encoded (Base64) previews ────────────────────────────────────────────

def test_the_original_base64_string_is_previewed_and_bounded():
    decoded = PLAINTEXT + b" padding=" + b"A" * 300
    raw = base64.b64encode(decoded)
    fact = _fact_for(decoded)
    assert f'Encoded_preview="{raw[:B64_PREVIEW_ENCODED_CHARS].decode()}"' in fact
    assert f"[+{len(raw) - B64_PREVIEW_ENCODED_CHARS}chars omitted]" in fact
    assert raw.decode() not in fact


def test_a_short_base64_string_is_previewed_whole():
    decoded = b"short config value"
    raw = base64.b64encode(decoded)
    assert len(raw) <= B64_PREVIEW_ENCODED_CHARS
    fact = _fact_for(decoded)
    assert f'Encoded_preview="{raw.decode()}"' in fact
    assert "chars omitted" not in fact


# ── Binary and structural content ────────────────────────────────────────

def test_pe_content_renders_as_bounded_hex_with_its_header_metadata():
    pe = _pe_bytes()
    fact = _fact_for(pe)
    assert "Decoded_type=PE" in fact
    assert f"Decoded_hex={pe[:B64_PREVIEW_HEX_BYTES].hex()}" in fact
    assert f"[+{len(pe) - B64_PREVIEW_HEX_BYTES}bytes omitted]" in fact
    assert "Decoded_preview=" not in fact
    assert "PE_sections=1" in fact
    assert "PE_image_size=0x2000" in fact


def test_binary_content_renders_as_hex_and_is_identified_by_its_digest():
    decoded = bytes(range(256)) * 2
    fact = _fact_for(decoded)
    assert f"Decoded_hex={decoded[:B64_PREVIEW_HEX_BYTES].hex()}" in fact
    assert f"Decoded_sha256={hashlib.sha256(decoded).hexdigest()}" in fact
    assert "Decoded_preview=" not in fact


def test_short_binary_content_is_still_identified_by_its_digest():
    # Hex shows a prefix of bytes nobody compares by eye, so the digest is
    # printed for binary content whether or not the hex was truncated.
    decoded = b"\x00\x01\x02\x03"
    fact = _fact_for(decoded)
    assert "bytes omitted" not in fact
    assert f"Decoded_sha256={hashlib.sha256(decoded).hexdigest()}" in fact


# ── Terminal safety ──────────────────────────────────────────────────────

def test_control_characters_in_decoded_text_are_escaped():
    decoded = b"key=value and enough printable text to read as plaintext\r\n\tsecond\x00end"
    fact = _fact_for(decoded)
    assert "Decoded_preview=" in fact
    assert "\\x0d\\x0a\\x09" in fact and "\\x00" in fact
    for raw in ("\r", "\n", "\t", "\x00"):
        assert raw not in fact


def test_ansi_escape_sequences_in_decoded_text_cannot_reach_the_terminal():
    decoded = b"harmless looking configuration text \x1b[31;1mred\x1b[0m and more text"
    fact = _fact_for(decoded)
    assert "\x1b" not in fact
    assert "\\x1b[31;1mred" in fact


def test_invalid_utf8_in_decoded_text_renders_deterministically():
    decoded = b"printable configuration text with a stray byte " + b"\xff" + b" at the end"
    fact = _fact_for(decoded)
    assert "\\xff" in fact
    assert fact == _fact_for(decoded)


def test_no_rendered_line_carries_a_character_a_terminal_acts_on():
    hostile = "".join(chr(c) for c in sorted(HOSTILE_CODEPOINTS))
    decoded = b"configuration text " + hostile.encode("utf-8") + b" trailing text"
    output = "\n".join(render_console_lines(_report_for(_b64_hit(decoded)), verbose=True))
    for codepoint in HOSTILE_CODEPOINTS:
        assert chr(codepoint) not in output


def test_an_ioc_string_cut_from_decoded_content_cannot_carry_an_ansi_escape():
    # The URL pattern matches on `\S`, which admits ESC: a matched URL
    # carries whatever the decoded content put inside it, so the IOC field
    # is dump-derived text with the same reach as the content preview.
    decoded = (b"printable configuration text here: "
               b"https://example.invalid/\x1b[31mred and more printable text")
    hit = _b64_hit(decoded)
    assert hit.classification.kind == "ioc_text"
    assert any("\x1b" in s for s in hit.classification.ioc_strings), \
        "the classifier must keep the exact IOC bytes -- escaping is the console's job"

    output = "\n".join(render_console_lines(_report_for(hit), verbose=True))
    assert "\x1b" not in output
    assert "IOC_strings=https://example.invalid/\\x1b[31mred" in output


# Every verbose renderer that quotes IOC strings, with the evidence bucket
# its check reads from -- a renderer added without escaping its own IOC
# field is a renderer this test does not yet name.
_IOC_RENDERING_CHECKS = {
    "obfuscation.sleep_mask_confirmed": (
        "sleep_mask_hits", dict(layer="sleep_mask", key=b"\x11\x22\x33", key_offset=1)),
    "obfuscation.base64_observation": ("base64_hits", dict(layer="base64", raw=b"QQQQ")),
    "obfuscation.xor_observation":    ("xor_hits", dict(layer="xor", key=0x5A)),
    "obfuscation.compressed_observation": ("compressed_hits", dict(layer="gzip")),
}


@pytest.mark.parametrize("check", sorted(_IOC_RENDERING_CHECKS))
def test_every_verbose_renderer_escapes_the_ioc_strings_it_quotes(check):
    bucket, kwargs = _IOC_RENDERING_CHECKS[check]
    hostile_ioc = "https://example.invalid/\x1b[31m\r\n\x00red"
    region = RegionRef(base_address=_BASE, allocation_base=_BASE, size=0x1000,
                       state="MEM_COMMIT", protect="PAGE_READWRITE", type="MEM_PRIVATE")
    hit = DecodedHit(region=region,
                     location=Location(va=_BASE, region_base=_BASE, file_offset=0x2200),
                     decoded=b"decoded text content", classification=Classification(
                         kind="ioc_text", is_pe=False, is_shellcode=False,
                         ioc_strings=(hostile_ioc,), hex_prefix="", entropy=1.0),
                     **kwargs)
    result = _check(check=check, tag=TAG_OBSERVATION, confidence=CONFIDENCE_LOW,
                    evidence=(hit,), evidence_limit=15)
    report = EncodingReport(score=0, coverage=_coverage(), results=(result,),
                            evidence=EncodingEvidence(**{bucket: (hit,)}))

    output = "\n".join(render_console_lines(report, verbose=True))
    assert "IOC_strings=" in output
    for raw in ("\x1b", "\r", "\x00"):
        assert raw not in output
    assert "https://example.invalid/\\x1b[31m\\x0d\\x0a\\x00red" in output


# ── Bounded, deterministic multi-hit output ──────────────────────────────

def test_every_retained_hit_keeps_its_own_line_and_previews_are_bounded():
    hits = tuple(_b64_hit(PLAINTEXT + b" n=%d" % i, va=_BASE + i * 0x1000)
                 for i in range(B64_PREVIEW_MAX_HITS + 5))
    facts = _verbose_facts(*hits)

    assert len(facts) == len(hits) + 1
    assert sum(1 for f in facts if "Encoded_preview=" in f) == B64_PREVIEW_MAX_HITS
    assert all(f.startswith("VA=0x") for f in facts[:len(hits)])
    assert facts[-1].startswith(
        f"Content previews bounded to the first {B64_PREVIEW_MAX_HITS} of {len(hits)} hits")


def test_hits_within_the_bound_get_no_trailing_bound_notice():
    hits = tuple(_b64_hit(PLAINTEXT, va=_BASE + i * 0x1000) for i in range(3))
    facts = _verbose_facts(*hits)
    assert len(facts) == 3
    assert all("Encoded_preview=" in f for f in facts)


def test_rendering_the_same_report_twice_produces_identical_output():
    report = _report_for(_b64_hit(PLAINTEXT), _b64_hit(_pe_bytes(), va=_BASE + 0x1000))
    assert render_console_lines(report, verbose=True) == render_console_lines(report, verbose=True)


def test_previews_are_verbose_only():
    report = _report_for(_b64_hit(PLAINTEXT))
    output = "\n".join(render_console_lines(report, verbose=False))
    assert "Decoded_preview" not in output
    assert "Encoded_preview" not in output
    assert PLAINTEXT.decode() not in output


# ── What previews must not change ────────────────────────────────────────

def test_structured_output_still_carries_the_full_raw_and_decoded_bytes():
    decoded = PLAINTEXT + b" padding=" + b"A" * 300
    raw = base64.b64encode(decoded)
    report = _report_for(_b64_hit(decoded))

    # The legacy dict keeps raw `bytes` (hex-encoded at --json
    # serialization time); the typed record hex-encodes them itself.
    legacy = project_legacy_dict(report)["base64"][0]
    assert legacy["decoded"] == decoded and legacy["raw"] == raw

    record = project_hunter_record(report).details.base64[0]
    assert record["decoded"] == decoded.hex() and record["raw"] == raw.hex()


def test_previews_do_not_reach_the_wire_facts_or_change_the_finding_id():
    report = _report_for(_b64_hit(PLAINTEXT))
    result = report.results[0]
    wire = finding_from_check_result(result, report)
    console = _console_finding(result, report)

    assert console.facts == wire.facts
    assert all("preview" not in f for f in wire.facts)
    assert console.id == wire.id
    assert (console.severity, console.confidence, console.tag) == (
        wire.severity, wire.confidence, wire.tag)


def test_verdict_score_and_coverage_are_untouched_by_previews():
    report = _report_for(_b64_hit(PLAINTEXT))
    output = "\n".join(render_console_lines(report, verbose=True))
    assert report.score == 0 and report.verdict_level == "clean"
    assert "CLEAN" in output
    assert "COMPLETE" in output


@pytest.mark.parametrize("verbose", [False, True])
def test_rendering_never_reads_from_the_dump(monkeypatch, verbose):
    def _refuse(*args, **kwargs):
        raise AssertionError("console rendering must not read the dump")

    monkeypatch.setattr("dumpex.core.memory.read_region", _refuse)
    monkeypatch.setattr("dumpex.hunt.encoding.read_region", _refuse)
    report = _report_for(_b64_hit(PLAINTEXT), _b64_hit(_pe_bytes(), va=_BASE + 0x1000))
    assert render_console_lines(report, verbose=verbose)
