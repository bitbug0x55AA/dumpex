"""
Unit tests for dumpex.output.serializer -- the strict v2 JSON encoder.
Unlike dumpex/ui/structured.py's `_json_safe` (permissive str(obj)
fallback, appropriate for v1.1), the v2 serializer must raise for any
value that isn't already a plain JSON scalar/list/dict, so a record type
that forgot to convert one of its own fields fails a test immediately
instead of silently shipping a stringified repr().
"""
import json
import re

import pytest

from dumpex.output.serializer import to_json, _ensure_json_safe
from dumpex.output.envelope import Result, Envelope


class _FakeEnvelope:
    def __init__(self, doc):
        self._doc = doc

    def to_dict(self):
        return self._doc


def test_valid_plain_document_serializes():
    doc = {"a": 1, "b": [1, 2.5, True, False, None, "x"], "c": {"d": []}}
    out = json.loads(to_json(_FakeEnvelope(doc)))
    assert out == doc


def test_unknown_object_type_raises_type_error_not_stringified():
    class Unrecognized:
        pass

    with pytest.raises(TypeError, match="not a plain JSON"):
        to_json(_FakeEnvelope({"x": Unrecognized()}))


def test_unknown_object_nested_in_list_raises():
    class Unrecognized:
        pass

    with pytest.raises(TypeError):
        to_json(_FakeEnvelope({"x": [1, 2, Unrecognized()]}))


def test_set_is_not_json_safe():
    # v1's _json_safe would sort a set into a list automatically; v2
    # requires the caller (a record's own to_dict()) to have already
    # done that -- the serializer itself must not paper over it.
    with pytest.raises(TypeError):
        to_json(_FakeEnvelope({"x": {1, 2, 3}}))


def test_bytes_is_not_json_safe():
    with pytest.raises(TypeError):
        to_json(_FakeEnvelope({"x": b"raw bytes"}))


def test_non_string_dict_key_raises():
    with pytest.raises(TypeError, match="is not a string"):
        _ensure_json_safe({1: "x"})


def test_error_message_includes_a_path_to_the_offending_value():
    class Unrecognized:
        pass

    with pytest.raises(TypeError, match=re.escape("$.result.data[0]")):
        _ensure_json_safe({"result": {"data": [Unrecognized()]}})


def test_real_envelope_with_result_records_serializes():
    result = Result(kind="modules", execution_status="completed",
                     coverage_status="complete", coverage_reasons=[],
                     summary={"count": 1}, records=[{"name": "a.dll"}])
    envelope = Envelope(meta={"schema_version": "2.0"}, result=result)
    doc = json.loads(to_json(envelope))
    assert doc["result"]["kind"] == "modules"
    assert doc["result"]["data"]["records"] == [{"name": "a.dll"}]
