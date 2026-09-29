"""The parser-state vocabulary of one minidump stream: whether dumpex
found it, parsed it, and could count what it holds.

Shared by `--profile`'s stream inventory and `--report`'s token
capability, which both describe the state of a stream they read.
"""
from enum import Enum


class StreamParserState(str, Enum):
    PARSED        = "parsed"          # present; dumpex parsed it (a countable collection
                                        # with >=1 item, or a singular non-collection stream)
    PRESENT_EMPTY = "present_empty"   # present; dumpex parsed it, verified zero items
    UNPARSED      = "unparsed"        # present; dumpex has no parser registered for this
                                        # stream type (covers every recognized-but-
                                        # unimplemented MINIDUMP_STREAM_TYPE and every
                                        # unrecognized numeric type alike)
    FAILED        = "failed"          # present; dumpex attempted to parse it and it raised
    INDETERMINATE = "indeterminate"   # present; >=1 OTHER directory entry shares this same
                                        # stream type, and open_dump()'s own single
                                        # mf.<attr>/_dumpex_stream_failures pair cannot be
                                        # attributed back to any ONE of the duplicate
                                        # entries with confidence -- see
                                        # dumpex.commands.profile's own docstring on why


_STREAM_PARSER_STATES = tuple(s.value for s in StreamParserState)
