"""Minidump file access beneath the `dumpex.core.memory` entry point.

One owner module per responsibility: `loader` (opening, header,
directory, per-stream isolation), `handle_stream` and
`thread_info_stream` (dumpex-owned stream parsers), `stream_state`
(stream-state observation), `segments` (segment table, address mapping,
capture accounting) and `reads` (checked, clamped and spanning reads).
This package defines and imports nothing itself, so importing one owner
loads only what that owner declares. See docs/developer/memory_layout.md.
"""
