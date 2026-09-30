"""Interpretation of a loaded dump beneath the `dumpex.core.memory` entry
point.

One owner module per responsibility: `threads` (thread records, DumpFlags,
recorded start addresses, captured contexts and their joins), `lookup`
(module, region, allocation and handle-descriptor lookup, protection
names, address arguments and read-size resolution) and `strings` (string
and IOC extraction and the committed-memory string search). This package
defines and imports nothing itself, so importing one owner loads only what
that owner declares. See docs/developer/memory_layout.md.
"""
