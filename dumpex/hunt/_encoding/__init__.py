"""
Internal submodules of dumpex.hunt.encoding, split out one layer at a
time (see docs on the encoding.py package split) so the file doesn't
grow into one monolithic module. Nothing here is a public import path —
dumpex.hunt.encoding re-exports everything a caller/test needs; import
from dumpex.hunt.encoding, not from dumpex.hunt._encoding.* directly.
"""
