"""Tunable constant for the process injection hunter."""

# Bytes read per MZ-prefixed candidate for structural PE validation — large
# enough for the DOS/COFF/optional headers plus a section table of typical
# size (a handful to a few dozen sections). A candidate whose section table
# extends past this just reports valid=False with a truncation reason
# (parse_pe_header) rather than growing this unboundedly for every
# MZ-prefixed hit in the dump.
PE_VALIDATE_READ_MAX = 4096
