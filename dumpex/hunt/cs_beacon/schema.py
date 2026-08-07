"""Cobalt Strike beacon config field tables and this hunter's own
score -> verdict_level mapping.

All lookup tables below are adapted from 1768.py by Didier Stevens (public
domain) — see CREDITS.
"""

# Field IDs from 1768.py dConfigIdentifiers
CS_FIELD_NAMES = {
    0x0001: 'BeaconType',
    0x0002: 'Port',
    0x0003: 'SleepTime',
    0x0004: 'MaxGetSize',
    0x0005: 'Jitter',
    0x0006: 'MaxDNS',
    0x0007: 'PublicKey',
    0x0008: 'C2Server',
    0x0009: 'UserAgent',
    0x000a: 'HTTP_PostURI',
    0x000b: 'MalleableC2',
    0x000c: 'HTTP_GetHeader',
    0x000d: 'HTTP_PostHeader',
    0x000e: 'SpawnTo',
    0x000f: 'PipeName',
    0x0010: 'KillDate_Year',
    0x0011: 'KillDate_Month',
    0x0012: 'KillDate_Day',
    0x0013: 'DNS_Idle',
    0x0014: 'DNS_Sleep',
    0x0015: 'SSH_Host',
    0x0016: 'SSH_Port',
    0x0017: 'SSH_Username',
    0x0018: 'SSH_Password',
    0x0019: 'SSH_PubKey',
    0x001a: 'HTTP_GetVerb',
    0x001b: 'HTTP_PostVerb',
    0x001c: 'HttpPostChunk',
    0x001d: 'SpawnTo_x86',
    0x001e: 'SpawnTo_x64',
    0x001f: 'CryptoScheme',
    0x0020: 'Proxy',
    0x0021: 'Proxy_Username',
    0x0022: 'Proxy_Password',
    0x0023: 'Proxy_Type',
    0x0025: 'LicenseID',
    0x0026: 'bStageCleanup',
    0x0027: 'bCFGCaution',
    0x0028: 'KillDate',
    0x002b: 'ProcInject_StartRWX',
    0x002c: 'ProcInject_UseRWX',
    0x002d: 'ProcInject_MinAlloc',
    0x002e: 'ProcInject_Transform_x86',
    0x002f: 'ProcInject_Transform_x64',
    0x0031: 'BindHost',
    0x0032: 'UsesCookies',
    0x0033: 'ProcInject_Execute',
    0x0034: 'ProcInject_AllocMethod',
    0x0035: 'ProcInject_Stub',
    0x0036: 'HostHeader',
    0x0037: 'EXIT_FUNK',
    0x0038: 'SSH_Banner',
    0x0039: 'SMB_FrameHeader',
    0x003a: 'TCP_FrameHeader',
    0x003b: 'HeadersToRemove',
    0x003c: 'DNS_Beacon',
    0x003d: 'DNS_A',
    0x003e: 'DNS_AAAA',
    0x003f: 'DNS_TXT',
    0x0040: 'DNS_Metadata',
    0x0041: 'DNS_Output',
    0x0042: 'DNS_Resolver',
    0x0043: 'DNS_Strategy',
    0x0044: 'DNS_StrategyRotateSecs',
    0x0045: 'DNS_StrategyFailX',
    0x0046: 'DNS_StrategyFailSecs',
    0x0047: 'MaxRetry_Attempts',
    0x0048: 'MaxRetry_Increase',
    0x0049: 'MaxRetry_Duration',
}

# Console-display names for parser.py's TLV `type` values (1/2/3) -- the
# public JSON/CSV `fields[*].type` stays the plain integer (schema_version
# 2.7 deliberately does not change that), this is purely for the
# `--verbose` Full Config Field Table's own "Type" column.
CS_FIELD_TYPE_NAMES = {1: "uint16", 2: "uint32", 3: "bytes"}

# From 1768.py LookupConfigValue
CS_BEACON_TYPES = {
    0:  'HTTP',
    1:  'DNS',
    2:  'SMB (bind pipe)',
    4:  'TCP (reverse)',
    8:  'HTTPS',
    16: 'TCP (bind)',
}
CS_PROXY_TYPES = {
    1: 'no proxy',
    2: 'IE settings',
    4: 'hardcoded proxy',
}
CS_INJECT_PERMS = {
    0x01: 'PAGE_NOACCESS',      0x02: 'PAGE_READONLY',
    0x04: 'PAGE_READWRITE',     0x08: 'PAGE_WRITECOPY',
    0x10: 'PAGE_EXECUTE',       0x20: 'PAGE_EXECUTE_READ',
    0x40: 'PAGE_EXECUTE_READWRITE',
    0x80: 'PAGE_EXECUTE_WRITECOPY',
}

# score -> verdict_level, owned by this hunter (see dumpex.hunt._finding.verdict_level).
# A structurally-valid config (score 1) already reflects strong evidence —
# see the package docstring — so it maps to "likely", not "possible".
_VERDICT_LEVEL_BY_SCORE = {1: "likely", 2: "high"}
