"""Minimal STATIC selector correlation only; never an accepted installation.

No roots/grants/composition/runtime authority are present. These bytes merely
let existing negative and transport-shell tests reach their intended boundary.
The real native qualification guard remains unmocked and refuses admission.
"""
from phase_tool.canonical import canonical_bytes,digest_bytes

def startup_shell():
    raw=canonical_bytes({'native_read_installation_version':'1.1',
        'registry_snapshot_digest':'sha256:2af8bac33feb42a583a14d6bff7b403de2ab0b63be3a962acc45807634a6ecca',
        'contract':{'id':'file_create.v1'}})
    return raw,digest_bytes(raw)
