# Original intent1.2: unselected native binding

This is structural integration in the existing Phase intent validator. It does
not enable a native provider, authorize dispatch, generate a new Core intent or
qualify NTFS. A05/G01, native Core receipt/inspect, six-contract MIX, FULL and
supported release remain NOT_VERIFIED. Production settings are unchanged.

The existing intent remains the sole operation record. Version1.2 adds one
closed native_binding: installation descriptor digest, composition/version/full
artifact-graph digest, one installed ext4 evidence identity and operation nonce.
Its one idempotency.root_identities table uses native device/VolumeGUID,32-bit
observed volume serial and full64-bit native serial/128-bit FileID/components.
It does not fabricate POSIX inode/device records or copy a second native table
into native_binding. These are bound claims; only a future trusted installation
and time-of-use observer can establish that they match the actual objects.

The new schema is selected only by its digest inside the exact contract package.
Its nested implementation_binding is the exact historical77db shape copied to
local definitions; all47refs are local. A changed current external schema cannot
silently change the new nested acceptance. Historical1.0/1.1 schema bytes and
validation paths remain unchanged. The first rejected draft with an external
nested reference is retained as unexecuted research, not a tested version.

A new file_create.v1@1.0.0 package generation pins this schema, while preserving
the original contract descriptor/mechanism/limits and all137previous registry
entries. Both new entries are current=False. Default file_create package remains
`e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870`.
Exact new package: `734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09`.
No trust root, current profile, registry selector or qualification guard changes.

pre_validator_binding_required explicitly requires saved raw prevalidator digest
for1.2, like1.1. Only1.0 retains its historical exemption; unknown1.3+ rejects.
Fourteen new unittest methods cover closed fields, fullnativeIDs/ranges, old
schema/default/descriptor preservation, oldpackage rejection, noexternalrefs,
replacement-current nested schema, duplicate/empty/legacyPOSIX roots and digest
requirements. Existing1.0/1.1 helper cases remain and1.2 is added explicitly.
Status before newHEAD CI: these new controls are SOURCE_REVIEWED, NOT_RUN.
They use synthetic structural data only and never grant native authority.

Next required pieces reuse existing lifecycle: checked-buffer original-intent
resolver, trusted immutable installation/artifact selector, root-wide original
intent scan under stable operational lock, existing worker/completion/retained
process owner, and existing observe_file wired to validators/independent inspect.
No second journal, queue, PENDING/FINALIZED system or document-version model.
Schema acceptance alone does not establish any of those pieces or permit GO.
