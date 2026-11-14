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

Intent validation selects the schema by its digest inside the exact contract
package. The new, distinct schema URI has one current schema generation for
normal discovery; this does not select a contract package or native provider.
Its nested implementation_binding is the exact historical77db shape copied to
local definitions; all47refs are local. A changed current external schema cannot
silently change the new nested acceptance. Historical1.0/1.1 schema bytes and
validation paths remain unchanged. The first rejected draft with an external
nested reference is retained as unexecuted research, not a tested version.

A new file_create.v1@1.0.0 package generation pins this schema, while preserving
the original contract descriptor/mechanism/limits and all137previous registry
entries. The schema entry is current=True at its new URI; the new contract
package stays current=False. Default file_create package remains
`e3231b5f97bb49c499a82fd1d003ddde081c9cbe31b7b10b87435526c1e15870`.
Exact new package: `734cf6905eba9e513c01654555d0a97edf05cd6e7da6cd2ec468e926cdbe8b09`.
No trust root, current profile, registry selector code or qualification guard changes.

pre_validator_binding_required explicitly requires saved raw prevalidator digest
for1.2, like1.1. Only1.0 retains its historical exemption; unknown1.3+ rejects.
Fourteen new unittest methods cover closed fields, fullnativeIDs/ranges, old
schema/default/descriptor preservation, oldpackage rejection, noexternalrefs,
replacement-current nested schema, duplicate/empty/legacyPOSIX roots and digest
requirements. Existing1.0/1.1 helper cases remain and1.2 is added explicitly.
At ccb98371 the14new structural methods passed on Python3.11 and3.12, but the
suite FAILED:1009PASS/2FAIL/1SKIP. The two existing integrity checks exposed a
zero-current generation for the distinct new schema URI. Exact negative ZIPs
and source are retained through officialPhase/ext4 with separate readback:
`g-ci-ccb9837-artifacts-1792664020127417100`, rawSHA256
`e25970fe6c9a2e173560b548af3c34d174bc215e238aa33fc814ded1ec713b80`, receipt
`b24a0204a238b230fe0ee59fe2444c7c028fb6a6481e979c8c503e4fe2fffb09`.
The workflow build/install smoke and resource steps were skipped. The internal
pytest wheel existed but was not retained in those ZIPs. This failed CI is not
acceptance of this correction or the further parser changes.

The unselected original-buffer parser checks canonical immutable original
intent/plan/prevalidator/frozen-input bytes and exact installed expectations.
Its result contains bytes/strings only and grants no authority. Existing POSIX
root validation remains first in validate_static_plan; only the pure logical
tail is shared. Saved builtin precondition semantics are extracted from the
existing recovery verifier and shared with this parser. The recovery reader,
exception mapping and historical1.0 exemption remain. No parallel validator,
evidence owner, journal or versioning system is introduced.

Rejected unexecuted parser drafts are preserved: an earlier pass-only check
missed code/expected/actual/time/observation semantics; the first extraction
contained an undefined name and lost the parser buffer bound. These were source
review findings before execution. The corrected parser checks immutable bounded
prevalidator bytes and uses the exact existing saved-result vocabulary.
New parser controls exercise rehashed malicious evidence, original hash domains,
full native roots, installed expectations, content links and immutable outputs.
First parser CI at4a0a72ad (workflow39763837068) FAILED on both Python versions:
1031total/1029PASS/1FAIL/1SKIP. Fourteen schema methods,18parser methods and both
previously failing registry-integrity checks passed. The remaining test failed
before its three installed-binding mismatch assertions: deepcopy(args) tried
to copy the registry's MappingProxyType and raised TypeError. Those subcases
were NOT_VERIFIED. The correction changes only that test's dictionary copy to
dict(args); decoded binding JSON is independent, assertions/product unchanged.
The negative run is preserved and independently inspectable:
`g-ci-4a0a72a-artifacts-1792666269046841100`, rawSHA256
`049839cdf82c72c98e2555f07b9997ff87cba793ee1806c8f87c621a8b7b8750`, receipt
`d9163502f0836ad463dfabbc27eef8751cb8976a8044d8f92b86c50231e9a0b5`.
Workflow build/installed smoke and resource steps were skipped; no accepted
package build resulted. First corrected-copy HEAD CI is PENDING. Older green
results do not accept the new tests. All data is synthetic structural claims;
none grants native authority or qualifies a Core route.

Next required pieces reuse existing lifecycle: actual durable-buffer reading
and trusted immutable installation/artifact selector, root-wide original
intent scan under stable operational lock, existing worker/completion/retained
process owner, and existing observe_file wired to validators/independent inspect.
No second journal, queue, PENDING/FINALIZED system or document-version model.
Schema acceptance alone does not establish any of those pieces or permit GO.
