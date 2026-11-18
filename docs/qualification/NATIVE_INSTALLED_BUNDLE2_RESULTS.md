# Installed Bundle2: normal publication result

A disposable Windows NTFS experiment completed one genuine MCP `execute_prepared` call through the existing Core, followed by a fresh SDK/MCP `inspect` call. The accepted build was HEAD `dcfcc6a7609d9b1d12b0515e4f16c03ad146830d`, wheel SHA-256 `c0735b2d5622245162b4aa18171b7a20c992b29b239d5ef52483562ce9babc14`, using `bundle_create.v2@1.2.1` and the existing native installation contract 1.9.

Both calls returned `success=true`, `terminal_status=succeeded_verified` and the same receipt: `sha256:78b78a198ee4b43c8f882e72383c727740d7f6cd68dcd64595c4be666bdb5eb3`. The execute result retained `target_verified=null`; it did not assert independent target verification. The fresh inspect result returned `target_verified=true`. Both original SDK calls completed with captured pipes and closed SDK contexts. Context closure and SDK exit are separate from native-worker evidence.

The closed evidence and subsequent HOST audit establish the following within this one experiment:

- Complete bytes for 23 ext4 evidence/input files and eight NTFS regular files, including two 262,181-byte payload files and zero-length members, matched their recorded hashes. Full 128-bit file identities bind the captured regular files, admitted results root and published target directory. The nested directory identity was not separately emitted by the additional census.
- Receipt, intent and effect-plan domain digests matched the exact captured control bytes and the real current-wheel read-only proof-verifier result. All frozen blobs, prepared candidate/payload bytes and original attachments were checked.
- The retained creation HANDLE established worker exit zero through eight recorded API calls, including the wait and exit-code checks; worker pipes and the HANDLE closed. The complete physical trace contained 26 events and a real PREPARED/ACK lineage.
- Exactly one directory publication used NOREPLACE semantics, information class 10 and flags zero, followed by a successful parent namespace flush. Six acknowledged `WriteFile` calls totalled 525,267 bytes, derived from the two payload bodies, bundle manifest and canonical owner record.

The original outer inspect harness result remains a negative artifact: SHA-256 `0d90c6845eff72d3ff4df0ea2841bcbdb13fdf49e88b78edd67c29c9750150f8`. After the genuine positive SDK response had been captured, its extra target census passed 65,536 as the `NativeIO.read_chunks` maximum and raised `ntfs.read_limit` on a larger file. This was a harness oracle error. The product and original result were unchanged.

A separate read-only adjudication used each already bounded file length as that maximum, completed the full byte/identity census and collected the original proof through the existing read-only container. It did not repeat Core publication, the mutation worker or either SDK call. Adjudication evaluation SHA-256: `195d5a8196ec775be1525301a3e338f90593b575ed698466f4962028da82f0a9`. Native-proof attachment SHA-256: `12e8b0d145853437a615d2a99c2ce884cf3a24a71a4a0a1e2dd656b247a031d7`.

The independent HOST-only audit passed with report SHA-256 `726e690aabb0f64d847e0cfdeb6450dd41680cca869baa7e96f3e20a883f5415`. It compared the complete retained captures, bytes, identities, domain digests and trace; it did not rerun NativeIO or the proof verifier. The actor and reviewer shared a host, model and toolchain, so this is corroboration of retained evidence rather than independent authentication against a privileged producer.

This is one experimental normal Bundle2 publication. It does not establish full qualification, security or scientific validity, A05/G01, release readiness, six current physical branches or ordinary prepared-recovery acceptance. Complete private evidence, including the original negative and correction, must be retained before public delivery; this local report remains pending that delivery gate.
