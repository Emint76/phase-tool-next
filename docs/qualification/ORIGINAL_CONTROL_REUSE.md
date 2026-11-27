# Shared read-only original controls

Implementation checkpoint; native admission, A05/G01, complete MIX, FULL and
release remain NOT_VERIFIED. No production runtime or Hermes change.

## Existing duplication and smallest change

The original endpoint first read intent, plan, saved validators and the entire
payload, discarded that payload, and then called the mandatory installed
binding.read/validate_planned, which repeated the full read and semantic parser.
A private reader._read_original_control_buffers now returns exactly the first
three original immutable buffers. Both the full reader and the endpoint's
initial nonce/control observation use that same read-only helper.

It retains Linux/ext4/root-identity and canonical native1.2/run/profile/registry/
installed-evidence-identity/single copy_and_hash/blob-digest checks. Each control
retains its2MiB bound; raw plan/pre hashes and a fresh actual root check precede
return. Executing uses pre-validator-results.json; planned uses the historical
validator-results.json, with no fallback. No blob bytes, ParsedNative tuple,
content assertion, worker, GO or authority are returned by the control helper.

The full reader still checks its closed1MiB/file1 or16MiB/version1 role bound
before I/O. It derives the blob solely from that validated original, checks the
actual root again immediately before and after the bounded blob read, verifies
the actual bytes, and returns the historical four-buffer tuple. The unchanged
full intent parser still owns all semantic plan, saved-precondition, candidate,
content, root and installed implementation checks.

Endpoint nonabsent branches still call the same mandatory binding.read or
validate_planned with the SAME expected intent digest before returning any
handoff/verification. Final installed-root/runtime checks remain. Query1.0/1.1/
1.2 formats, role selection, actual original-reader EOF/exit before worker spawn/
READY/GO, Core receipts/idempotency/recovery and all fixed limits are unchanged.

## Error ordering and test boundary

Valid outputs and single-fault error codes are compatibility oracles. Multiple
simultaneous faults may report earlier: wrong invocation nonce plus corrupt blob
now reports nonce before the later full read; invalid plan/pre plus missing or
corrupt blob now reports control hash mismatch before blob I/O. No alternate
diagnostic is reported as success. Valid controls alone can exist with a missing
blob and cannot produce full read bytes, parsed handoff or GO.

Tests use disposable actual qualified ext4 fixtures with no qualification mock,
plus existing pure semantic/query controls. They check exact3control/4full reads,
fixed caps and output bytes, planned/executing filenames and no fallback, missing
blob versus control-only output, control corruption precedence, root replacement,
and version1 payload beyond file1 scope through the unchanged full parser.
Selected positive native endpoint execution remains NOT_VERIFIED. Source review
and ordinary Linux tests do not establish Windows namespace/lifetime guarantees.

## Streamed native file2 remains separate

The existing original-reader contour has every mount read-only. Creating the
Host helper's TemporaryFile(dir=blob.parent) there would violate that role.
Transfer1.1 buffers complete version1 bytes and establishes actual reader exit
before worker spawn; it is not a2GiB transport. This change adds no snapshot,
RW-reader mount, fallback path, spool, iterator, class, public API, wire, provider,
profile, guard, journal, queue, receipt owner or document-version mechanism.

A future bounded file2 implementation must separately resolve a Core-owned
verified same-input lifetime, trusted original checks, cross-OS chunks/backpressure,
one local protocol deadline, one worker/GO, input verification before target
acquisition/mutation and actual producer/worker finalization. A Linux FD cannot
be inherited as a Windows HANDLE; matching header/end hashes alone prove none
of these properties. Unknown outcomes must retain the original Core guard.
