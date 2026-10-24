# Native file1 preparation: candidate software only

This change prepares literal file-create input for the existing fixed native
Core entrypoint. It does not qualify NTFS, implement the high-level
PublishFileResult API, or establish an accepted launcher. A05 and G01 remain
NOT_VERIFIED. An unqualified profile still refuses before source/scratch I/O.

The new closed request has exactly these fields:

```json
{
  "operation": "execute",
  "native_file_publication_request_version": "1.0",
  "source_locator": "incoming/synthetic.bin",
  "target_locator": "synthetic/output.bin",
  "request_id": "synthetic-request",
  "expected_digest": null
}
```

The source namespace is the fixed installation's preparation root on qualified
ext4. No arbitrary source, evidence, preparation or target root is accepted in
the request. The file1 bound remains 1 MiB. Target projections stay lexical:
Linux preparation does not resolve, stat, open or lock an NTFS target.

The existing installation checks the real profile, root identities, ext4,
ownership/modes, descendant mounts and disjoint roots before preparation. Normal
Core admission repeats these checks against its actual prepared request. The
shared checker is on the same installation; it creates no second factory,
admission flag, cached qualification or lifecycle.

Preparation reuses copy_and_hash, revalidate_frozen and the existing canonical
candidate builder. Core receives prepared paths, expected payload digest/length
and exact expected candidate bytes. Core still owns capture, original intent,
idempotency, locking, effects, receipt and recovery. The preparation catch ends
before Core is invoked. Later failure and uncertainty remain the original Core
result, with the existing parent responsible for process/pipe finalization.

Scratch remains available as prepared input on failure or uncertainty. There is
no automatic cleanup, outcome journal, replay worker or retry path in this
wrapper. Existing evidence inspection and original-intent barriers remain
mandatory before any further operation. Namespace checks are point-in-time;
their lifetime protection depends on G01, which this change does not prove.

The original five-field prepared request, raw CommandResult and outer
phase.native.command version 1.0 envelope are unchanged. This new request returns
the raw execute result; it cannot claim high-level publication verification.
Fresh inspect uses the existing separate read-only invocation. A bounded,
explicitly versioned literal publication-facts projection and the high-level
Windows/MCP adapter remain unfinished. Native file2 and bundle entrypoints are
also unfinished. No published descriptor, historical binding or receipt schema
is changed by these preparation sources.

New tests are negative software components using static selector/stdio shells.
The real qualification guard is never mocked. They exercise both static registry
generations, refusal before preparation/Core/channel, closed request grammar,
the distinct version name, and rejection of an ordinary Host installation.
They establish neither G01 nor positive native execution. Source review and AST
parsing are not execution; the tests require exact-HEAD CI acceptance.
