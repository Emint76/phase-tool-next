# Original Core evidence reader (unselected component)

The native integration reuses the existing Core intent, effect plan, saved
pre-validator results, frozen input, idempotency and receipt/recovery lifecycle.
There is no additional journal, pending/finalized state or version history.

`mutation/ntfs/reader.py` reads four original buffers from the existing fixed
Core evidence layout. Only a future trusted installed endpoint supplies the
ext4 evidence root, immutable installed identity and RegistrySnapshot. An
external caller will provide only run ID and original profile intent digest;
this function is an internal read-only component, not that endpoint.

It reuses actual host root qualification, requires ext4, checks the installed
device/inode before and after reading, validates the exact package-bound1.2
schema and registry/profile identity before deriving the frozen blob path,
and reuses bounded regular-file reads. Plan/precondition raw hashes and blob
hash must match the original intent. The unchanged pure original-buffer parser
then owns complete candidate/effect/precondition/root/idempotency semantics.

The initial structural subset remains one copy-and-hash frozen input for
existing file_create.v1, <=1MiB with existing parents. Control buffers remain
<=2MiB. This introduces no contract or limit expansion and no bundle/version
support claim. The four returned buffers are immutable original bytes; no
EvidenceStore is constructed and no result or evidence file is created.

The component tests use clearly synthetic claimed intents in owned temporary
Linux/ext4 directories. They check exact four-buffer/parser roundtrip, early
closed input rejection, actual identity and schema/hash checks, limits,
nonregular files, Linux links, missing data and a deterministic replacement
of the owned evidence root after the last read. The actual root qualification
is not replaced by a successful mock. An unavailable actual ext4 environment
is SKIP/NOT_VERIFIED. These fixtures are not real executed Core intents,
Windows SYMLINK qualification or evidence of an admitted native installation.

Source review precedes first execution. At this source checkpoint the new
reader tests are unexecuted; their exact HEAD CI results must be recorded
separately. Previous HEAD4820f6f5 Linux CI39767106576 passed all three jobs,
each Python1030PASS/1SKIP, with all19 original-buffer parser and14 native
intent schema methods. The old results do not accept the changed candidate.

Root/path fingerprints and matching bytes establish consistency in the owned
fixed evidence namespace. They do not prove hostile-namespace fencing, remote
Docker identity, loaded executable bytes, durability or current-invocation
authority. Remaining work includes a trusted immutable installation/bootstrap
and artifact graph, fixed read-only transport, invocation/root locking and
root-wide unresolved-original-intent checks, native observation/GO and Core
dispatch/receipts. No parallel coordinator or recovery store is needed.

Qualification guard, defaults and historical descriptors remain unchanged.
A05/G01, native Core create/update/bundle, MIX/FULL and native runtime rollback
remain NOT_VERIFIED. No supported NTFS release or Hermes production activation.
