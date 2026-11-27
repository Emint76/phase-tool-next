# Installed Version v2 and Core conflict checks

These physical Windows checks used separate, owned synthetic NTFS roots, the
common launcher, and the exact CI135 wheel
f04ff3ed57d8d77bc11e46eb87d05639e7cf292c2bda5129db518e0390d953a5.
This is the physical artifact scope. The later CI138 wheel differs in the
prepared-recovery terminal capture helper and RECORD. Its recovery result
is documented separately.

## Version v2

One CLI publish_new_version.v2 execution succeeded. A separate genuine MCP
SDK client initialized, discovered the tool and called phase_inspect once.
It returned target_verified=true with the same typed receipt, intent and plan.

| Evidence | Digest |
|---|---|
| Receipt | sha256:5b805681d70dde17f439c32a1dcb1163cbdb88201506c13a0558c82204409fe8 |
| Intent | sha256:63445dd587ffb36ee58ac30e40ae4a36418d9d557ec4338084a05e5b7e4cd98e |
| Effect plan | sha256:05d46cd65bb9ca7c9ef09520f6691dac2fac384656552172048f85c632956d69 |
| Native proof attachment | sha256:9e8180445defb8dd96a51be1dad2309a434797860c73dd3efccfa168f0b11cee |

The read-only collector verified the complete 39-byte old object, 38-byte new
object and 38-byte current file. Current matched the new object. It compared
Full128 identities of the three files and their bound roots, confirmed three
recorded renames and 115 bytes of writes, and checked exit 0 on the retained
worker creation handle. The independent saved-evidence audit
9818fee84caa5a1de5555664012b4071b38a2f88f737f0c9b37608a1eb1581a2
recomputed the raw and typed digests from the saved evidence.

## Expected rejections

Each negative returned CLI exit 10, an original rejection receipt, no intent
or effect plan, and no attempted mutation. The terminal proof showed no worker
dispatch. Read-only checks compared complete contents and recorded NTFS
identities before and after. The successful create and update in the repeated
key case were each inspected before the third request. Their original evidence
and archived version remained intact.

| Synthetic case | Sole blocker | Receipt |
|---|---|---|
| Create with an occupied destination | target.destination_exists | sha256:a53306b309ed5ecf97f0d2b84e67c30bf01092eb9d91eae25cf7e82fd36d3600 |
| Update with a stale expected digest | publish.state_conflict | sha256:f30681cfa7bdf4be6ece3cc126583a348ffa866ac23ecb362dd8a29dc08f77de |
| Same key with changed inputs after a successful update | idempotency.same_key_conflict | sha256:87adac39ef21228237fa349b4cf1bc51ecc92d09d77f1340beb033eebd7202a2 |

A05, G01, MIX and FULL remain NOT_VERIFIED. No supported release or
production rollout follows. Full originals and reproduction bindings are
retained privately.
