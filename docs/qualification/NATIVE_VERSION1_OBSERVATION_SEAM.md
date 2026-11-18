# Version1 contract observation seam: software prerequisite only

This change puts current/archive observations behind one private stateless
method of the existing `PublishNewVersionHook`. Planning, preconditions,
before-effect checks, postvalidation, receipt inspection and prior/missing
receipt classification use that same instance method. Default Host reads,
build-only missing-root handling, error ordering, legacy module entry points
and the built-in factory retain their previous behavior.

The existing contract continues to own archive locations, state classification
and effect construction. Its archive-first, in-place update, `atomicity: none`
and 16 MiB bound remain unchanged. No additional journal, queue, operation owner
or document version system is introduced. Core lifecycle, registry, published
descriptors, schemas, provider selection and qualification guards are unchanged.

The method is a prerequisite for a future fixed native current/archive reader.
It is not a native observer, an authority grant or a public provider selector.
No request can select a replacement hook through this change. Pair observations
are sequential facts; they do not establish an atomic snapshot or pinned native
identities. No cache stores observations across hook calls.

Eight new Linux component tests use explicit synthetic pair facts directly at
the contract hook while forbidding POSIX I/O on an opaque target projection.
They exercise genuine ordinary Host Core, frozen inputs and evidence in
disposable roots for golden fixtures. They do not patch admission checks or
fabricate an admitted native Core installation. Existing Host lifecycle and
recovery regressions remain part of CI. At source preservation time these tests
have not run; the predicted suite is 1282 cases, including the one existing
platform skip. A later CI report must state the observed result.

Previous accepted Linux CI is run `40033599558` at
`ec6fc7151a338ed2681272af91525dca315c96f2`: both Python lanes had
1273 passed and one existing skip; all three jobs succeeded. See
`NATIVE_COMMAND_RESULT_BINDING_CI.md` for its exact artifacts and limitations.
That result does not apply automatically to the next commit.

| Remaining item | Status after this source change |
| --- | --- |
| Actual native current/archive observer and fixed role binding | Not implemented |
| Version1 worker, safe archive-parent creation and 16 MiB bounded handoff | Not implemented |
| Native pair identity/proof and independent inspect integration | Not implemented |
| First native Core create, receipt and fresh inspect | NOT_VERIFIED |
| A05 real Windows SYMLINK and G01 namespace lifetime | NOT_VERIFIED |
| Complete six-contract MIX qualification and full REF | NOT_VERIFIED |
| FULL, native CLI/MCP, historical compatibility and runtime rollback | NOT_VERIFIED |
| Supported NTFS release | Not permitted before mandatory acceptance |

Native integration remains authorized development work. Future observation must
bind both identities and revalidate them under the existing operation mutex.
Future payload transfer must reuse the same admitted reader/worker and bounded
frames with exact length, digest, ordering and deadline checks. These are not
claims demonstrated by the present refactor. A05 requires the separately
documented permitted isolated stand; no Windows policy changes are authorized.
Production Phase, Hermes, installed profiles and scientific data are unchanged.

Rollback of this software refactor is a normal code revert through the project
process; no new on-disk format is introduced. This statement is not a tested
native runtime rollback result. Existing documents and evidence must be retained.
