# Unselected native candidate registry

The native file-create candidate binds a different immutable contract generation
than the ordinary Host installation. Core already requires an exact current
generation before checking guarantees. A caller-selected exception would weaken
that check. This change adds one code-selected package resource instead:

`registries/native-file-create-candidate-v1.json`

Its raw and canonical SHA-256 is
`fa2a9aff5f576d15b5a71574a11bd3a7a994a38346540ff6d7e7a74335cfa2c7`.
Relative to the complete default snapshot it changes only two `current` flags:
`file_create.v1@1.0.0` generation `e3231b5f…` becomes inactive and generation
`734cf690…` becomes current in this new snapshot. All 139 entries, trust roots,
descriptors and pre-existing package-resource bytes remain otherwise identical.
The ordinary `data/registry.json` remains byte-identical, still selecting `e3231b5f…`.
The additional resource does not change the default snapshot digest.

The private loader in `installation.py` accepts no arguments. It reads only the
fixed bundled resource, verifies its raw hash and canonical bytes, selects the
exact expected contract and uses the existing resolver for trust, package,
dependency, schema and Core compatibility checks. It returns structural registry
data. It supplies no authority, qualification, loaded-code authentication,
installation selection or execution entry point. The default factory, CLI, MCP,
Core classes and existing generation/qualification checks are unchanged.

The tests distinguish the two actual Core refusals on owned Linux/ext4 fixtures:
the default snapshot rejects this generation; the candidate snapshot reaches
real root qualification and rejects the absent authority profile. Both use a
concrete ordinary `Installation` and `HostAuthorityProvider` with no successful
qualification or coverage mocks. Deliberately missing candidate/input files
ensure capture cannot silently replace the intended blocker. Core does reserve
the run and write its normal pre-intent rejection receipt. Assertions check the
exact blocker, lifecycle, absent intent and frozen blobs, untouched target, and
receipt inspected by a fresh Python process with the same implementation bytes
and exact snapshot. These are negative Core integration tests. Unavailable ext4
is skipped as NOT_VERIFIED; pure schema/resource tests never qualify a platform.

A future authenticated native composition must explicitly select this snapshot
and preserve the same evidence identity and all prior original intents. Changing
snapshot does not discharge history; the existing original-intent guard continues
to refuse unresolved or foreign bindings. No new journal, queue, PENDING/FINALIZED
store, receipt format, idempotency owner or document-version system is introduced.

Native provider composition, original 1.2 intent production through Core, dispatch,
independent native observation and final receipt closure remain unfinished.
G01, real Windows SYMLINK A05, positive native Core publication, MIX/FULL and
native-runtime rollback remain NOT_VERIFIED. This artifact is unselected and
does not make NTFS a supported environment. Initial native component controls
remain 2 MiB and its frozen file at most 1 MiB; no streaming/version/bundle or
Source/Knowledge/append/journal qualification is implied.
