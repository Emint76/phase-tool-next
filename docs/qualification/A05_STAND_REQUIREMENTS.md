# Minimum isolated environment for the outstanding Windows SYMLINK case

## Current verdict and human boundary

A05 is **NOT_VERIFIED**. This host has no supplied safe native Windows SYMLINK
fixture and no separate suitable stand. Both tested creation APIs returned 1314;
the available junction (0xA0000003) and LX_SYMLINK (0xA000001D) are distinct.
The human explicitly confirmed this and required the mandatory native SYMLINK
case to be performed before full qualification is claimed. Generic native
reparse tests do not replace that case. Development and independent tests continue.

No current Windows policy, privilege, ACL, Developer Mode setting, driver,
Docker/WSL setting, production mount or runtime is to be changed for this gap.

## Required stand

1. A disposable, independently authorized Windows installation with a fixed
   local NTFS volume and ordinary owned test directories. No production data,
   profiles, secrets, canonical volumes or network-mapped target. For direct
   applicability, reproduce the frozen Windows build, Docker Desktop/Engine,
   backend, kernel and mount transport of the campaign. A different stack needs
   its own manifest and repetition of all affected qualification cases; its
   result cannot automatically qualify this host.
2. A **non-elevated** synthetic fixture actor that can already create native
   Windows file and directory SYMLINKs. For example, an independently provisioned
   stand may already permit the documented unprivileged CreateSymbolicLinkW
   mode. Provisioning rights/policies is separate from this task. Phase itself
   must remain non-elevated; an elevated Phase runtime is not an acceptable fix.
   Alternatively, receive pre-created owned synthetic fixtures with proven
   identities and safely contained targets. Creation-dependent races still need
   an actor with the required capability; a static fixture does not cover them.
   Preflight must exercise the actual APIs required by each reached schedule.
   Unprivileged CreateSymbolicLinkW support alone does not prove that native
   SYMLINK metadata conversion via FSCTL is available to the same actor.
3. Native AMD64 Python matching the candidate's declared supported interpreter,
   the exact accepted Phase candidate and composite implementation artifacts,
   frozen dependencies, registry, profiles, grants and harness hashes. No
   installation into production Python or reuse of a production container.
4. At most two private test containers: nonroot, network none, read-only rootfs,
   cap-drop ALL, no-new-privileges, 2 CPU / 2 GiB RAM / 128 processes each. Mount
   only owned synthetic subroots. Use own qualified ext4 evidence/preparation
   and a separate read-only verifier. No Docker socket/device/privileged mount.
5. Ownership manifests, disjoint source/target/preparation/evidence roots,
   synthetic outside-of-target sentinels still inside the owned stand, and the
   original 32 GiB campaign cap. The A05 subset is small: enforce the reviewed
   small-case reserve of at least **4 GiB** on both host disks and ext4, and
   total small-stage storage **below 256 MiB**, before execution. This does
   not authorize boundary-size tests without their separate peak-space gate.

## Minimum replay and evidence

- Verify actual FILE_ATTRIBUTE_REPARSE_POINT and **tag 0xA000000C**, volume and
  full FileId for both Windows file and directory SYMLINKs before counting a
  case. Confirm the link's synthetic target independently. A dangling or failed
  creation is not a passed no-traversal test.
- Place fixtures at the leaf and each applicable parent position, including
  root replacement where required by A03/A05. Exercise the exact candidate's
  create, update, archive/object, bundle staging/commit, readback, inspect and
  permitted recovery paths. Unsupported NTFS source contours must fail explicitly.
- Use real reached schedules and the original repetition counts. Distinguish
  prevention, detection, kernel rejection, an effect confined to the original
  pinned object, and a missed race. Do not count a timeout or missing window as
  a pass. Keep the original Linux/junction/LX cases separate.
- Independently check native identities, named bindings, membership, all sentinel
  bytes/hashes and absence of outside creation/rename/delete. A post-check error
  cannot make an earlier outside effect safe; no failed binding may yield verified.
- Preserve positive and negative raw results through supported Phase/ext4,
  native receipt plus independent inspect/readback, exact build/environment
  identity and full observer logs. Retain the current 1314 counterexamples and
  NOT_VERIFIED rows rather than replacing them with later successes.

The output is a case-level A05 decision and an updated matrix for the exact
build/stack. It alone is not acceptance of MIX, FULL or the complete release.
