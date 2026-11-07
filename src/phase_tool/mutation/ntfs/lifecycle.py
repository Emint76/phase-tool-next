"""DRAFT private wrapper around the ONE existing Core lifecycle.

Not installed/imported/executed. The full fixed bootstrap/parent/proof/closure
slice is still pending source review. No new journal, queue, recovery owner or
target operation lives here. Native admission precedes the existing lifecycle.
"""
from __future__ import annotations

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes, profile_digest
from ...errors import PhaseError
from .native import _error_record, _require



def _keep_native_primary(context,error,secondary):
    """Pure causal ordering; never a provider, state store or recovery owner."""
    prior=context.broker_interruption
    if prior is None:return error
    if error is not prior and not any(error is saved for saved in secondary):
        secondary.append(error)
    return prior


def _run_native_file_create(core, request, *, execute, faults):
    from ...core import _NativeRunContext
    from ...installation import _NativeFileCreateInstallation
    from .uncertainty import _NativeLifecycleUnresolved
    installed = core.installation
    _require(type(installed) is _NativeFileCreateInstallation,
        'ntfs.closed_native_installation_required')
    # No GO or native I/O can occur before this exact admission.
    installed.admit(core.registry, request, execute=execute, faults=faults)
    authority = installed.authority
    context = _NativeRunContext(native_authority=authority)
    secondary = []
    try:
        return _run_admitted(core, request, execute=execute, context=context, secondary=secondary)
    except BaseException as primary:
        # Covers lock/worker/validation AND proof/receipt publication failures,
        # including a visible receipt whose final durability acknowledgement failed.
        raise _NativeLifecycleUnresolved(request=request, context=context,
            authority=authority, primary=primary, secondary=secondary) from primary


def _run_admitted(core, request, *, execute, context, secondary):
    from ...core import PhaseOutcome, _NativeRunContext, _guard_native_original_intents
    from ...evidence import validate_receipt, _write_native_canonical
    from ...installation import _NativeFileCreateInstallation
    from .proof import make_native_terminal_proof, verify_native_terminal_proof

    installed = core.installation
    _require(type(installed) is _NativeFileCreateInstallation,
        'ntfs.closed_native_installation_required')
    # This is a closed installation check, not a provider/qualification callback
    # supplied by a request. Candidate profiles refuse even empty requirements.
    authority = installed.authority
    primary = None
    outcome = None
    try:
        with _guard_native_original_intents(installed.read_binding,history_bindings=installed.history_bindings):
            try:
                outcome = core._run_lifecycle(request, execute=execute, native_ctx=context)
                # Core may prepare an indeterminate terminal from interruption.
                # Keep its original cause ahead of the later inevitable seal
                # failure; a secondary cleanup error must not replace it.
                if context.broker_interruption is not None:
                    primary=context.broker_interruption
            except BaseException as error:
                primary=_keep_native_primary(context,error,secondary)
            finally:
                try:
                    authority.seal(intent_digest=context.original_intent_digest)  # One attempt; a failed check is not a seal fact.
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        secondary.append(error)
            if primary is not None:
                raise primary
        # Only after the context manager's real __exit__ completed successfully.
        context.common_guard_finalized = True
    except BaseException as error:
        if primary is not None and error is not primary:
            secondary.append(error)
        else:
            primary = error

    if not authority._seal_attempted:
        try:
            authority.seal(intent_digest=context.original_intent_digest)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                secondary.append(error)
    physical = None
    if authority._seal_attempted:
        try:
            physical = authority.prepared_physical_proof()
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                secondary.append(error)
    if primary is not None:
        # No receipt is published over unknown worker, namespace or checked-exit
        # facts. Keep the original and existing Core attachments unresolved. The
        # caller receives bounded diagnostic facts for its approved evidence path;
        # do not perform a fallback write after losing evidence ownership.
        raise primary

    _require(context.prepared is not None and outcome is not None
        and context.common_guard_finalized and physical is not None
        and physical['local_channel_sealed'] is True,
        'ntfs.native_terminal_not_prepared')
    _require(not context.idempotency_enter_started or context.idempotency_finalized,
        'ntfs.native_idempotency_finalization_unknown')
    prepared = context.prepared
    # A recorded execution original is not discharged by an absence claim or a
    # client seal. Require either all executed-worker facts OR a no-worker ACK
    # from the same parent whose sole unused GO slot was irreversibly consumed.
    # Neither is a request flag, and neither downgrades an unknown dispatch.
    _require(physical['server_ingress_sealed'] is True
        and (physical['parent_safety_established'] is True
            or physical['no_dispatch_safety_established'] is True),
        'ntfs.native_parent_completion_unresolved')

    store = context.store
    _require(store is not None and not context.proof_publication_attempted
        and not context.publication_attempted, 'ntfs.native_terminal_publication_consumed')
    proof = make_native_terminal_proof(installed.read_binding, request, prepared,
        physical=physical,
        idempotency={'enter_started': context.idempotency_enter_started,
            'entered': context.idempotency_entered, 'finalized': context.idempotency_finalized},
        common_guard_finalized=context.common_guard_finalized)
    # Two artifacts in the existing EvidenceStore: ONE proof and ONE receipt.
    # Never overwrite either object, acknowledge a visible-but-unconfirmed link,
    # try a downgraded second receipt, or retry a native target effect.
    context.proof_publication_attempted = True
    _, proof_digest = _write_native_canonical(store,installed.read_binding,'attachments/native-terminal-proof.json',proof)
    receipt = parse_json_bytes(canonical_bytes(prepared.receipt))
    receipt['evidence']['attachment_digests'] = sorted(set(
        receipt['evidence']['attachment_digests'] + [proof_digest]))
    # Preserve Core's completeness fact. A proof cannot repair missing effect
    # or validator attachments, even when its own publication succeeds.
    validate_receipt(receipt, core.registry)
    # Verify the complete current dependency set BEFORE the one receipt write.
    # The existing readonly verifier accepts the constructed receipt, reads the
    # published proof and immutable dependencies, and performs no fsync/write.
    # EvidenceStore holds the same owned attachments identity across both writes.
    verify_native_terminal_proof(installed.read_binding,store.run_root,receipt)
    context.publication_attempted = True
    _write_native_canonical(store,installed.read_binding,'receipt.json',receipt)
    return PhaseOutcome(prepared.run_id, receipt['exit_code'], receipt,
        prepared.intent, prepared.effect_plan, prepared.lifecycle,
        profile_digest('receipt', receipt), prepared.effect_plan_digest)
