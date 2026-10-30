"""Existing Core recovery owner for the closed native B2 successor.

No original writes, POSIX target access, new journal, retries or receipt repair.
The common evidence guard and original Prepared/Binding/Continuation formats
remain the owners. Windows alone owns the remaining native effect.
"""
from __future__ import annotations
from pathlib import Path
import os
import threading

from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from ...errors import PhaseError
from .native import _require
from .bundle_recovery_original import (select_original,verify_original,verify_quiescence,
    verify_trace,verify_physical_closed,native_inventory,_wire)
from .bundle_recovery_worker import recovery_context,validate_recovery_ready


class _NativeCommitCheckpoint:
    """The existing Core's one durable continuation/readback BEFORE recovery GO."""
    def __init__(self,store,binding,original,context):
        self.store,self.binding,self.original,self.context=store,binding,original,context
        self.prepared=original['prepared'];self._attempted=False
        self.owner=os.getpid(),threading.get_ident();self.continued=None

    def persist(self,ready):
        from ...continuation import ContinuationIntent,validate_record_schema
        from ...evidence import _write_native_recovery_canonical
        _require(self.owner==(os.getpid(),threading.get_ident()) and not self._attempted,
            'recovery.continuation_consumed')
        self._attempted=True
        _require(self.context['mode']=='commit_prepared','recovery.closed_commit_role_required')
        validate_recovery_ready(ready,context=self.context,projection=self.original['projection'],
            prepared=self.prepared,expected_pid=ready['pid'])
        intent=self.original['intent'];effect=self.original['plan']['effects'][0]
        self.continued=ContinuationIntent(original_intent_digest=self.context['intent_digest'],
            preparation_digest=self.context['preparation_digest'],run_id=intent['run_id'],
            request_id=intent['idempotency']['key'],effect_plan_digest=intent['effect_plan_digest'],
            contract=intent['contract'],target=effect['target'],device=self.prepared['device'],
            inode=self.prepared['inode']).model_dump()
        validate_record_schema(self.binding.registry,self.original['contract'],
            'schemas/continuation-intent.schema.json',self.continued)
        path,_digest=_write_native_recovery_canonical(self.store,'commit-intent.json',self.continued)
        from ...recovery import read_record
        _require(read_record(path)==self.continued,'recovery.continuation_conflict')
        return {'native_recovery_go_version':'1.0','context':self.context,
            'ready_digest':digest_bytes(canonical_bytes(ready))}


def verify_completion(parent,original,context):
    from .bundle_execution import _validate_bundle_content,_bundle_projection_value
    _require(type(parent) is dict and set(parent)=={'native_recovery_parent_version','context',
        'completion','completion_wire','process_witness','owner_finalization','operation_primary','go_attempted'}
        and parent['native_recovery_parent_version']=='1.0' and parent['context']==context
        and parent['operation_primary'] is None and parent['go_attempted'] is True,
        'recovery.native_parent_incomplete')
    completion=parent['completion'];raw=_wire(parent['completion_wire'])
    _require(type(completion) is dict and set(completion)=={'native_recovery_completion_version','context',
        'pid','ready','after','mutation_attempted','rename','parent_identity','namespace_flushed','mutation_trace',
        'mutex_events','mutex_state','mutation_session_state','remaining_handle_count',
        'unproven_handle_ownership','handle_finalization','primary_error','finalization_errors'}
        and canonical_bytes(completion)==raw and completion['native_recovery_completion_version']=='1.0'
        and completion['context']==context and type(completion['pid']) is int,
        'recovery.native_completion_mismatch')
    verify_quiescence(parent,completion);verify_physical_closed(completion)
    _require(completion['primary_error'] is None,'recovery.native_effect_failed')
    projection=original['projection'];value=_bundle_projection_value(projection)
    ready=validate_recovery_ready(completion['ready'],context=context,projection=projection,
        prepared=original['prepared'],expected_pid=completion['pid'])
    trace=verify_trace(completion)
    renames=[row for row in trace if row.get('api')=='NtSetInformationFile']
    if ready['selected']=='stage':
        rename=completion['rename']
        _require(len(renames)==1 and rename==renames[0] and rename['class']==10
            and rename['replace_if_exists'] is False and type(rename['rename_flags']) is int
            and rename['rename_flags']==0 and rename['return_status']==rename['io_status']=='0x00000000'
            and rename['effect_state']=='committed'
            and rename['source_identity']==ready['native']['native_identity']
            and rename['parent_identity']==completion['parent_identity']
            and rename['leaf']==value['effect']['target']['relative_locator'].split('/')[-1],
            'recovery.native_rename_unproven')
    else:
        _require(renames==[] and completion['rename'] is None,'recovery.native_rename_repeated')
    _require(completion['mutation_attempted'] is True and completion['namespace_flushed']==['target_parent'],
        'recovery.native_flush_unproven')
    flushes=[row for row in trace if row.get('api')=='NtFlushBuffersFileEx' and row.get('kind')=='directory']
    _require(len(flushes)==1 and flushes[0].get('accepted') is True
        and flushes[0].get('return_status')==flushes[0].get('io_status')=='0x00000000'
        and flushes[0].get('flags')==0 and 'post_observation_error' not in flushes[0]
        and flushes[0].get('object_identity')==completion['parent_identity'],
        'recovery.native_flush_unproven')
    after=completion['after']
    _validate_bundle_content({'known':True,'exists':True,'digest':projection.content_digest,
        'length':projection.content_length,'head_token':None},after,value['grant'],projection=projection)
    _require(after['native_identity']==ready['native']['native_identity']
        and after['stat_identity']=={'device':original['prepared']['device'],'inode':original['prepared']['inode']},
        'recovery.preparation_mismatch')
    return after


def _expected_continuation(original):
    from ...continuation import ContinuationIntent
    intent=original['intent'];prepared=original['prepared']
    return ContinuationIntent(original_intent_digest=profile_digest('intent',intent),
        preparation_digest=digest_bytes(canonical_bytes(prepared)),run_id=intent['run_id'],
        request_id=intent['idempotency']['key'],effect_plan_digest=intent['effect_plan_digest'],
        contract=intent['contract'],target=original['plan']['effects'][0]['target'],
        device=prepared['device'],inode=prepared['inode']).model_dump()


def verify_saved_recovery(binding,original):
    """Immutable lineage only. Fresh target verification is a separate operation."""
    from .bundle_recovery_original import _record as read_record
    directory=original['run']/'recovery';proof=read_record(directory/'native-commit-proof.json')
    _require(type(proof) is dict and set(proof)=={'native_bundle_recovery_proof_version','original_intent_digest',
        'effect_plan_digest','installation_digest','registry_snapshot_digest','original_files','operation',
        'recovery_context','parent_response','observation','common_guard_finalized'}
        and proof['native_bundle_recovery_proof_version']=='1.0'
        and proof['original_intent_digest']==profile_digest('intent',original['intent'])
        and proof['effect_plan_digest']==original['intent']['effect_plan_digest']
        and proof['installation_digest']==binding.manifest_digest
        and proof['registry_snapshot_digest']==binding.registry.digest
        and proof['common_guard_finalized'] is True,'recovery.native_proof_mismatch')
    from jsonschema import Draft202012Validator
    schema=binding.registry.schema_document('https://phase-tool.local/schemas/native-bundle-recovery-proof-1.0.schema.json')
    Draft202012Validator(schema,registry=binding.registry.schema_registry()).validate(proof)
    original_files={n:list(v)for n,v in original['files'].items() if not n.startswith('recovery/')}
    _require(proof['original_files']==original_files,'recovery.original_changed')
    if proof['operation']=='commit_prepared':
        context=recovery_context(proof['recovery_context'])
        verified=verify_completion(proof['parent_response'],original,context)
        from .bundle_execution import _bundle_projection_value,validate_bundle_observation
        projected=_bundle_projection_value(original['projection'])
        observed=validate_bundle_observation(proof['observation'],projected['grant'],
            projected['effect']['target']['relative_locator'],projection=original['projection'])
        _require(canonical_bytes(observed['native'])==canonical_bytes(verified),'recovery.worker_observer_mismatch')
        _require(read_record(directory/'commit-intent.json')==_expected_continuation(original),
            'recovery.continuation_conflict')
        expected={'continuation_receipt_version':'1.0','original_intent_digest':proof['original_intent_digest'],
            'preparation_digest':digest_bytes(canonical_bytes(original['prepared'])),
            'continuation_intent_digest':digest_bytes(canonical_bytes(_expected_continuation(original))),
            'status':'verified_existing','target_verified':True,
            'effect_plan_digest':original['intent']['effect_plan_digest']}
        _require(read_record(directory/'commit-receipt.json')==expected,'recovery.continuation_conflict')
    elif proof['operation']=='observe':
        from .bundle_execution import validate_bundle_observation,_bundle_projection_value
        value=_bundle_projection_value(original['projection'])
        observed=validate_bundle_observation(proof['observation'],value['grant'],
            value['effect']['target']['relative_locator'],projection=original['projection'])
        verified=observed['native']
        _require(proof['parent_response'] is None and proof['recovery_context'] is None,
            'recovery.native_proof_mismatch')
    else:raise PhaseError('recovery.native_proof_mismatch')
    _require(verified['stat_identity']=={'device':original['prepared']['device'],
        'inode':original['prepared']['inode']},'recovery.preparation_mismatch')
    return proof,verified


def recover_native(application,authority,*,evidence_root,run_id,target_root,request_id,expected_intent_digest,mode='observe'):
    from ...application import ApplicationResponse
    from ...recovery import NativeRecoveryResult
    from ...core import _guard_native_original_intents
    from ...evidence import (_open_native_recovery_store,_close_native_recovery_store,
        _write_native_recovery_canonical)
    from .experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3
    from .bundle_execution import _bundle_projection_value
    _require(type(authority) is _ExperimentalBundle2AuthorityV3,'recovery.closed_native_role_required')
    result=NativeRecoveryResult(run_id=run_id,request_id=request_id,recovery_mutation_attempted=False,
        recovery_mode=mode if mode in {'observe','commit_prepared'} else 'observe');store=None;original=None
    binding=authority.read_binding;manifest=parse_json_bytes(binding.manifest_bytes)
    try:
        _require(mode in {'observe','commit_prepared'} and not authority._inspection_only
            and run_id==authority._run_id and Path(evidence_root)==Path(manifest['evidence_root'])
            and str(target_root)==manifest['root_projections']['phase_result_root'],
            'recovery.closed_native_role_required')
        selection=select_original(binding,run_id,request_id,expected_intent_digest)
        after=parent=observation=context=None;previous=None
        with _guard_native_original_intents(binding,_recovery_selection=selection):
            original=selection.check(Path(evidence_root)/'.phase/runs'/run_id)
            intent=original['intent'];value=_bundle_projection_value(original['projection'])
            result.intent_digest=expected_intent_digest;result.effect_plan_digest=intent['effect_plan_digest']
            receipt=original['original_receipt']
            result.original_receipt_digest=None if receipt is None else profile_digest('receipt',receipt)
            result.original_terminal_status=None if receipt is None else receipt['terminal_status']
            store=_open_native_recovery_store(binding,run_id)
            directory=original['run']/'recovery'
            if (directory/'native-commit-proof.json').exists():
                previous,after=verify_saved_recovery(binding,original)
                result.commit_finalization_verified=True
            elif directory.exists():
                # An earlier continuation without complete proof has unknown GO
                # delivery/outcome. It never grants another worker or rename.
                _require(not any(path.name in {'commit-intent.json','commit-receipt.json'}
                    for path in directory.iterdir()),'recovery.previous_dispatch_unresolved')
            if mode=='observe' or previous is not None:
                observation=authority.observe(run_id=run_id,root_binding='phase_result_root',
                    locator=value['effect']['target']['relative_locator'],
                    expected_identity=original['parent']['completion']['physical_evidence']['stage_identity'])
                from .bundle_execution import validate_bundle_observation
                observed=validate_bundle_observation(observation,value['grant'],value['effect']['target']['relative_locator'],
                    projection=original['projection'])
                after=observed['native']
                _require(after['stat_identity']=={'device':original['prepared']['device'],
                    'inode':original['prepared']['inode']},'recovery.preparation_mismatch')
                result.recovery_mutation_attempted=False
            else:
                context={'native_recovery_context_version':'1.0','run_id':run_id,
                    'intent_digest':expected_intent_digest,'effect_plan_digest':intent['effect_plan_digest'],
                    'installation_digest':binding.manifest_digest,'operation_nonce':authority._operation_nonce,
                    'channel_id':authority.channel.channel_id,'original_operation_nonce':value['context']['operation_nonce'],
                    'preparation_digest':digest_bytes(canonical_bytes(original['prepared'])),'mode':'commit_prepared'}
                checkpoint=_NativeCommitCheckpoint(store,binding,original,context)
                # Unknown dispatch stays nullable, never coerced to false/true.
                result.recovery_mutation_attempted=None
                result.recovery_effect_state='unknown'
                authority._dispatch_attempted=True
                from ..broker import EffectBroker
                parent=EffectBroker(binding.registry,None,authority.profile,_native_authority=authority).resume_prepared_bundle(
                    original['plan'],original['contract'],original['run']/'intent.json',Path(target_root),
                    expected_intent_digest,_native_checkpoint=checkpoint)
                after=verify_completion(parent,original,context)
                observation=authority.observe(run_id=run_id,root_binding='phase_result_root',
                    locator=value['effect']['target']['relative_locator'],expected_identity=after['native_identity'])
                from .bundle_execution import validate_bundle_observation
                observed=validate_bundle_observation(observation,value['grant'],
                    value['effect']['target']['relative_locator'],projection=original['projection'])
                _require(canonical_bytes(observed['native'])==canonical_bytes(after),'recovery.worker_observer_mismatch')
                result.recovery_mutation_attempted=parent['completion']['mutation_attempted']
                result.commit_finalization_verified=True
            authority.channel.seal()
            authority._server_ingress_sealed=True
            # Original immutable bodies must still match before leaving the one
            # common guard. Added recovery records are separate code-owned leaves.
            current=native_inventory(binding,original['run'])
            _require({n:v for n,v in current.items()if not n.startswith('recovery/')}==
                {n:v for n,v in original['files'].items()if not n.startswith('recovery/')},'recovery.original_changed')
        # A failed common-lock release cannot publish a positive recovery proof.
        from ...continuation_progress import LockFinalization
        result.lock_finalization=LockFinalization(unlock='succeeded',close='succeeded')
        if previous is None and mode=='commit_prepared':
            proof={'native_bundle_recovery_proof_version':'1.0','original_intent_digest':expected_intent_digest,
                'effect_plan_digest':result.effect_plan_digest,'installation_digest':binding.manifest_digest,
                'registry_snapshot_digest':binding.registry.digest,'original_files':{
                    n:list(v)for n,v in original['files'].items()if not n.startswith('recovery/')},
                'operation':mode,'recovery_context':context,'parent_response':parent,
                'observation':observation,'common_guard_finalized':True}
            _write_native_recovery_canonical(store,'native-commit-proof.json',proof)
            if mode=='commit_prepared':
                _write_native_recovery_canonical(store,'commit-receipt.json',{
                    'continuation_receipt_version':'1.0','original_intent_digest':expected_intent_digest,
                    'preparation_digest':context['preparation_digest'],
                    'continuation_intent_digest':digest_bytes(canonical_bytes(_expected_continuation(original))),
                    'status':'verified_existing','target_verified':True,'effect_plan_digest':result.effect_plan_digest})
        result.status='verified_existing';result.success=True;result.target_verified=True
        result.recovery_effect_state='committed';result.inspection_required=False;result.exit_code=0
    except (PhaseError,OSError,ValueError,TypeError,KeyError) as error:
        from .uncertainty import _diagnostic
        result.error=getattr(error,'code',None)or'recovery.native_unknown'
        result.native_error_details=[_diagnostic(error)]
        captured=authority.channel.captured_file2_completion()
        if captured is not None:
            result.native_parent_response=parse_json_bytes(captured,maximum_bytes=2*1024**2)
            try:
                fact=result.native_parent_response
                completion=fact['completion']
                _require(context is not None and fact['context']==context
                    and canonical_bytes(completion)==_wire(fact['completion_wire'])
                    and completion['context']==context,'recovery.native_completion_mismatch')
                records=verify_trace(completion)
                if type(completion['mutation_attempted']) is bool:
                    result.recovery_mutation_attempted=completion['mutation_attempted']
                    if completion['mutation_attempted'] is False:result.recovery_effect_state='not_attempted'
                if any(r.get('api')=='NtSetInformationFile' and r.get('class')==10
                    and r.get('return_status')==r.get('io_status')=='0x00000000'
                    and r.get('effect_state')=='committed' for r in records):
                    result.recovery_effect_state='committed'
            except (PhaseError,KeyError,TypeError,ValueError):pass
        result.status='indeterminate';result.success=False;result.exit_code=40
        result.inspection_required=True
    finally:
        if not authority.channel._sealed:
            try:
                authority.channel.seal()
                authority._server_ingress_sealed=True
            except BaseException as error:
                from .uncertainty import _diagnostic
                result.success=False;result.status='indeterminate';result.inspection_required=True
                result.exit_code=40;result.error=getattr(error,'code',None)or'recovery.channel_finalization_unknown'
                result.native_error_details.append(_diagnostic(error))
        if store is not None:
            # Finalize the long-lived pinned original owner BEFORE recording a
            # successful observation. The short telemetry writer cannot attest
            # its own future close; its errors affect delivery and remain data.
            from .uncertainty import _diagnostic
            try:_close_native_recovery_store(store)
            except BaseException as error:
                result.success=False;result.status='indeterminate';result.inspection_required=True
                result.exit_code=40;result.error=getattr(error,'code',None)or'recovery.store_finalization_unknown'
                result.native_error_details.append(_diagnostic(error))
            observation_store=None
            try:
                observation_store=_open_native_recovery_store(binding,run_id)
                raw=result.model_dump(exclude={'observation_digest','observation_path'})
                leaf=digest_bytes(canonical_bytes(raw))[7:]+'.json'
                path,digest=_write_native_recovery_canonical(observation_store,leaf,raw)
                result.observation_path=str(path);result.observation_digest=digest
            except BaseException as error:
                result.success=False;result.status='indeterminate';result.inspection_required=True
                result.exit_code=40;result.error=getattr(error,'code',None)or'recovery.observation_unknown'
                result.native_error_details.append(_diagnostic(error))
            finally:
                if observation_store is not None:
                    try:_close_native_recovery_store(observation_store)
                    except BaseException as error:
                        result.success=False;result.status='indeterminate';result.inspection_required=True
                        result.exit_code=40;result.error=getattr(error,'code',None)or'recovery.telemetry_finalization_unknown'
                        result.native_error_details.append(_diagnostic(error))
    return ApplicationResponse(result.model_dump(),result.exit_code)
