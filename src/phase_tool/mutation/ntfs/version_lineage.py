"""Immutable prior-run provenance in EXISTING Core attachments.

Not dispatch/recovery authority or an alternate history. Link validation reads
exact Original values/full bytes, not a recursive prior-success assertion. The
common guard separately verifies EVERY original's actual worker/IO closure.
"""
from pathlib import Path
import re

from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from .native import _require

_LEAF='native-version-lineage.json'
_KEYS={'native_version_lineage_version','original_run_id','original_intent_digest','original_files_digest',
    'original_closure_artifact','original_closure_digest','continued_run_id','continued_intent_digest',
    'request_id','scope_digest','request_digest','installation_digest','registry_snapshot_digest'}


def _old_files_digest(files):
    return digest_bytes(canonical_bytes({name:list(row)for name,row in files.items()if not name.startswith('recovery/')}))


def lineage_value(binding, original, new_intent, *, resolution_digest=None):
    old=original['intent'];key=old['idempotency'];current=new_intent['idempotency']
    manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
    installed={'id':manifest['installation_id'],'descriptor_digest':binding.manifest_digest}
    _require(new_intent['run_id']!=old['run_id'] and new_intent['execution_requested']is True
        and new_intent['contract']==old['contract']==manifest['contract']and new_intent['core']==old['core']
        and new_intent['registry_snapshot_digest']==old['registry_snapshot_digest']==binding.registry.digest
        and all(record['native_binding']['installation']==installed
            and record['native_binding']['composition']==manifest['composition']
            and record['native_binding']['evidence_identity']==manifest['evidence_identity']
            for record in(old,new_intent))
        and current==dict(key),'recovery.version_lineage_conflict')
    leaf=('attachments/native-terminal-proof.json'if original['closure_kind']=='native_terminal_proof'
        else'attachments/native-parent-failure.json'if original['closure_kind']=='validated_parent_failure_completion'else None)
    _require(leaf is not None and leaf in original['original_files'],'recovery.version_lineage_conflict')
    value = {'native_version_lineage_version':'1.0','original_run_id':old['run_id'],
        'original_intent_digest':profile_digest('intent',old),'original_files_digest':_old_files_digest(original['original_files']),
        'original_closure_artifact':leaf,'original_closure_digest':original['original_files'][leaf][0],
        'continued_run_id':new_intent['run_id'],'continued_intent_digest':profile_digest('intent',new_intent),
        'request_id':key['key'],'scope_digest':key['scope_digest'],'request_digest':key['request_digest'],
        'installation_digest':binding.manifest_digest,'registry_snapshot_digest':binding.registry.digest}
    if resolution_digest is not None:
        _require(type(resolution_digest) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', resolution_digest),
            'recovery.version_lineage_conflict')
        value.update(native_version_lineage_version='1.1', resolution_digest=resolution_digest)
    return value


def verify_version_lineage(binding, run, new_intent, *, require_resolution=False):
    """Return only verified provenance digest, never prior-worker permission.

    No recursive terminal-proof inspection: the full common history barrier
    remains responsible for each run's closure. All linked original bytes are
    hashed/read; no run, registry, root or lookup index is selected by evidence.
    """
    from ...evidence import validate_intent,validate_run_id,evidence_file_exists
    from .bundle_recovery_original import native_inventory
    from .version_original_closure import _canonical,version_original_role
    path=run/'attachments'/_LEAF
    if not evidence_file_exists(path):return None
    version_original_role(binding)
    value,raw=_canonical(path)
    _require(type(value) is dict and (
        (set(value) == _KEYS and value['native_version_lineage_version'] == '1.0')
        or (set(value) == _KEYS | {'resolution_digest'} and value['native_version_lineage_version'] == '1.1'
            and type(value['resolution_digest']) is str
            and re.fullmatch(r'sha256:[0-9a-f]{64}', value['resolution_digest']))),
        'recovery.version_lineage_conflict')
    validate_run_id(value['original_run_id']);validate_run_id(value['continued_run_id'])
    _require(value['continued_run_id']==run.name==new_intent['run_id']
        and value['original_run_id']!=run.name,'recovery.version_lineage_conflict')
    oldrun=run.parent/value['original_run_id'];old,_=_canonical(oldrun/'intent.json')
    validate_intent(old,binding.registry);validate_intent(new_intent,binding.registry)
    _require(old['run_id']==oldrun.name and old['execution_requested']is True,
        'recovery.version_lineage_conflict')
    # Genuine existing full Original parser, including retained input bytes.
    binding.read(run_id=oldrun.name,intent_digest=profile_digest('intent',old))
    before=native_inventory(binding,oldrun)
    original_files={name:row for name,row in before.items()if not name.startswith('recovery/')}
    artifact=value['original_closure_artifact']
    _require(artifact in{'attachments/native-terminal-proof.json','attachments/native-parent-failure.json'}
        and artifact in original_files,'recovery.version_lineage_conflict')
    # Reading an exact artifact digest is provenance, not validating its worker
    # facts. Source guard/proof verifiers still perform that separate check.
    projection={'intent':old,'original_files':original_files,
        'closure_kind':'native_terminal_proof'if artifact.endswith('terminal-proof.json')else'validated_parent_failure_completion'}
    resolution_digest = value.get('resolution_digest')
    _require(value == lineage_value(binding, projection, new_intent, resolution_digest=resolution_digest)
        and before==native_inventory(binding,oldrun),'recovery.version_lineage_conflict')
    if require_resolution and resolution_digest is not None:
        # The digest is committed by the lineage attachment in the continued
        # receipt. Checking that receipt again here would recurse.
        from .version_continuation import validate_version_resolution_shape
        member = 'recovery/' + resolution_digest[7:] + '.json'
        _require(member in before, 'recovery.version_resolution_required')
        resolution, resolution_raw = _canonical(oldrun / member)
        validate_version_resolution_shape(resolution, old)
        _require((digest_bytes(resolution_raw), len(resolution_raw)) == before[member]
            and digest_bytes(resolution_raw) == resolution_digest
            and resolution['native_version_resolution_version'] == '1.3'
            and resolution['continued_run_id'] == new_intent['run_id']
            and resolution['continued_intent_digest'] == value['continued_intent_digest']
            and resolution['installation_digest'] == value['installation_digest']
            and resolution['registry_snapshot_digest'] == value['registry_snapshot_digest'],
            'recovery.version_lineage_conflict')
    binding.check_evidence_root()
    return digest_bytes(raw)


def attach_version_continuation_lineage(store,intent):
    from .version_continuation import _ACTIVE, validate_version_resolution_shape
    lease=_ACTIVE.get()
    if lease is None:return None
    lease.check();selection=lease.selection
    _require(lease.taken and lease.request_checked and lease.observation is not None
        and not lease.lineage_attempted and lease.lineage is None
        and store.run_root.name==selection.new_run_id==intent['run_id'],
        'recovery.version_lineage_conflict')
    lease.lineage_attempted=True # Consume before verification or any possible IO.
    old=selection.check(store.runs_root/selection.original_run_id)
    resolution = dict(lease.observation, native_version_resolution_version='1.3',
        continued_run_id=intent['run_id'], continued_intent_digest=profile_digest('intent', intent))
    validate_version_resolution_shape(resolution, old['intent'])
    resolution_digest = digest_bytes(canonical_bytes(resolution))
    value = lineage_value(selection.binding, old, intent, resolution_digest=resolution_digest)
    # Existing Core EvidenceStore exclusive/durable writer, before broker GO.
    path,digest=store.write_canonical('attachments/'+_LEAF,value)
    _require(path==store.attachment_root/_LEAF
        and verify_version_lineage(selection.binding,store.run_root,intent)==digest,
        'recovery.version_lineage_conflict')
    lease.lineage={'digest':digest,'value':value}
    lease.resolution = resolution
    return digest
