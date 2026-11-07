"""Closed two-root Version2 experiment, without qualification claims."""
from dataclasses import dataclass
from pathlib import PureWindowsPath
import re
from typing import ClassVar

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...evidence import validate_run_id
from ...paths import safe_relative_locator
from .experimental_file1 import _AUTHORIZATION, _ExperimentalFile1Admission
from .native import _require


_VERSION2_CONTRACT={'id':'publish_new_version.v2','version':'1.0.0',
    'package_digest':'sha256:5a4e0ef57258674c32c430df3aecb47b0f65debfee9686f42463f1f753502065'}


@dataclass(frozen=True)
class _ExperimentalVersion2Admission(_ExperimentalFile1Admission):
    _contract: ClassVar[dict]=_VERSION2_CONTRACT
    _profile: ClassVar[str]='phase.native.ntfs.experiment.version2.authority.v3@1.0.0'
    _manifest_version: ClassVar[str]='1.5'
    _installation_prefix: ClassVar[str]='phase.experiment.version2.'
    _authority_artifact: ClassVar[str]='phase_tool/mutation/ntfs/experimental_version2_authority_v2.py'
    _required: ClassVar[frozenset[str]]=frozenset({'exclusive_create','readback_verification',
        'cross_process_serialization','namespace_bound_mutation','atomic_replace','namespace_metadata_flush_attempted'})

    def document(self):
        _require(type(self.raw) is bytes and len(self.raw)<=32768,'ntfs.experimental_admission_required')
        doc=parse_json_bytes(self.raw,maximum_bytes=32768)
        _require(type(doc) is dict and canonical_bytes(doc)==self.raw and set(doc)=={
            'experimental_admission_version','authorization_digest','contract','run_id','request_id',
            'target_locator','candidate_digest','content_digest','content_length','windows_roots','root_grants',
            'evidence_identity','preparation_identity','wheel_digest','qualification','release_eligible'},
            'ntfs.experimental_admission_shape')
        _require(doc['experimental_admission_version']=='1.1' and doc['authorization_digest']==_AUTHORIZATION
            and doc['contract']==_VERSION2_CONTRACT and doc['release_eligible'] is False
            and doc['qualification']=={'A05':'NOT_VERIFIED','G01':'NOT_VERIFIED'},'ntfs.experimental_admission_scope')
        validate_run_id(doc['run_id'])
        _require(type(doc['request_id']) is str and len(doc['request_id'])<=128
            and re.fullmatch('[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*',doc['request_id']) is not None
            and type(doc['target_locator']) is str and safe_relative_locator(doc['target_locator'])==doc['target_locator']
            and type(doc['content_length']) is int and 0<=doc['content_length']<=512*1024,'ntfs.experimental_admission_scope')
        for key in ('candidate_digest','content_digest','wheel_digest'):
            _require(type(doc[key]) is str and re.fullmatch('sha256:[0-9a-f]{64}',doc[key]) is not None,
                'ntfs.experimental_admission_shape')
        from .version2_observation import _version2_grants
        grants=_version2_grants(doc['root_grants'])
        roots=doc['windows_roots']
        _require(type(roots) is dict and set(roots)=={'current_root','objects_root'},'ntfs.experimental_admission_scope')
        parents=[]
        for binding,leaf in [('current_root','results'),('objects_root','objects')]:
            _require(type(roots[binding]) is str,'ntfs.experimental_admission_scope')
            root=PureWindowsPath(roots[binding])
            _require(root.drive=='S:' and root.is_absolute() and str(root)==roots[binding]
                and len(root.parts)==4 and root.parts[1]=='Phase-NTFS-Qualification'
                and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',root.parts[2]) is not None
                and root.parts[3]==leaf and grants[binding].components==root.parts[1:],
                'ntfs.experimental_admission_scope')
            parents.append(root.parent)
        _require(parents[0]==parents[1],'ntfs.experimental_admission_scope')
        from .reader import _evidence_identity
        for key in ('evidence_identity','preparation_identity'):_evidence_identity(canonical_bytes(doc[key]))
        return doc

    def check_binding(self,binding):
        from ...installation import _NativeFileCreateReadBinding
        _require(type(binding) is _NativeFileCreateReadBinding and binding.experimental_admission is self,
            'ntfs.experimental_admission_required')
        doc=self.document();manifest=parse_json_bytes(binding.manifest_bytes,maximum_bytes=2*1024**2)
        _require(manifest['native_read_installation_version']=='1.5'
            and manifest['installation_id']==self._installation_prefix+self.digest[7:]
            and manifest['contract']==doc['contract'] and manifest['root_grants']==doc['root_grants']
            and manifest['evidence_identity']==doc['evidence_identity']
            and manifest['preparation_identity']==doc['preparation_identity'],'ntfs.experimental_admission_binding_mismatch')
        return doc

    def check_original(self,intent,plan):
        from .intent import _version2_content_binding
        doc=self.document();value=intent['candidate']['storage']['value']
        content=_version2_content_binding(intent,plan)
        _require(intent['run_id']==plan['run_id']==doc['run_id'] and intent['contract']==plan['contract']==doc['contract']
            and value['idempotency_key']==doc['request_id'] and value['target_locator']==doc['target_locator']
            and digest_bytes(canonical_bytes(value))==doc['candidate_digest']
            and digest_bytes(content)==doc['content_digest'] and len(content)==doc['content_length']
            and intent['idempotency']['root_identities']==doc['root_grants'],'ntfs.experimental_original_mismatch')
