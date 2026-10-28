"""Two-root Version2 role within the existing Core-owned native lifecycle."""
from pathlib import Path

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...contracts.publish_new_version_v2 import inline_content
from .authority import _NativeFileCreateAuthority
from .experimental_authority import _ExperimentalFile1Authority
from .experimental_version2 import _VERSION2_CONTRACT, _ExperimentalVersion2Admission
from .native import NativeIdentity, _require
from .version2_observation import (_version2_grants, _version2_targets,
    validate_version2_observation, validate_version2_triple)


class _ExperimentalVersion2Authority(_ExperimentalFile1Authority):
    def require_contract(self,contract):
        self._usable()
        admission=self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalVersion2Admission,'ntfs.experimental_admission_required')
        operation=contract.document['operation']
        _require({'id':contract.document['identity']['id'],'version':contract.document['identity']['version'],
            'package_digest':contract.package_digest}==self._manifest['contract']==_VERSION2_CONTRACT
            and operation['intent']=='publish_new_version' and operation['maximum_effects']==1
            and operation['allowed_effects']==['publish_new_version']
            and {k:operation['mechanism'][k] for k in ('id','version','package_digest')}==self._manifest['mechanism']
            and not operation.get('effect_mechanisms'),'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding,operation['required_guarantees'],[operation['mechanism']])

    def idempotency(self,contract,candidate,frozen,roots):
        doc=self.read_binding.experimental_admission.check_binding(self.read_binding)
        value=parse_json_bytes(candidate.canonical_bytes);content=inline_content(value)
        _require(self._run_id==doc['run_id'] and value['idempotency_key']==doc['request_id']
            and value['target_locator']==doc['target_locator'] and not frozen
            and digest_bytes(candidate.canonical_bytes)==doc['candidate_digest']
            and digest_bytes(content)==doc['content_digest'] and len(content)==doc['content_length'],
            'ntfs.experimental_input_mismatch')
        return _NativeFileCreateAuthority.idempotency(self,contract,candidate,frozen,roots)

    def require_version2_roots(self,roots):
        self.require_request_roots(roots,Path(self._manifest['evidence_root']))
        _version2_grants(self._manifest['root_grants'])

    def observe_version2_advisory(self,*,root_binding,locator,expected_identity=None):
        self._usable()
        _require(self._version2,'ntfs.original_closed_role_required')
        grants=_version2_grants(self._manifest['root_grants'])
        _require(root_binding in grants,'ntfs.effect_grant_mismatch')
        response=self.channel.observe_file(run_id=self._run_id,root_binding=root_binding,
            locator=locator,expected_identity=expected_identity)
        observed=validate_version2_observation(response,grants[root_binding].as_dict(),locator)
        if expected_identity is not None:
            _require(observed['native']['exists'] is True
                and canonical_bytes(observed['native']['native_identity'])==canonical_bytes(expected_identity),
                'ntfs.version2_observer_identity_mismatch')
        return observed

    def observe_version2_triple(self,*,effect,expected_targets=None):
        self._usable()
        _require(expected_targets is None or type(expected_targets) is bytes,'ntfs.native_hook_identity_binding')
        expected=None if expected_targets is None else parse_json_bytes(expected_targets)
        if expected_targets is not None:
            _require(type(expected) is dict and set(expected)=={'current','old_object','new_object'}
                and canonical_bytes(expected)==expected_targets,'ntfs.native_hook_identity_binding')
            for identity in expected.values():NativeIdentity.parse(identity)
        observations={name:self.observe_version2_advisory(root_binding=binding,locator=locator,
            expected_identity=None if expected is None else expected[name])
            for name,(binding,locator) in _version2_targets(effect).items()}
        return validate_version2_triple(observations,self._manifest['root_grants'],effect,expected_targets=expected)

    def observe_version2_post_triple(self,*,run_id,effect):
        self._execution_required();self._usable()
        _require(self._version2 and run_id==self._run_id and self._dispatch_attempted
            and self._parent_safety_established and not self._version2_post_attempted,
            'ntfs.native_parent_completion_unresolved')
        self._version2_post_attempted=True
        expected=self.expected_after_identity(effect)
        _require(type(expected) is dict and set(expected)=={'current','old_object','new_object'},
            'ntfs.worker_observer_mismatch')
        observed=self.observe_version2_triple(effect=effect,expected_targets=canonical_bytes(expected))
        self._observations['post_operation']=canonical_bytes({'run_id':run_id,'observation':observed})
        return observed
