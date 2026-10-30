"""Fixed native version1 hook using the existing contract's semantic owner.

Authenticated installation context selects this private class. It never reads
a Linux target projection, caches observations or owns versions/evidence. A
saved inspect identity is an immutable expected binding, not an observation.
"""
from __future__ import annotations

from ..canonical import canonical_bytes, parse_json_bytes
from ..mutation.ntfs.native import NativeIdentity, _require
from .publish_new_version_v1 import PublishNewVersionHook, _postcondition_result


def _state(observation):
    return {key:observation['state'][key] for key in ('exists','digest','length')}


class _NativeVersion1Hook(PublishNewVersionHook):
    def __init__(self, authority, contract, *, expected_targets: bytes | None = None):
        from ..mutation.ntfs.experimental_file1 import _is_native_authority
        _require(_is_native_authority(authority),'ntfs.closed_native_installation_required')
        authority.require_contract(contract)
        _require(contract.document['identity']['id'] == 'publish_new_version.v1',
            'ntfs.native_hook_contract_mismatch')
        self._authority = authority
        self._expected_targets = None
        if expected_targets is not None:
            _require(type(expected_targets) is bytes,'ntfs.native_hook_identity_binding')
            targets = parse_json_bytes(expected_targets)
            _require(type(targets) is dict and set(targets) == {'current','archive'}
                and canonical_bytes(targets) == expected_targets,'ntfs.native_hook_identity_binding')
            current,archive = NativeIdentity.parse(targets['current']),NativeIdentity.parse(targets['archive'])
            _require(current != archive,'ntfs.version1_current_archive_alias')
            self._expected_targets = expected_targets

    def _observe_pair(self, root, current_locator, archive_target_locator, *, allow_missing_root=False):
        _require(type(allow_missing_root) is bool,'ntfs.native_hook_context_required')
        binding = self._authority.hook_root_binding(root)
        expected = (None if self._expected_targets is None else parse_json_bytes(self._expected_targets))
        current = self._authority.observe_advisory(root_binding=binding,locator=current_locator,
            expected_identity=None if expected is None else expected['current'])
        archive = self._authority.observe_advisory(root_binding=binding,locator=archive_target_locator,
            expected_identity=None if expected is None else expected['archive'])
        if current['native']['exists'] and archive['native']['exists']:
            _require(current['native']['native_identity'] != archive['native']['native_identity'],
                'ntfs.version1_current_archive_alias')
        return _state(current),_state(archive)

    def run_post_validator(self, identifier, contract, effect_plan, root_bindings, evidence_root=None):
        if identifier != 'publish_new_version.result_v1':
            return None
        self._authority.require_contract(contract)
        effect = effect_plan['effects'][0]
        binding = self._authority.hook_root_binding(root_bindings[effect['target']['root_binding']])
        _require(binding == effect['target']['root_binding'],'ntfs.effect_grant_mismatch')
        pair = self._authority.observe_version1_post_pair(run_id=effect_plan['run_id'],effect=effect)
        return _postcondition_result(effect,_state(pair['current']),_state(pair['archive']))

    def inspect_native_result(self, receipt, plan, root, registry, evidence_root, *, root_bindings):
        # A native pair has real scoped byte observations and NativeIDs, not an
        # invented POSIX byte buffer/stream. Reuse the existing contract's ONE
        # receipt/state verifier, with immutable expected IDs from checked proof.
        return self.inspect_receipt_result(receipt,plan,root,registry,evidence_root,
            root_bindings=root_bindings)
