"""Native observations for the existing Version2 semantic hook.

This draft is unselected until the closed two-root installation and complete
worker/proof path exist. It owns no versions, execution evidence or recovery.
Linux root projections are labels; this class never resolves or opens them.
"""
from __future__ import annotations

from ..canonical import canonical_bytes, parse_json_bytes
from ..mutation.ntfs.native import NativeIdentity, _require
from .publish_new_version_v2 import PublishNewVersionV2Hook


class _NativeVersion2Hook(PublishNewVersionV2Hook):
    def __init__(self, authority, contract, *, expected_targets: bytes | None = None):
        from ..mutation.ntfs.experimental_file1 import _is_native_authority
        _require(_is_native_authority(authority), 'ntfs.closed_native_installation_required')
        authority.require_contract(contract)
        _require(contract.document['identity']['id'] == 'publish_new_version.v2',
            'ntfs.native_hook_contract_mismatch')
        self._authority = authority
        self._expected_targets = None
        if expected_targets is not None:
            _require(type(expected_targets) is bytes, 'ntfs.native_hook_identity_binding')
            targets = parse_json_bytes(expected_targets)
            _require(type(targets) is dict and set(targets) == {'current', 'old_object', 'new_object'}
                and canonical_bytes(targets) == expected_targets, 'ntfs.native_hook_identity_binding')
            for value in targets.values():
                NativeIdentity.parse(value)
            # Equal old/new digests legitimately identify the same object.
            # Do not invent a requirement for three distinct NativeIDs.
            self._expected_targets = expected_targets

    def _validate_roots(self, root_bindings):
        self._authority.require_version2_roots(root_bindings)

    def _observe_state(self, root, locator):
        binding = self._authority.hook_root_binding(root)
        observation = self._authority.observe_version2_advisory(root_binding=binding, locator=locator)
        return {key: observation['state'][key] for key in ('exists', 'digest', 'length')}

    def _observe_effect(self, effect, root_bindings):
        self._validate_roots(root_bindings)
        observed = self._authority.observe_version2_triple(
            effect=effect, expected_targets=self._expected_targets)
        _require(type(observed) is dict and set(observed) == {'current', 'old_object', 'new_object'},
            'ntfs.version2_observation_mismatch')
        return {name: {key: value['state'][key] for key in ('exists', 'digest', 'length')}
            for name, value in observed.items()}

    def _observe_result(self, effect, root_bindings):
        # Independent inspect/classification never consume an executing slot.
        return self._observe_effect(effect, root_bindings)

    def _observe_post_result(self, effect, root_bindings, *, run_id):
        self._validate_roots(root_bindings)
        observed = self._authority.observe_version2_post_triple(run_id=run_id, effect=effect)
        _require(type(observed) is dict and set(observed) == {'current', 'old_object', 'new_object'},
            'ntfs.version2_observation_mismatch')
        return {name: {key: value['state'][key] for key in ('exists', 'digest', 'length')}
            for name, value in observed.items()}

    def inspect_native_result(self, receipt, plan, root, registry, evidence_root, *, root_bindings):
        return self.inspect_receipt_result(receipt, plan, root, registry, evidence_root,
            root_bindings=root_bindings)
