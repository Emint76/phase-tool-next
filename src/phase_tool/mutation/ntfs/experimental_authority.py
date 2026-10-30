"""Linux-only closed role; shared admission data stays Windows-importable.

Physical effects, process ownership and lifecycle are inherited unchanged.
This module is not a public provider selector or a qualification certificate.
"""
from ...canonical import digest_bytes, parse_json_bytes
from .authority import _NativeFileCreateAuthority
from .experimental_file1 import _CONTRACT, _experimental_admission
from .native import _require


class _ExperimentalFile1Authority(_NativeFileCreateAuthority):
    def _admitted_profile(self):
        context = _experimental_admission(self.read_binding)
        _require(context is not None and context.profile(self.read_binding) == self.profile,
            'ntfs.experimental_admission_required')
        return self.registry.resolve_guarantee_profile(self.profile.as_dict())

    def require_contract(self, contract):
        self._usable()
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'],
            'version': contract.document['identity']['version'], 'package_digest': contract.package_digest}
            == self._manifest['contract'] == _CONTRACT
            and operation['intent'] == 'create' and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == ['exclusive_create']
            and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')}
            == self._manifest['mechanism']
            and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return self.read_binding.experimental_admission.assess(self.read_binding,
            operation['required_guarantees'], [operation['mechanism']])

    def idempotency(self, contract, candidate, frozen, roots):
        doc = self.read_binding.experimental_admission.check_binding(self.read_binding)
        value = parse_json_bytes(candidate.canonical_bytes)
        payload = frozen.get('payload')
        _require(self._run_id == doc['run_id'] and value['idempotency_key'] == doc['request_id']
            and value['target_locator'] == doc['target_locator']
            and digest_bytes(candidate.canonical_bytes) == doc['candidate_digest']
            and payload is not None and payload.digest == doc['payload_digest']
            and payload.length == doc['payload_length'], 'ntfs.experimental_input_mismatch')
        return super().idempotency(contract, candidate, frozen, roots)

