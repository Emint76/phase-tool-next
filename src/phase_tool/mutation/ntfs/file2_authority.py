"""Contract projection for the ordinary, qualified File v2 authority."""
from ..guarantees import verify_guarantee_coverage
from .authority import _NativeFileCreateAuthority
from .native import _require


class _QualifiedFile2Authority(_NativeFileCreateAuthority):
    def _admitted_profile(self):
        from ...installation import _native_qualified_profile

        admitted = _native_qualified_profile(self.registry, self.profile.as_dict(), _file2=True)
        provider = {'id': admitted.implementation_id, 'version': admitted.implementation_version,
                    'artifact_digest': admitted.implementation_artifact_digest}
        _require(admitted == self.profile and self._manifest['authority'] == {
            'usage': 'provider_backed', 'profile': admitted.as_dict(), 'provider': provider,
        }, 'ntfs.original_implementation_mismatch')
        return self.registry.resolve_guarantee_profile(admitted.as_dict())

    def require_contract(self, contract):
        self._usable()
        operation = contract.document['operation']
        identity = contract.document['identity']
        binding = {'id': identity['id'], 'version': identity['version'],
                   'package_digest': contract.package_digest}
        mechanism = operation['mechanism']
        mechanism_binding = {key: mechanism[key] for key in ('id', 'version', 'package_digest')}
        _require(binding == self._manifest['contract']
                 and identity['id'] == 'file_create.v2' and identity['version'] == '1.0.0'
                 and operation['intent'] == 'create' and operation['maximum_effects'] == 1
                 and operation['allowed_effects'] == ['exclusive_create']
                 and not operation.get('effect_mechanisms')
                 and mechanism_binding == self._manifest['mechanism'],
                 'ntfs.original_single_effect_required')
        return verify_guarantee_coverage(operation['required_guarantees'], [mechanism],
                                         self.profile, self.registry)
