"""Linux-only Version1 admission seam; inherited lifecycle owns every effect."""
from .experimental_authority import _ExperimentalFile1Authority
from .experimental_version1 import _VERSION1_CONTRACT, _ExperimentalVersion1Admission
from .native import _require


class _ExperimentalVersion1Authority(_ExperimentalFile1Authority):
    def require_contract(self, contract):
        self._usable()
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalVersion1Admission,
            'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'],
            'version': contract.document['identity']['version'], 'package_digest': contract.package_digest}
            == self._manifest['contract'] == _VERSION1_CONTRACT
            and operation['intent'] == 'publish_new_version' and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == ['publish_new_version']
            and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')}
            == self._manifest['mechanism']
            and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'],
            [operation['mechanism']])
