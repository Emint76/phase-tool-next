"""Linux-only file2 admission seam; existing authority owns the entire lifecycle."""
from .experimental_authority import _ExperimentalFile1Authority
from .experimental_file2 import _FILE2_CONTRACT, _ExperimentalFile2Admission
from .native import _require


class _ExperimentalFile2Authority(_ExperimentalFile1Authority):
    def require_contract(self, contract):
        self._usable()
        admission = self.read_binding.experimental_admission
        _require(type(admission) is _ExperimentalFile2Admission,
            'ntfs.experimental_admission_required')
        operation = contract.document['operation']
        _require({'id': contract.document['identity']['id'],
            'version': contract.document['identity']['version'], 'package_digest': contract.package_digest}
            == self._manifest['contract'] == _FILE2_CONTRACT
            and operation['intent'] == 'create' and operation['maximum_effects'] == 1
            and operation['allowed_effects'] == ['exclusive_create']
            and {k: operation['mechanism'][k] for k in ('id', 'version', 'package_digest')}
            == self._manifest['mechanism']
            and not operation.get('effect_mechanisms'), 'ntfs.original_single_effect_required')
        return admission.assess(self.read_binding, operation['required_guarantees'],
            [operation['mechanism']])
