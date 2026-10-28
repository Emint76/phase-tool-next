"""Closed, explicitly selected file1 experiment; no production qualification.

Reuses the existing native authority, Core, EvidenceStore, worker and proof.
The fixed experimental launcher supplies this context outside operation JSON.
An exact context is correlation inside that installation, not authentication
against an administrator replacing the installation. Default startup refuses it.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import ClassVar
import re

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ..guarantees import GuaranteeProfileBinding, verify_guarantee_coverage
from .native import _require

_AUTHORIZATION = 'sha256:6d3646ce58d6045fae41d1b22791c4f05d6cb177c343883fad86cd6ae0b0a40b'
_PROFILE = 'phase.native.ntfs.experiment.file1.authority.v1@1.0.0'
_CONTRACT = {'id': 'file_create.v1', 'version': '1.0.0',
    'package_digest': 'sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a'}
_REQUIRED = {'exclusive_create', 'readback_verification', 'cross_process_serialization'}
_NAME = 'experimental-admission.json'


@dataclass(frozen=True)
class _ExperimentalFile1Admission:
    raw: bytes
    _contract: ClassVar[dict] = _CONTRACT
    _profile: ClassVar[str] = _PROFILE
    _manifest_version: ClassVar[str] = '1.1'
    _installation_prefix: ClassVar[str] = 'phase.experiment.file1.'
    _authority_artifact: ClassVar[str] = 'phase_tool/mutation/ntfs/experimental_authority.py'
    _minimum_payload_length: ClassVar[int] = 1
    _maximum_payload_length: ClassVar[int] = 1024**2
    _required: ClassVar[frozenset[str]] = frozenset(_REQUIRED)

    def document(self):
        _require(type(self.raw) is bytes and len(self.raw) <= 32768,
            'ntfs.experimental_admission_required')
        doc = parse_json_bytes(self.raw, maximum_bytes=32768)
        _require(type(doc) is dict and canonical_bytes(doc) == self.raw
            and set(doc) == {'experimental_admission_version', 'authorization_digest',
                'contract', 'run_id', 'request_id', 'target_locator', 'candidate_digest',
                'payload_digest', 'payload_length', 'windows_root', 'root_grant',
                'evidence_identity', 'preparation_identity', 'wheel_digest', 'qualification',
                'release_eligible'}, 'ntfs.experimental_admission_shape')
        _require(doc['experimental_admission_version'] == '1.0'
            and doc['authorization_digest'] == _AUTHORIZATION
            and doc['contract'] == self._contract and doc['release_eligible'] is False
            and doc['qualification'] == {'A05': 'NOT_VERIFIED', 'G01': 'NOT_VERIFIED'},
            'ntfs.experimental_admission_scope')
        from ...evidence import validate_run_id
        validate_run_id(doc['run_id'])
        _require(type(doc['request_id']) is str and len(doc['request_id']) <= 128
            and re.fullmatch('[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*', doc['request_id']) is not None,
            'ntfs.experimental_admission_scope')
        _require(type(doc['target_locator']) is str
            and safe_relative_locator(doc['target_locator']) == doc['target_locator']
            and type(doc['payload_length']) is int and self._minimum_payload_length <= doc['payload_length'] <= self._maximum_payload_length,
            'ntfs.experimental_admission_scope')
        for key in ('candidate_digest', 'payload_digest', 'wheel_digest'):
            _require(type(doc[key]) is str and re.fullmatch('sha256:[0-9a-f]{64}', doc[key]) is not None,
                'ntfs.experimental_admission_shape')
        value = doc['windows_root']
        _require(type(value) is str, 'ntfs.experimental_admission_scope')
        root = PureWindowsPath(value)
        _require(root.drive == 'S:' and root.is_absolute() and str(root) == value
            and len(root.parts) == 4 and root.parts[1] == 'Phase-NTFS-Qualification'
            and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', root.parts[2]) is not None
            and root.parts[3] == 'results', 'ntfs.experimental_admission_scope')
        from .worker import _grant
        grant = _grant(doc['root_grant'])
        _require(tuple(grant.components) == root.parts[1:], 'ntfs.experimental_admission_scope')
        from .reader import _evidence_identity
        for key in ('evidence_identity', 'preparation_identity'):
            _evidence_identity(canonical_bytes(doc[key]))
        return doc

    @property
    def digest(self):
        self.document()
        return digest_bytes(self.raw)

    def check_binding(self, binding):
        from ...installation import _NativeFileCreateReadBinding
        _require(type(binding) is _NativeFileCreateReadBinding
            and binding.experimental_admission is self, 'ntfs.experimental_admission_required')
        doc = self.document()
        manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=2*1024**2)
        _require(manifest['native_read_installation_version'] == self._manifest_version
            and manifest['installation_id'] == self._installation_prefix + self.digest[7:]
            and manifest['contract'] == doc['contract']
            and manifest['root_grants'] == [doc['root_grant']]
            and manifest['evidence_identity'] == doc['evidence_identity']
            and manifest['preparation_identity'] == doc['preparation_identity'],
            'ntfs.experimental_admission_binding_mismatch')
        return doc

    def profile(self, binding):
        self.check_binding(binding)
        exact = binding.registry.guarantee_profile_bindings().get(self._profile)
        _require(exact is not None, 'ntfs.experimental_profile_required')
        desc = binding.registry.resolve_guarantee_profile(exact)
        impl = desc['implementation']
        _require(desc['classification'] == 'qualification_candidate'
            and desc['provided_guarantees'] == desc['conformance'] == []
            and impl['artifact'] == self._authority_artifact,
            'ntfs.experimental_profile_required')
        manifest = parse_json_bytes(binding.manifest_bytes, maximum_bytes=2*1024**2)
        _require(manifest['authority'] == {'usage': 'provider_backed', 'profile': exact,
            'provider': {k: impl[k] for k in ('id', 'version', 'artifact_digest')}},
            'ntfs.original_implementation_mismatch')
        return GuaranteeProfileBinding(exact['id'], exact['version'], exact['descriptor_digest'],
            impl['id'], impl['version'], impl['artifact_digest'])

    def assess(self, binding, requirements, mechanisms):
        """Validate obligations structurally; explicitly do NOT certify coverage."""
        self.profile(binding)
        rows = requirements.get('mechanisms', [])
        # Contracts carry availability/capability metadata; saved plans and
        # requirement mappings carry the same three-field exact binding.
        exact = [{k: m[k] for k in ('id', 'version', 'package_digest')} for m in mechanisms]
        _require(len(rows) == len(mechanisms) == 1
            and set(rows[0]['all_of']) == self._required
            and rows[0]['mechanism'] == exact[0]
            == parse_json_bytes(binding.manifest_bytes)['mechanism'],
            'ntfs.experimental_requirements_mismatch')
        try:
            verify_guarantee_coverage(requirements, mechanisms, None, binding.registry)
        except PhaseError as error:
            if error.code != 'guarantee.profile_unavailable':
                raise
        else:
            raise PhaseError('ntfs.experimental_requirements_mismatch')
        return {'vocabulary': dict(requirements['vocabulary']), 'mechanisms': [
            {'mechanism': dict(exact[0]), 'all_of': sorted(self._required)}]}

    def verify_attachment(self, binding, run_id, receipt=None):
        doc = self.check_binding(binding)
        _require(run_id == doc['run_id'], 'ntfs.experimental_run_mismatch')
        from ...streaming import read_bounded_file
        root = binding.check_evidence_root()
        path = root / '.phase' / 'runs' / run_id / 'attachments' / _NAME
        import os, stat
        info = path.lstat()
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.geteuid() and not info.st_mode & 0o022
            and read_bounded_file(path, 32768) == self.raw,
            'ntfs.experimental_evidence_mismatch')
        if receipt is not None:
            _require(self.digest in receipt['evidence']['attachment_digests'],
                'ntfs.experimental_evidence_mismatch')

    def check_original(self, intent, plan):
        """Additional literal binding AFTER the existing complete original parser.

        That parser verifies actual frozen bytes and all ordinary schema/digest
        relations. These checks bind those same facts to the admitted experiment.
        They do not replace parsing with assertions from the admission document.
        """
        doc = self.document()
        value = intent['candidate']['storage']['value']
        inputs = intent['inputs']
        effects = plan['effects']
        _require(intent['run_id'] == plan['run_id'] == doc['run_id']
            and intent['contract'] == plan['contract'] == doc['contract']
            and value['idempotency_key'] == doc['request_id']
            and value['target_locator'] == doc['target_locator']
            and digest_bytes(canonical_bytes(value)) == doc['candidate_digest']
            and len(inputs) == len(effects) == 1
            and inputs[0]['binding_id'] == value['input_binding'] == 'payload'
            and inputs[0]['digest'] == inputs[0]['blob_digest'] == doc['payload_digest']
            and inputs[0]['freeze_strategy'] == 'copy_and_hash'
            and effects[0]['kind'] == 'exclusive_create'
            and effects[0]['input_binding'] == 'payload'
            and effects[0]['target'] == {'root_binding': doc['root_grant']['root_binding'],
                'relative_locator': doc['target_locator']}
            and effects[0]['content_digest'] == doc['payload_digest']
            and effects[0]['content_length'] == doc['payload_length'],
            'ntfs.experimental_original_mismatch')


def _experimental_admission(binding):
    context = getattr(binding, 'experimental_admission', None)
    if context is None:
        return None
    from .experimental_file2 import _ExperimentalFile2Admission
    from .experimental_version1 import _ExperimentalVersion1Admission
    from .experimental_version2 import _ExperimentalVersion2Admission
    from .experimental_history import (_ExperimentalHistoryFile1Admission,
        _ExperimentalHistoryVersion1Admission)
    _require(type(context) in (_ExperimentalFile1Admission, _ExperimentalFile2Admission,
            _ExperimentalVersion1Admission, _ExperimentalVersion2Admission, _ExperimentalHistoryFile1Admission,
            _ExperimentalHistoryVersion1Admission),
        'ntfs.experimental_admission_required')
    context.check_binding(binding)
    return context




def _is_native_authority(value):
    import sys
    if not sys.platform.startswith('linux'):
        return False
    from .authority import _NativeFileCreateAuthority
    from .experimental_authority import _ExperimentalFile1Authority
    from .experimental_file2_authority import _ExperimentalFile2Authority
    from .experimental_version1_authority import _ExperimentalVersion1Authority
    from .experimental_version2_authority import _ExperimentalVersion2Authority
    from .experimental_history_authority import _ExperimentalHistoryAuthority
    if type(value) is _NativeFileCreateAuthority:
        return getattr(getattr(value, 'read_binding', None), 'experimental_admission', None) is None
    from .experimental_file2 import _ExperimentalFile2Admission
    from .experimental_version1 import _ExperimentalVersion1Admission
    from .experimental_version2 import _ExperimentalVersion2Admission
    from .experimental_history import (_ExperimentalHistoryFile1Admission,
        _ExperimentalHistoryVersion1Admission)
    if type(value) is _ExperimentalHistoryAuthority:
        return type(_experimental_admission(value.read_binding)) in (
            _ExperimentalHistoryFile1Admission,_ExperimentalHistoryVersion1Admission)
    paired = {_ExperimentalFile1Authority: _ExperimentalFile1Admission,
        _ExperimentalFile2Authority: _ExperimentalFile2Admission,
        _ExperimentalVersion1Authority: _ExperimentalVersion1Admission,
        _ExperimentalVersion2Authority: _ExperimentalVersion2Admission}
    if type(value) in paired:
        return type(_experimental_admission(value.read_binding)) is paired[type(value)]
    return False
