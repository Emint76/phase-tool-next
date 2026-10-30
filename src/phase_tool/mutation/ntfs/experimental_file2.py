"""Closed file2 experiment data; ordinary startup never selects this context."""
from dataclasses import dataclass
from typing import ClassVar
from .experimental_file1 import _ExperimentalFile1Admission

_FILE2_CONTRACT = {'id': 'file_create.v2', 'version': '1.0.0',
    'package_digest': 'sha256:aa6b901831f24dc0e5d7d131e5bf0633a8bdcdaa7ffeb5dedacc6e1d5d329634'}


@dataclass(frozen=True)
class _ExperimentalFile2Admission(_ExperimentalFile1Admission):
    _contract: ClassVar[dict] = _FILE2_CONTRACT
    _profile: ClassVar[str] = 'phase.native.ntfs.experiment.file2.authority.v1@1.0.0'
    _manifest_version: ClassVar[str] = '1.3'
    _installation_prefix: ClassVar[str] = 'phase.experiment.file2.'
    _authority_artifact: ClassVar[str] = 'phase_tool/mutation/ntfs/experimental_file2_authority.py'
    _minimum_payload_length: ClassVar[int] = 0
    _maximum_payload_length: ClassVar[int] = 2*1024**3
