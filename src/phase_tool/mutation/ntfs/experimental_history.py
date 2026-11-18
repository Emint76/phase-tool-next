"""Accepted three-run experiment; companions are read expectations only.

This new composition does not broaden the old standalone Version1 profile.
Existing candidate grammars, effects, versioning and evidence formats are reused.
"""
from dataclasses import dataclass
from typing import ClassVar

from .experimental_file1 import _ExperimentalFile1Admission
from .experimental_version1 import _ExperimentalVersion1Admission


@dataclass(frozen=True)
class _ExperimentalHistoryFile1Admission(_ExperimentalFile1Admission):
    _profile: ClassVar[str] = 'phase.native.ntfs.experiment.history.authority.v1@1.0.0'
    _installation_prefix: ClassVar[str] = 'phase.experiment.history.file1.'
    _authority_artifact: ClassVar[str] = 'phase_tool/mutation/ntfs/experimental_history_authority.py'


@dataclass(frozen=True)
class _ExperimentalHistoryVersion1Admission(_ExperimentalVersion1Admission):
    _profile: ClassVar[str] = 'phase.native.ntfs.experiment.history.authority.v1@1.0.0'
    _installation_prefix: ClassVar[str] = 'phase.experiment.history.version1.'
    _authority_artifact: ClassVar[str] = 'phase_tool/mutation/ntfs/experimental_history_authority.py'
